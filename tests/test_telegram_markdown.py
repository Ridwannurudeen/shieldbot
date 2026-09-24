"""Untrusted text in the bot's Markdown replies renders literally: no link, no markup, no new line.

Replies use Telegram's legacy Markdown. parse_legacy_markdown below follows tdlib's parser for it
(td/telegram/MessageEntity.cpp, parse_markdown), so a test sees the text and entities Telegram would
show, and a reply Telegram would reject ("Can't find end of the entity") raises instead.
"""

import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from telegram import Update

from core.telegram_formatter import format_full_report
from tests.test_api import client  # noqa: F401
from tests.test_bot_app import MEMPOOL_ALERT, MEMPOOL_STATS, bot_module, mempool_api  # noqa: F401

HOSTILE = "*_[evil](http://x)"
ADDRESS = "0x" + "a" * 40
_ENTITY_TYPES = {"_": "italic", "*": "bold", "`": "code", "[": "text_link"}


def parse_legacy_markdown(text):
    """Return the rendered text and its entities as (type, start, end, url) tuples."""
    rendered, entities = [], []
    i, size = 0, len(text)
    while i < size:
        c = text[i]
        if c == "\\" and text[i + 1 : i + 2] in ("_", "*", "`", "["):
            rendered.append(text[i + 1])
            i += 2
            continue
        if c not in "_*`[":
            rendered.append(c)
            i += 1
            continue
        begin, end_character, is_pre = i, "]" if c == "[" else c, False
        i += 1
        if c == "`" and text[i : i + 2] == "``":
            i += 2
            is_pre = True
            language_end = i
            while (
                language_end < size
                and not text[language_end].isspace()
                and text[language_end] != "`"
            ):
                language_end += 1
            if i != language_end and language_end < size and text[language_end] != "`":
                i = language_end
            if text[i : i + 1] in ("\n", "\r"):
                i += 2 if text[i + 1 : i + 2] in ("\n", "\r") and text[i] != text[i + 1] else 1
        start = len(rendered)
        while i < size and (text[i] != end_character or (is_pre and text[i + 1 : i + 3] != "``")):
            rendered.append(text[i])
            i += 1
        if i == size:
            raise ValueError(f"Can't find end of the entity starting at byte offset {begin}")
        url = None
        if c == "[":
            if text[i + 1 : i + 2] == "(":
                i += 2
                url_start = i
                while i < size and text[i] != ")":
                    i += 1
                url = text[url_start:i]
            else:
                url = text[begin + 1 : i]
        if start != len(rendered):
            entities.append(("pre" if is_pre else _ENTITY_TYPES[c], start, len(rendered), url))
        i += 3 if is_pre else 1
    return "".join(rendered), entities


def assert_literal(message, *values, links=()):
    """Telegram accepts ``message``, shows every value verbatim outside any entity, and links only ``links``."""
    rendered, entities = parse_legacy_markdown(message)
    assert [url for kind, _, _, url in entities if kind == "text_link"] == list(links)
    for value in values:
        spans = [match.span() for match in re.finditer(re.escape(value), rendered)]
        assert spans, f"{value!r} is not shown verbatim"
        for start, end in spans:
            assert all(stop <= start or begin >= end for _, begin, stop, _ in entities)
    return rendered


@pytest.mark.parametrize(
    "text, rendered, entities",
    [
        (
            "*bold* _it_ `code`",
            "bold it code",
            [("bold", 0, 4, None), ("italic", 5, 7, None), ("code", 8, 12, None)],
        ),
        ("[site](http://x)", "site", [("text_link", 0, 4, "http://x")]),
        ("\\*\\_\\[x](y)", "*_[x](y)", []),
        ("**Bold:** x", "Bold: x", []),
        ("a\\b", "a\\b", []),
    ],
)
def test_the_parser_follows_telegram(text, rendered, entities):
    assert parse_legacy_markdown(text) == (rendered, entities)


@pytest.mark.parametrize("text", ["*open", "a_b", "`x", "[link"])
def test_the_parser_rejects_what_telegram_rejects(text):
    with pytest.raises(ValueError):
        parse_legacy_markdown(text)


# --- /scan and /token reports ----------------------------------------------------------------


def _report(complete, **overrides):
    risk = {
        "rug_probability": 80,
        "risk_level": "HIGH",
        "risk_archetype": "honeypot",
        "confidence_level": 90,
        "critical_flags": [HOSTILE, f"Honeypot coverage unknown: {HOSTILE}"],
        "category_scores": {"structural": 10, "market": 20, "behavioral": 30, "honeypot": 90},
        "status": "ok" if complete else "unknown",
        "coverage": {
            "structural": 1,
            "market": 1,
            "behavioral": 1,
            "honeypot": 1 if complete else 0.5,
        },
        "coverage_reasons": {} if complete else {"honeypot": HOSTILE},
    }
    kwargs = {
        "contract_data": {
            "is_contract": True,
            "is_verified": False,
            "contract_age_days": 1,
            "ownership_renounced": False,
            "bytecode_warnings": [HOSTILE],
            "source_code_patterns": [HOSTILE],
        },
        "dex_data": {"reason": HOSTILE},
        "ethos_data": {"reputation_score": 10, "trust_level": HOSTILE, "scam_flags": [HOSTILE]},
        "honeypot_data": {"is_honeypot": None, "reason": HOSTILE},
        "address": ADDRESS,
        "ai_analysis": f"**Risk Score:** 90/100\n{HOSTILE}\nSee `set_fee`",
        "token_info": {"name": HOSTILE, "symbol": HOSTILE},
        **overrides,
    }
    return format_full_report(risk, **kwargs)


@pytest.mark.parametrize("complete", [True, False], ids=["complete", "incomplete"])
def test_scan_and_token_reports_show_untrusted_values_literally(complete):
    rendered = assert_literal(_report(complete), HOSTILE)

    assert f"Token: {HOSTILE} ({HOSTILE})" in rendered
    assert f"  • {HOSTILE}" in rendered
    assert f"  Trust: {HOSTILE}" in rendered
    if complete:
        # The model's ** bold and code spans render as plain text; its other text is shown as written.
        assert f"Risk Score: 90/100\n{HOSTILE}\nSee set_fee" in rendered
    else:
        assert f"  Honeypot: 90/100 ({HOSTILE})" in rendered


def test_a_token_name_cannot_add_a_line_to_a_report():
    name = "Evil\n\U0001f7e2 Generally Safe — Low risk (0%)\u2028"

    rendered = assert_literal(_report(True, token_info={"name": name, "symbol": "EVL"}))

    assert "Token: Evil \U0001f7e2 Generally Safe — Low risk (0%)  (EVL)" in rendered.splitlines()
    assert not any(line.startswith("\U0001f7e2") for line in rendered.splitlines())


def test_a_trailing_backslash_cannot_escape_the_markup_after_it():
    rendered = assert_literal(_report(True, token_info={"name": "Evil\\", "symbol": "EVL\\"}))

    assert "Token: Evil\u2216 (EVL\u2216)" in rendered


# --- Legacy fallback reports ------------------------------------------------------------------

AI_RISK = {
    "risk_score": 90,
    "risk_level": "HIGH",
    "key_findings": [HOSTILE],
    "recommendation": HOSTILE,
}


def test_fallback_scan_report_shows_untrusted_values_literally(bot_module):
    result = {
        "address": ADDRESS,
        "risk_level": "high",
        "risk_score": 90,
        "confidence": 80,
        "status": "ok",
        "coverage": {"contract": 1},
        "is_contract": True,
        "is_verified": False,
        "checks": {"is_verified": False},
        "scam_matches": [{"type": HOSTILE, "reason": HOSTILE}],
        "warnings": [HOSTILE],
        "ai_risk_score": AI_RISK,
        "ai_analysis": HOSTILE,
    }

    rendered = assert_literal(bot_module.format_scan_result(result), HOSTILE)

    assert f"• {HOSTILE}: {HOSTILE}" in rendered
    assert (
        assert_literal(
            bot_module.format_scan_result({**result, "forensic_report": HOSTILE}), HOSTILE
        )
        == HOSTILE
    )


def test_fallback_token_report_shows_untrusted_values_literally(bot_module):
    result = {
        "address": ADDRESS,
        "name": HOSTILE,
        "symbol": HOSTILE,
        "safety_level": "danger",
        "risk_score": 90,
        "confidence": 80,
        "status": "ok",
        "coverage": {"token": 1},
        "is_honeypot": True,
        "buy_tax": 0,
        "sell_tax": 100,
        "checks": {"can_buy": True, "can_sell": False},
        "risks": [HOSTILE],
        "ai_risk_score": AI_RISK,
        "ai_analysis": HOSTILE,
    }

    rendered = assert_literal(bot_module.format_token_result(result), HOSTILE)

    assert f"Token: {HOSTILE} ({HOSTILE})" in rendered
    assert (
        assert_literal(
            bot_module.format_token_result({**result, "forensic_report": HOSTILE}), HOSTILE
        )
        == HOSTILE
    )


# --- Command replies ----------------------------------------------------------------------------


def _update():
    update = MagicMock(spec=Update)
    update.effective_user.id = 42
    update.message.reply_text = AsyncMock(
        return_value=SimpleNamespace(delete=AsyncMock(), edit_text=AsyncMock())
    )
    return update


def _reply(update):
    call = update.message.reply_text.await_args
    assert call.kwargs.get("parse_mode") == "Markdown"
    return call.args[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("blacklisted", [False, True])
async def test_report_reply_shows_the_reason_literally(bot_module, monkeypatch, blacklisted):
    monkeypatch.setattr(
        bot_module,
        "scam_db",
        SimpleNamespace(
            report_address=MagicMock(
                return_value={
                    "accepted": True,
                    "blacklisted": blacklisted,
                    "reports": 1,
                    "needed": 3,
                }
            )
        ),
    )
    monkeypatch.setattr(bot_module, "onchain_recorder", SimpleNamespace(is_available=lambda: False))
    monkeypatch.setattr(bot_module, "base_attestor", SimpleNamespace(is_available=lambda: False))
    update = _update()

    await bot_module.report_command(update, SimpleNamespace(args=[ADDRESS, "honeypot", HOSTILE]))

    assert f"Reason: honeypot {HOSTILE}\n" in assert_literal(_reply(update), HOSTILE)


@pytest.mark.asyncio
async def test_rescue_reply_shows_token_and_spender_text_literally(bot_module, monkeypatch):
    approval = {
        "risk_level": "HIGH",
        "token_symbol": HOSTILE,
        "spender_label": HOSTILE,
        "risk_reason": HOSTILE,
    }
    alert = {
        "title": f"Dangerous Approval: {HOSTILE}\\",
        "description": HOSTILE,
        "what_you_can_do": HOSTILE,
    }
    monkeypatch.setattr(
        bot_module, "settings", SimpleNamespace(bscscan_api_key="", etherscan_api_key="")
    )
    bot_module.container.rescue_service.scan_approvals = AsyncMock(
        return_value={
            "total_approvals": 1,
            "high_risk": 1,
            "medium_risk": 0,
            "status": "unknown",
            "coverage": {"prices": 0},
            "coverage_reasons": {"prices": HOSTILE},
            "approvals": [approval],
            "alerts": [alert],
            "revoke_txs": [{}],
        }
    )
    bot_module.web3_client.validate_chain_id = lambda chain_id: chain_id
    update = _update()

    await bot_module.rescue_command(update, SimpleNamespace(args=[ADDRESS], user_data={}))

    rendered = assert_literal(_reply(update), HOSTILE, links=["https://revoke.cash/"])
    assert f"\U0001f534 {HOSTILE} → {HOSTILE} — {HOSTILE}" in rendered
    assert f"Dangerous Approval: {HOSTILE}\u2216\n" in rendered


@pytest.mark.asyncio
async def test_threats_reply_shows_alert_text_literally(bot_module, monkeypatch, mempool_api):
    monkeypatch.setattr(bot_module, "settings", SimpleNamespace(shieldbot_api_url=mempool_api.url))
    mempool_api.alerts = [{**MEMPOOL_ALERT, "alert_type": "sandwich\\", "description": HOSTILE}]
    mempool_api.stats = MEMPOOL_STATS
    update = _update()

    await bot_module.threats_command(update, SimpleNamespace(args=[]))

    rendered = assert_literal(_reply(update), HOSTILE)
    assert f"Sandwich\u2216 (BSC)\n  {HOSTILE}\n" in rendered


@pytest.mark.asyncio
async def test_campaign_reply_shows_indicators_literally(bot_module):
    bot_module.container.campaign_service.get_entity_graph = AsyncMock(
        return_value={
            "campaign": {"is_campaign": True, "severity": "HIGH", "indicators": [HOSTILE]},
            "deployer": ADDRESS,
        }
    )
    update = _update()

    await bot_module.campaign_command(update, SimpleNamespace(args=[ADDRESS]))

    assert f"• {HOSTILE}\n" in assert_literal(_reply(update), HOSTILE)


def test_launch_alerts_are_plain_text_and_show_flags_as_written(bot_module):
    scan = {
        "outcome": "blocked",
        "status": "ok",
        "risk_level": "HIGH",
        "risk_score": 90,
        "coverage_reasons": {},
        "flags": [HOSTILE],
        "scanned_at": 990.0,
    }
    item = {
        "chain_id": 4663,
        "token_address": ADDRESS,
        "launchpad": "LONG",
        "verdict_url": "/v",
        "scan": scan,
    }

    assert f"• {HOSTILE}" in bot_module.format_launch_alert(item).splitlines()


# --- Addresses a user types reach code spans, which legacy Markdown cannot escape ---------------

HOSTILE_ADDRESS = "0x`[Claim](https://evil.example)`aaaa"
INVALID = "\N{CROSS MARK} Invalid address format."


@pytest.fixture
def entry_points(bot_module, monkeypatch):
    """The bot with a real address check and its scans replaced, so only the entry points reply."""
    from web3 import Web3

    monkeypatch.setattr(bot_module.web3_client, "is_valid_address", Web3.is_address)
    monkeypatch.setattr(bot_module.web3_client, "validate_chain_id", lambda chain_id: chain_id)
    monkeypatch.setattr(bot_module, "scan_contract", AsyncMock())
    monkeypatch.setattr(bot_module, "check_token", AsyncMock())
    return bot_module


def _assert_rejected(bot, replies):
    for call in replies.await_args_list:
        if call.kwargs.get("parse_mode") == "Markdown":
            assert_literal(call.args[0])
    assert replies.await_args.args == (INVALID,)
    bot.scan_contract.assert_not_awaited()
    bot.check_token.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["scan_command", "token_command"])
async def test_a_scan_command_rejects_an_address_that_is_not_one(entry_points, command):
    update = _update()

    await getattr(entry_points, command)(
        update, SimpleNamespace(args=[HOSTILE_ADDRESS], user_data={})
    )

    _assert_rejected(entry_points, update.message.reply_text)


@pytest.mark.asyncio
async def test_a_typed_address_that_is_not_one_is_rejected(entry_points):
    update = _update()
    update.message.text = HOSTILE_ADDRESS.ljust(42, "a")

    await entry_points.handle_address(update, SimpleNamespace(user_data={}))

    _assert_rejected(entry_points, update.message.reply_text)


@pytest.mark.asyncio
async def test_a_token_button_with_an_address_that_is_not_one_is_rejected(entry_points):
    query = MagicMock(data=f"token_{HOSTILE_ADDRESS}")
    query.answer = AsyncMock()
    query.message.reply_text = AsyncMock()

    await entry_points.button_callback(
        SimpleNamespace(callback_query=query), SimpleNamespace(user_data={})
    )

    _assert_rejected(entry_points, query.message.reply_text)


def test_bidi_and_zero_width_controls_are_blanked():
    name = "Evil\N{RIGHT-TO-LEFT OVERRIDE}Name\N{ZERO WIDTH SPACE}X\N{LEFT-TO-RIGHT ISOLATE}Y"

    rendered = assert_literal(_report(True, token_info={"name": name, "symbol": "EVL"}))

    assert "Token: Evil Name X Y (EVL)" in rendered


# --- Operator alerts sent with Markdown ----------------------------------------------------------


@pytest.mark.parametrize("alert_type", ["1", "2"])
def test_uptime_alerts_show_monitor_text_literally(client, monkeypatch, alert_type):
    import httpx

    import api as api_module

    sent = []

    class Telegram:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json):
            sent.append(json)

    monkeypatch.setattr(httpx, "AsyncClient", Telegram)
    monkeypatch.setattr(
        api_module,
        "container",
        SimpleNamespace(
            settings=SimpleNamespace(
                webhook_secret="s",
                webhook_allow_query_secret=False,
                telegram_bot_token="t",
                telegram_alert_chat_id="1",
            )
        ),
    )

    response = client.post(
        "/webhook/uptime",
        data={
            "alertType": alert_type,
            "monitorFriendlyName": HOSTILE,
            "monitorURL": f"https://status.example/{HOSTILE}",
            "alertDetails": HOSTILE,
        },
        headers={"x-webhook-secret": "s"},
    )

    assert response.status_code == 200
    (message,) = sent
    assert message["parse_mode"] == "Markdown"
    assert_literal(message["text"], HOSTILE)


@pytest.mark.asyncio
async def test_watch_alerts_show_the_watch_record_literally(monkeypatch):
    import aiohttp

    from core.indexer import DeployerIndexer

    sent = []

    class Response:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def post(self, url, json, timeout):
            sent.append(json)
            return Response()

    monkeypatch.setattr(aiohttp, "ClientSession", Session)
    indexer = DeployerIndexer(
        MagicMock(),
        MagicMock(),
        SimpleNamespace(telegram_bot_token="t", telegram_alert_chat_id="1"),
    )

    assert await indexer._send_watch_alert(
        ADDRESS, 56, ADDRESS, {"watch_reason": HOSTILE, "risk_severity": HOSTILE}
    )
    assert sent[0]["parse_mode"] == "Markdown"
    assert_literal(sent[0]["text"], HOSTILE)
