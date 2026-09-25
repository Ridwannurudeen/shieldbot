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

# Markup that would open bold and italic and make a text link. Its link target has no scheme, because
# untrusted text now shows a scheme's colon as a look-alike (test_unlinked_defuses_every_uri_scheme...).
HOSTILE = "*_[evil](x)"
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
        "ethos_data": {
            "reputation_score": 10,
            "ethos_raw_score": 280,
            "trust_level": HOSTILE,
            "scam_flags": [HOSTILE],
        },
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
            report_address=AsyncMock(
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
    monkeypatch.setattr(bot_module, "web3_client", SimpleNamespace(
        validate_chain_id=lambda chain_id: chain_id, is_valid_address=lambda address: True,
    ))
    update = _update()

    await bot_module.report_command(update, SimpleNamespace(args=[ADDRESS, "honeypot", HOSTILE], user_data={}))

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


def _graph(deployer=None, contracts_deployed=()):
    """An entity graph as campaign_service builds it for an address with no campaign indicators."""
    return {
        "address": ADDRESS,
        "deployer": deployer,
        "funder": None,
        "funder_value_wei": "0",
        "contracts_deployed": list(contracts_deployed),
        "total_deployed": len(contracts_deployed),
        "cross_chain_contracts": [],
        "funder_cluster": [],
        "campaign": {"is_campaign": False, "severity": "NONE", "indicators": []},
    }


@pytest.mark.asyncio
async def test_campaign_for_an_address_the_index_has_never_seen_is_unknown(bot_module):
    bot_module.container.campaign_service.get_entity_graph = AsyncMock(return_value=_graph())
    update = _update()

    await bot_module.campaign_command(update, SimpleNamespace(args=[ADDRESS]))

    rendered = assert_literal(_reply(update))
    assert "Campaign Detected: Unknown (not indexed yet)" in rendered
    assert "isolated" not in rendered
    assert "Campaign Detected: No" not in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "graph",
    [_graph(deployer="0x" + "d" * 40), _graph(contracts_deployed=[{"contract": ADDRESS, "tx_hash": "0x1"}])],
)
async def test_campaign_for_an_indexed_address_without_links_says_isolated(bot_module, graph):
    bot_module.container.campaign_service.get_entity_graph = AsyncMock(return_value=graph)
    update = _update()

    await bot_module.campaign_command(update, SimpleNamespace(args=[ADDRESS]))

    rendered = assert_literal(_reply(update))
    assert "Campaign Detected: No" in rendered
    assert "No campaign links found" in rendered


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


INVISIBLE = (
    0xFEFF,
    0x2060,
    0x2061,
    0x2062,
    0x2063,
    0x2064,
    0x00AD,
    0x061C,
    0x180E,
    0x115F,
    0x1160,
    0x3164,
    0xFFA0,
)


@pytest.mark.parametrize("code", INVISIBLE, ids=[f"U+{code:04X}" for code in INVISIBLE])
def test_invisible_and_filler_characters_are_blanked(code):
    rendered = assert_literal(
        _report(True, token_info={"name": f"Evil{chr(code)}Name", "symbol": "EVL"})
    )

    assert "Token: Evil Name (EVL)" in rendered


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


# --- Telegram links domains, @mentions and /commands in any text; untrusted text cannot make one -----

LURE = "Claim at evil.com or t\N{IDEOGRAPHIC FULL STOP}me/x, ask @scam_admin, send /start"
SHOWN = (
    "Claim at evil\N{ONE DOT LEADER}com or t\N{ONE DOT LEADER}me/x, "
    "ask \N{FULLWIDTH COMMERCIAL AT}scam_admin, send \N{DIVISION SLASH}start"
)
# The parts of LURE Telegram would turn into a link, a mention or a command.
LINKED = ("evil.com", "t\N{IDEOGRAPHIC FULL STOP}me", "@scam_admin", "/start")


def _assert_unlinked(text):
    assert SHOWN in text
    for part in LINKED:
        assert part not in text, part


def test_a_report_shows_untrusted_domains_mentions_and_commands_unlinked():
    rendered = assert_literal(
        _report(
            True,
            token_info={"name": LURE, "symbol": "@evil"},
            ai_analysis=f"Summary\n{LURE}",
            contract_data={"is_contract": True, "bytecode_warnings": [LURE]},
        )
    )

    assert f"Token: {SHOWN} (\N{FULLWIDTH COMMERCIAL AT}evil)" in rendered
    assert f"Bytecode Warnings: {SHOWN}" in rendered
    assert f"Summary\n{SHOWN}" in rendered
    _assert_unlinked(rendered)


def test_ordinary_text_keeps_its_characters():
    rendered = assert_literal(_report(True, token_info={"name": "Moon / Sun. Tax: 5 @ 10%", "symbol": "MS"}))

    assert "Token: Moon / Sun. Tax: 5 @ 10% (MS)" in rendered


def test_a_launch_alert_shows_untrusted_flags_and_reasons_unlinked(bot_module):
    scan = {
        "outcome": "blocked",
        "status": "unknown",
        "risk_level": "HIGH",
        "risk_score": 90,
        "coverage_reasons": {"honeypot": LURE},
        "flags": [LURE],
        "scanned_at": 990.0,
    }
    item = {"chain_id": 4663, "token_address": ADDRESS, "launchpad": "LONG", "verdict_url": "/v", "scan": scan}

    text = bot_module.format_launch_alert(item)

    assert f"• {SHOWN}" in text.splitlines()
    assert f"Unknown: {SHOWN}" in text.splitlines()
    _assert_unlinked(text)


@pytest.mark.asyncio
async def test_an_advisor_reply_shows_the_models_text_unlinked(bot_module):
    bot_module.container.advisor.chat = AsyncMock(return_value={"text": f"Line one\n{LURE}"})
    typing = SimpleNamespace(edit_text=AsyncMock())
    update = _update()
    update.message.reply_text = AsyncMock(return_value=typing)

    await bot_module._handle_advisor_chat(update, "What is new?")

    assert typing.edit_text.await_args.args[0] == f"Line one\n{SHOWN}"



# A dot is defused only where a domain's next label starts with a letter, so numbers keep their dots.
NUMBERS = "Sell tax 12.5%, price $0.0023, router v1.2, 1.2.3.4"


@pytest.mark.parametrize(
    "text, shown",
    [
        (NUMBERS, NUMBERS),
        ("Moon / Sun. Tax: 5 @ 10%", "Moon / Sun. Tax: 5 @ 10%"),
        ("evil.com", "evil\N{ONE DOT LEADER}com"),
        ("rh-claim.io", "rh-claim\N{ONE DOT LEADER}io"),
        ("x.co/abc", "x\N{ONE DOT LEADER}co/abc"),
        ("1.com", "1\N{ONE DOT LEADER}com"),
        ("@scam_admin", "\N{FULLWIDTH COMMERCIAL AT}scam_admin"),
        ("/start", "\N{DIVISION SLASH}start"),
    ],
)
def test_unlinked_defuses_domains_mentions_and_commands_but_not_numbers(text, shown):
    from core.telegram_formatter import unlinked

    assert unlinked(text) == shown


def test_numbers_and_versions_keep_their_dots_in_untrusted_text(bot_module):
    rendered = assert_literal(
        _report(
            True,
            token_info={"name": NUMBERS, "symbol": "V1.2"},
            ai_analysis=NUMBERS,
            contract_data={"is_contract": True, "bytecode_warnings": [NUMBERS]},
        )
    )
    alert = bot_module.format_launch_alert({
        "chain_id": 4663, "token_address": ADDRESS, "launchpad": "LONG", "verdict_url": "/v",
        "scan": {
            "outcome": "blocked", "status": "ok", "risk_level": "HIGH", "risk_score": 90,
            "coverage_reasons": {}, "flags": [NUMBERS], "scanned_at": 990.0,
        },
    })

    assert f"Token: {NUMBERS} (V1.2)" in rendered
    assert f"Bytecode Warnings: {NUMBERS}" in rendered
    assert f"\n{NUMBERS}\n" in rendered
    assert f"• {NUMBERS}" in alert.splitlines()


def test_an_operator_uptime_alert_keeps_its_monitor_url_tappable(client, monkeypatch):
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
            "alertType": "1",
            "monitorFriendlyName": "api.shieldbotsecurity.online",
            "monitorURL": "https://api.shieldbotsecurity.online/health",
            "alertDetails": "Timeout",
        },
        headers={"x-webhook-secret": "s"},
    )

    assert response.status_code == 200
    (message,) = sent
    rendered = assert_literal(message["text"])
    assert "URL: https://api.shieldbotsecurity.online/health" in rendered
    assert "api.shieldbotsecurity.online is unreachable." in rendered


@pytest.mark.asyncio
async def test_an_operator_watch_alert_keeps_its_text(monkeypatch):
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
    reason = "Linked to rh-claim.io, see ops.example.com/runbook"

    assert await indexer._send_watch_alert(
        ADDRESS, 56, ADDRESS, {"watch_reason": reason, "risk_severity": "high"}
    )
    assert f"Watch reason: {reason} | Severity: high" in assert_literal(sent[0]["text"])



@pytest.mark.parametrize(
    "text, shown",
    [
        ("tg://resolve?domain=x", "tg\N{RATIO}//resolve?domain=x"),
        ("ton://x", "ton\N{RATIO}//x"),
        ("http://intranet/login", "http\N{RATIO}//intranet/login"),
        ("https://x.co", "https\N{RATIO}//x\N{ONE DOT LEADER}co"),
        ("open svn+ssh://host now", "open svn+ssh\N{RATIO}//host now"),
        ("Note: 12:30, ratio 3:1, see 10:00-12:30", "Note: 12:30, ratio 3:1, see 10:00-12:30"),
    ],
)
def test_unlinked_defuses_every_uri_scheme_but_not_ordinary_colons(text, shown):
    from core.telegram_formatter import unlinked

    assert unlinked(text) == shown



@pytest.mark.parametrize(
    "text, shown",
    [
        # l and a combining acute accent, which composes to one letter.
        ("evil\N{COMBINING ACUTE ACCENT}.com", "evi\N{LATIN SMALL LETTER L WITH ACUTE}\N{ONE DOT LEADER}com"),
        # x and a combining acute accent, which has no composed form, so the mark stays before the dot.
        ("x\N{COMBINING ACUTE ACCENT}.com", "x\N{COMBINING ACUTE ACCENT}\N{ONE DOT LEADER}com"),
        ("e\N{COMBINING ACUTE ACCENT}\N{COMBINING DOT BELOW}.io", "\N{LATIN SMALL LETTER E WITH DOT BELOW}\N{COMBINING ACUTE ACCENT}\N{ONE DOT LEADER}io"),
        ("v1\N{COMBINING ACUTE ACCENT}.2", "v1\N{COMBINING ACUTE ACCENT}.2"),
    ],
)
def test_a_combining_mark_before_a_domains_dot_does_not_keep_it_linkable(text, shown):
    from core.telegram_formatter import unlinked

    assert unlinked(text) == shown
