"""Robinhood Chain scans, launch records, alerts and bot reports carry the official-token check."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from agent.hunter import Hunter
from agent.tools import AgentTools
from core.database import Database
from core.registry import RUN_ALL_DEADLINE_SECONDS
from core.telegram_formatter import format_full_report
from services.robinhood_assets import RULES_VERSION, check_token
from services.robinhood_simulation import WETH
from tests.test_bot_app import CHAIN, CHAT_A, TOKENS, _scan, _subscribe, alerts, bot_module  # noqa: F401
from tests.test_guard_rescan import confirmed, measurement, now, publisher_for  # noqa: F401
from tests.test_robinhood_assets import AMD, LISTED, NVDA, TSLA
from tests.test_telegram_markdown import assert_literal
from tests.test_verdict_wiring import bot_scan_functions, update  # noqa: F401

TOKEN = TOKENS[0]
IMPOSTOR = check_token(TOKEN, "NVDA", "NVIDIA", LISTED)
COLLISION = check_token(TOKEN, "AMD", "Moon", LISTED)
OFFICIAL = check_token(NVDA, None, None, LISTED)
NO_MATCH = check_token(TOKEN, "MOON", "Moon", LISTED)
UNKNOWN = check_token(TOKEN, None, None, LISTED)
IMPOSTOR_FLAG = f"Impersonates official NVDA token (Robinhood-issued); official contract {NVDA}"
IMPOSTOR_HEADER = f"\N{POLICE CARS REVOLVING LIGHT} IMPOSTOR: {IMPOSTOR_FLAG}"


# --- AgentTools: the scan every hunter path uses ---------------------------------------------


def _tools(check, run_all=None):
    container = MagicMock()
    container.registry.run_all = run_all or AsyncMock(return_value=[])
    container.risk_engine.compute_from_results = MagicMock(
        return_value={"rug_probability": 20, "critical_flags": ["New pair (<24h)"]}
    )
    container.robinhood_assets.check_onchain = AsyncMock(return_value=check)
    return AgentTools(container), container


@pytest.mark.asyncio
async def test_a_4663_scan_leads_with_the_impostor_flag_and_keeps_its_score():
    tools, container = _tools(IMPOSTOR)

    result = await tools.scan_contract("0x" + "Ab" * 20, chain_id=4663)

    container.robinhood_assets.check_onchain.assert_awaited_once_with(
        "0x" + "ab" * 20, RUN_ALL_DEADLINE_SECONDS
    )
    assert result == {
        "rug_probability": 20,
        "critical_flags": [IMPOSTOR_FLAG, "New pair (<24h)"],
        "honeypot_data": None,
        "impostor_check": IMPOSTOR,
    }


@pytest.mark.asyncio
async def test_a_background_scan_checks_within_its_own_deadline():
    tools, container = _tools(NO_MATCH)

    await tools.scan_contract(TOKEN, chain_id=4663, deadline=45)

    container.robinhood_assets.check_onchain.assert_awaited_once_with(TOKEN, 45)


@pytest.mark.asyncio
async def test_the_check_runs_alongside_the_analyzers():
    checking = asyncio.Event()

    async def run_all(ctx, deadline=None):
        await asyncio.wait_for(checking.wait(), 1)
        return []

    tools, container = _tools(NO_MATCH, run_all=run_all)
    container.robinhood_assets.check_onchain = AsyncMock(
        side_effect=lambda *args: checking.set() or NO_MATCH
    )

    assert (await tools.scan_contract(TOKEN, chain_id=4663))["impostor_check"] == NO_MATCH


@pytest.mark.asyncio
async def test_other_chains_are_not_checked():
    tools, container = _tools(IMPOSTOR)

    result = await tools.scan_contract(TOKEN, chain_id=56)

    container.robinhood_assets.check_onchain.assert_not_awaited()
    assert "impostor_check" not in result


# --- Hunter and database: the check is stored with the launch ----------------------------------


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "impostors.db"))
    await database.initialize()
    yield database
    await database.close()


async def _discover(db):
    await db.upsert_discovered_launches(
        CHAIN,
        [
            {
                "token_address": TOKEN,
                "source": "long",
                "launchpad": "LONG",
                "source_rank": 5,
                "pool_id": None,
                "block_number": 100,
                "tx_hash": "0x" + "01" * 32,
                "block_timestamp": 1_758_000_100,
            }
        ],
    )


def _hunter(db, *results, publisher=None):
    tools = MagicMock(
        scan_contract=AsyncMock(side_effect=list(results)), auto_watch_deployer=AsyncMock()
    )
    return Hunter(
        tools=tools,
        db=db,
        ai_analyzer=MagicMock(is_available=MagicMock(return_value=False)),
        sentinel=MagicMock(),
        verdict_publisher=publisher,
    )


def _watching(check):
    return {
        "rug_probability": 50,
        "risk_level": "MEDIUM",
        "critical_flags": [],
        "status": "ok",
        "coverage": {"structural": 1, "honeypot": 1},
        "coverage_reasons": {},
        "impostor_check": check,
    }


async def _stored(db):
    (item,), _ = await db.get_launch_feed(CHAIN, 10)
    return item["impostor_check"]


@pytest.mark.asyncio
async def test_a_launch_scan_stores_the_check_before_its_outcome(db, monkeypatch):
    await _discover(db)
    seen = []
    record_launch_scan = db.record_launch_scan

    async def record_after_reading(*args):
        seen.append(await _stored(db))
        await record_launch_scan(*args)

    monkeypatch.setattr(db, "record_launch_scan", record_after_reading)

    assert (
        await _hunter(db, _watching(IMPOSTOR)).scan_launch("sweep", {"token_address": TOKEN})
        == "watching"
    )

    assert seen == [IMPOSTOR]
    assert await _stored(db) == IMPOSTOR


@pytest.mark.asyncio
async def test_an_unknown_check_or_a_failed_scan_keeps_a_decided_check(db):
    await _discover(db)
    hunter = _hunter(db, _watching(IMPOSTOR), _watching(UNKNOWN), RuntimeError("RPC down"))

    for _ in range(3):
        await hunter.scan_launch("sweep", {"token_address": TOKEN})

    assert await _stored(db) == IMPOSTOR


def _older(check):
    return {**check, "rules": RULES_VERSION - 1}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stored, new, kept",
    [
        (IMPOSTOR, NO_MATCH, IMPOSTOR),
        (IMPOSTOR, COLLISION, IMPOSTOR),
        (OFFICIAL, NO_MATCH, OFFICIAL),
        (COLLISION, NO_MATCH, COLLISION),
        (COLLISION, IMPOSTOR, IMPOSTOR),
        (NO_MATCH, COLLISION, COLLISION),
        (UNKNOWN, NO_MATCH, NO_MATCH),
        (NO_MATCH, NO_MATCH, NO_MATCH),
        # A check made under newer rules corrects one made under older rules, whatever their ranks.
        (_older(IMPOSTOR), NO_MATCH, NO_MATCH),
        ({key: value for key, value in IMPOSTOR.items() if key != "rules"}, NO_MATCH, NO_MATCH),
        (NO_MATCH, _older(IMPOSTOR), NO_MATCH),
        # An official finding is not replaced from a shorter list.
        (OFFICIAL, {**IMPOSTOR, "list_size": 150}, OFFICIAL),
        (OFFICIAL, {**OFFICIAL, "list_size": 150}, OFFICIAL),
        (OFFICIAL, {**OFFICIAL, "list_size": 196}, {**OFFICIAL, "list_size": 196}),
    ],
)
async def test_a_stored_check_is_replaced_under_newer_rules_or_by_one_at_least_as_decided(
    db, stored, new, kept
):
    await _discover(db)
    # Stored as an earlier write left it, which may predate rule versions.
    await db._db.execute("UPDATE discovered_launches SET impostor_check = ?", (json.dumps(stored),))

    await db.record_launch_impostor_check(CHAIN, TOKEN, new)

    assert await _stored(db) == kept


@pytest.mark.asyncio
async def test_a_recheck_decides_a_check_the_launch_scan_could_not(db):
    await _discover(db)
    hunter = _hunter(db, _watching(UNKNOWN), _watching(NO_MATCH))

    await hunter.scan_launch("sweep", {"token_address": TOKEN})
    assert await _stored(db) == UNKNOWN
    await hunter.recheck_pair(
        "sweep", {"pair_address": TOKEN, "token_address": TOKEN, "chain_id": CHAIN}
    )

    assert await _stored(db) == NO_MATCH


@pytest.mark.asyncio
async def test_a_guard_rescan_stores_the_check(db, now):
    await _discover(db)
    publisher = publisher_for(db)
    await confirmed(db, publisher, TOKEN, 600)
    hunter = _hunter(db, {**measurement(now[0]), "impostor_check": IMPOSTOR}, publisher=publisher)

    (subject,) = await hunter.due_guard_subjects()
    await hunter.rescan_guard_subject(subject)

    assert await _stored(db) == IMPOSTOR


@pytest.mark.asyncio
async def test_a_launch_table_from_before_the_check_gains_it(tmp_path):
    path = str(tmp_path / "old.db")
    database = Database(path)
    await database.initialize()
    await database._db.execute("DROP TABLE discovered_launches")
    await database._db.execute("""
        CREATE TABLE discovered_launches (
            chain_id INTEGER NOT NULL, token_address TEXT NOT NULL, source TEXT NOT NULL,
            launchpad TEXT NOT NULL, source_rank INTEGER NOT NULL, pool_id TEXT,
            block_number INTEGER NOT NULL, tx_hash TEXT NOT NULL, block_timestamp INTEGER NOT NULL,
            discovered_at REAL NOT NULL, scan_status TEXT, risk_score REAL, scanned_at REAL,
            PRIMARY KEY (chain_id, token_address)
        )
    """)
    await database._db.commit()
    await _discover(database)
    await database.close()

    reopened = Database(path)
    await reopened.initialize()
    try:
        assert await _stored(reopened) is None
        await reopened.record_launch_impostor_check(CHAIN, TOKEN, IMPOSTOR)
        assert await _stored(reopened) == IMPOSTOR
    finally:
        await reopened.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("check, queued", [(IMPOSTOR, True), (COLLISION, False), (NO_MATCH, False)])
async def test_an_impostor_launch_alerts_chats_subscribed_to_blocked_launches(db, check, queued):
    await _subscribe(db, CHAT_A, "blocked")
    await _scan(db, TOKEN, "cleared", 10, at=990.0)
    await db.record_launch_impostor_check(CHAIN, TOKEN, check)

    await db.enqueue_launch_alerts(CHAIN, 900.0)

    pending = await db.get_pending_launch_alerts(1000.0, 3600, 5, 5)
    assert [alert["token_address"] for alert in pending] == ([TOKEN] if queued else [])


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["blocked", "all"])
async def test_an_impostor_alerts_once_besides_its_blocked_outcome(db, now, mode):
    await _subscribe(db, CHAT_A, mode)
    await _scan(db, TOKEN, "cleared", 10, at=990.0)
    await db.record_launch_impostor_check(CHAIN, TOKEN, IMPOSTOR)
    for status, score, at, evidence in (
        ("cleared", 10, 990.0, None),
        ("watching", 50, 991.0, None),
        # Stored with its evidence, so the blocked alert is not held back waiting for it.
        ("blocked", 90, 992.0, {"critical_flags": ["Honeypot detected"]}),
    ):
        await _scan(db, TOKEN, status, score, at=at, evidence=evidence)
        await db.enqueue_launch_alerts(CHAIN, 900.0)

    pending = await db.get_pending_launch_alerts(1000.0, 3600, 5, 5)
    assert [alert["outcome"] for alert in pending] == ["impostor", "blocked"]


# --- Launch alerts -------------------------------------------------------------------------------

ITEM = {
    "chain_id": CHAIN,
    "token_address": TOKEN,
    "launchpad": "LONG",
    "verdict_url": f"/api/verdict/{CHAIN}/{TOKEN}",
}
CLEARED = {
    "outcome": "cleared",
    "status": "ok",
    "risk_level": None,
    "risk_score": 10,
    "coverage_reasons": {},
    "flags": [],
    "scanned_at": 990.0,
}


def _alert(bot, scan, check):
    return bot.format_launch_alert({**ITEM, "scan": scan, "impostor_check": check}).splitlines()


def test_an_impostor_is_never_alerted_under_a_cleared_heading(bot_module):
    lines = _alert(bot_module, CLEARED, IMPOSTOR)

    assert lines[:3] == [IMPOSTOR_HEADER, f"Token: {TOKEN}", "Launchpad: LONG"]
    assert not any("CLEARED" in line or line.startswith("\N{LARGE GREEN CIRCLE}") for line in lines)


def test_a_blocked_impostor_keeps_its_heading_and_is_labelled_once(bot_module):
    scan = {
        **CLEARED,
        "outcome": "blocked",
        "risk_score": 90,
        "flags": [IMPOSTOR_FLAG, "Honeypot detected"],
    }

    lines = _alert(bot_module, scan, IMPOSTOR)

    assert lines[:2] == [
        IMPOSTOR_HEADER,
        "\N{LARGE RED CIRCLE} BLOCKED: high-risk Robinhood Chain launch",
    ]
    assert [line for line in lines if line.startswith("• ")] == ["• Honeypot detected"]


def test_an_incomplete_impostor_scan_stays_unknown_without_a_score(bot_module):
    scan = {
        **CLEARED,
        "status": "unknown",
        "coverage_reasons": {"honeypot": "Simulation unavailable"},
    }

    lines = _alert(bot_module, scan, IMPOSTOR)

    assert lines[:2] == [
        IMPOSTOR_HEADER,
        "\N{MEDIUM WHITE CIRCLE} UNKNOWN: scan incomplete, not a safety verdict",
    ]
    assert not any(line.startswith("Risk score") for line in lines)


@pytest.mark.parametrize(
    "check, line",
    [
        (UNKNOWN, "Official token check: unknown (Token symbol or name unavailable)"),
        (OFFICIAL, "Official NVDA token (Robinhood)"),
    ],
)
def test_an_alert_states_an_unknown_or_official_check(bot_module, check, line):
    assert line in _alert(bot_module, CLEARED, check)


# An impostor check as stored before rule versions, pointers and canonical tokens.
ROUND_3_IMPOSTOR = {
    "status": "impostor",
    "symbol": "NVDA",
    "official_address": NVDA,
    "matched_by": "symbol and name",
    "third_party": False,
    "also": None,
    "reason": None,
    "list_size": 195,
}


def test_an_alert_queued_under_older_rules_still_formats(bot_module):
    assert _alert(bot_module, CLEARED, ROUND_3_IMPOSTOR)[0] == IMPOSTOR_HEADER


def test_the_official_symbol_in_an_alert_cannot_add_a_line(bot_module):
    symbol = "NV\nDA\N{RIGHT-TO-LEFT OVERRIDE}"

    impostor = _alert(bot_module, CLEARED, {**IMPOSTOR, "symbol": symbol})
    official = _alert(bot_module, CLEARED, {**OFFICIAL, "symbol": symbol})

    assert impostor[0].startswith(
        "\N{POLICE CARS REVOLVING LIGHT} IMPOSTOR: Impersonates official NV DA  token"
    )
    assert impostor[1] == f"Token: {TOKEN}"
    assert "Official NV DA  token (Robinhood)" in official


@pytest.mark.parametrize("check", [None, NO_MATCH])
def test_other_launches_carry_no_check_line(bot_module, check):
    lines = _alert(bot_module, CLEARED, check)

    assert lines[0].startswith("\N{LARGE GREEN CIRCLE} CLEARED")
    assert not any("mpersonates" in line or "fficial" in line for line in lines)


COLLISION_HEADER = (
    "\N{WARNING SIGN}\N{VARIATION SELECTOR-16} NOT OFFICIAL: "
    "shares a ticker or name with an official Robinhood token"
)
COLLISION_LINE = f"Not the official AMD token (same ticker); official contract {AMD}"


@pytest.mark.parametrize(
    "check, line",
    [
        (COLLISION, COLLISION_LINE),
        (
            check_token(TOKEN, "TSLAx", "Tesla xStock", LISTED),
            f"TSLA token in another issuer's convention (xStock), not Robinhood's TSLA; official contract {TSLA}",
        ),
    ],
)
def test_a_collision_is_never_alerted_under_a_cleared_heading(bot_module, check, line):
    lines = _alert(bot_module, CLEARED, check)

    assert lines[:3] == [COLLISION_HEADER, f"Token: {TOKEN}", "Launchpad: LONG"]
    assert line in lines
    assert not any("CLEARED" in text or text.startswith("\N{LARGE GREEN CIRCLE}") for text in lines)


def test_a_collision_keeps_its_scan_heading_and_names_the_official_token(bot_module):
    lines = _alert(bot_module, {**CLEARED, "outcome": "watching", "risk_score": 45}, COLLISION)

    assert lines[0] == "\N{LARGE YELLOW CIRCLE} WATCHING: medium-risk Robinhood Chain launch"
    assert COLLISION_LINE in lines


@pytest.mark.asyncio
async def test_a_chat_subscribed_to_blocked_launches_receives_the_impostor_alert(
    bot_module, alerts
):
    await _subscribe(alerts.db, CHAT_A, "blocked")
    await _scan(alerts.db, TOKEN, "cleared", 10, at=990.0)
    await alerts.db.record_launch_impostor_check(CHAIN, TOKEN, IMPOSTOR)
    await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)

    await bot_module.deliver_launch_alerts(alerts.bot)

    assert alerts.bot.send_message.await_args.kwargs["text"].splitlines()[0] == IMPOSTOR_HEADER


@pytest.mark.asyncio
async def test_a_cleared_launch_later_found_to_be_an_impostor_alerts_again_once(
    bot_module, alerts, now
):
    await _subscribe(alerts.db, CHAT_A, "all")
    await _scan(alerts.db, TOKEN, "cleared", 10, at=990.0)
    await alerts.db.record_launch_impostor_check(CHAIN, TOKEN, NO_MATCH)
    await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)
    await bot_module.deliver_launch_alerts(alerts.bot)
    await alerts.db.record_launch_impostor_check(CHAIN, TOKEN, IMPOSTOR)
    await _scan(alerts.db, TOKEN, "cleared", 10, at=995.0)
    for _ in range(2):
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)
        await bot_module.deliver_launch_alerts(alerts.bot)

    headings = [
        call.kwargs["text"].splitlines()[0] for call in alerts.bot.send_message.await_args_list
    ]
    assert headings == [
        "\N{LARGE GREEN CIRCLE} CLEARED: a complete scan found no major risks",
        IMPOSTOR_HEADER,
    ]


# --- Bot /scan and /token reports -------------------------------------------------------------

RISK = {
    "rug_probability": 20,
    "risk_level": "LOW",
    "status": "ok",
    "coverage": {"structural": 1},
    "critical_flags": [],
}
INCOMPLETE = {**RISK, "status": "unknown", "coverage": {"structural": 0.5}}
METADATA = {"name": "Moon", "symbol": "MOON"}


def _report(check, contract_data=None, token_info=METADATA, risk=RISK):
    return format_full_report(
        {**risk, "impostor_check": check},
        contract_data or {},
        {},
        {},
        address=TOKEN,
        token_info=token_info,
    )


@pytest.mark.parametrize(
    "check, line",
    [
        (IMPOSTOR, f"\N{WARNING SIGN} {IMPOSTOR_FLAG}"),
        (COLLISION, f"Not the official AMD token (same ticker); official contract {AMD}"),
        (
            check_token(TOKEN, "AMD", "Advanced Micro Dog", LISTED),
            f"Not the official AMD token (same ticker); official contract {AMD}",
        ),
        (
            check_token(TOKEN, "MOON", "Tesla", LISTED),
            f"Not the official TSLA token (same company name); official contract {TSLA}",
        ),
        (
            check_token(TOKEN, "NVDAX", "Moon", LISTED),
            f"Not the official NVDA token (ticker with an affix); official contract {NVDA}",
        ),
        (
            check_token(TOKEN, "AMD", "Tesla", LISTED),
            f"Not the official AMD token (same ticker); official contract {AMD}; "
            f"also resembles official TSLA token, contract {TSLA}",
        ),
        (
            check_token(TOKEN, "TSLAx", "Tesla xStock", LISTED),
            f"TSLA token in another issuer's convention (xStock), not Robinhood's TSLA; official contract {TSLA}",
        ),
        (
            check_token(TOKEN, "WETH", "WETH", LISTED),
            f"\N{WARNING SIGN} Impersonates the canonical WETH of Robinhood Chain; canonical contract {WETH}",
        ),
        (
            check_token(TOKEN, "WETH", "Wrapped Ether", LISTED),
            f"Not the canonical WETH of Robinhood Chain (same ticker); canonical contract {WETH}",
        ),
        (check_token(WETH, None, None, LISTED), "The canonical WETH of Robinhood Chain"),
        (OFFICIAL, "Official NVDA token (Robinhood)"),
        (NO_MATCH, "No match among official Robinhood Chain tokens"),
        (
            check_token(TOKEN, "MOON", "Moon", None),
            "Unknown (Official Robinhood token list unavailable)",
        ),
    ],
)
def test_a_report_states_the_check(check, line):
    assert f"Official Token Check: {line}" in assert_literal(_report(check)).splitlines()


def test_a_report_puts_the_official_contracts_in_code_spans():
    report = _report(check_token(TOKEN, "AMD", "Tesla", LISTED))

    assert (
        f"official contract `{AMD}`; also resembles official TSLA token, contract `{TSLA}`"
        in report
    )


@pytest.mark.parametrize("contract", ["0x1234", "0x_not*an`address"])
def test_a_report_leaves_an_official_contract_that_is_not_an_address_as_plain_text(contract):
    assert_literal(_report({**COLLISION, "official_address": contract}), f"official contract {contract}")


def test_a_report_on_a_check_stored_under_older_rules_still_formats():
    collision = {**ROUND_3_IMPOSTOR, "status": "collision", "matched_by": "symbol"}

    rendered = assert_literal(_report(collision)).splitlines()

    assert (
        f"Official Token Check: Not the official NVDA token (same ticker or name); official contract {NVDA}"
        in rendered
    )


@pytest.mark.parametrize(
    "check, risk, verdict",
    [
        (IMPOSTOR, RISK, "Impersonates official NVDA: do not treat as the real token"),
        (
            IMPOSTOR,
            INCOMPLETE,
            "Impersonates official NVDA: do not treat as the real token; unknown risk: provider coverage incomplete",
        ),
        (
            check_token(TOKEN, "WETH", "WETH", LISTED),
            RISK,
            "Impersonates the canonical WETH: do not treat as the real token",
        ),
    ],
)
def test_an_impostor_report_ends_with_its_own_verdict(check, risk, verdict):
    lines = assert_literal(_report(check, risk=risk)).splitlines()

    assert lines[0].startswith("\N{POLICE CARS REVOLVING LIGHT}")
    assert lines[-1] == f"\N{POLICE CARS REVOLVING LIGHT} {verdict}"


@pytest.mark.parametrize("check", [COLLISION, NO_MATCH, OFFICIAL])
def test_other_reports_keep_their_verdict(check):
    assert "Generally Safe" in _report(check).splitlines()[-1]


@pytest.mark.parametrize(
    "check, contract_data, token_info",
    [
        (None, {}, METADATA),
        (NO_MATCH, {"is_contract": False}, METADATA),
        (UNKNOWN, {"is_contract": False}, {}),
    ],
)
def test_a_report_on_a_wallet_or_without_a_check_has_no_line(check, contract_data, token_info):
    assert "Official Token Check" not in _report(check, contract_data, token_info)


@pytest.mark.parametrize(
    "check, line",
    [
        (OFFICIAL, "Official NVDA token (Robinhood)"),
        (UNKNOWN, "Unknown (Token symbol or name unavailable)"),
        # The check reads the token's symbol and name itself, so it stands without the report's.
        (IMPOSTOR, f"\N{WARNING SIGN} {IMPOSTOR_FLAG}"),
        (COLLISION, f"Not the official AMD token (same ticker); official contract {AMD}"),
        (NO_MATCH, "No match among official Robinhood Chain tokens"),
    ],
)
def test_a_check_is_stated_without_the_reports_metadata(check, line):
    assert (
        f"Official Token Check: {line}"
        in assert_literal(_report(check, token_info={})).splitlines()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
@pytest.mark.parametrize(
    "metadata, status, flagged",
    [
        ({"name": "NVIDIA", "symbol": "NVDA"}, "impostor", True),
        ({"name": "Advanced Micro Dog", "symbol": "AMD"}, "collision", False),
        ({"name": "Moon", "symbol": "AMD"}, "collision", False),
        ({"name": "Tesla, Inc. dShares", "symbol": "TSLA.d"}, "collision", False),
    ],
)
async def test_a_4663_bot_scan_checks_the_symbol_and_name_it_reads_itself(
    bot_scan_functions, handler, metadata, status, flagged
):
    ns = bot_scan_functions
    ns["format_full_report"] = format_full_report
    # The token info read fails whole when decimals() or totalSupply() reverts, which an impostor can
    # arrange; the check reads symbol() and name() on its own, as the launch hunter's does.
    ns["web3_client"].get_token_info = AsyncMock(return_value={})
    ns["container"].robinhood_assets.check_onchain = AsyncMock(
        return_value=check_token(TOKEN, metadata["symbol"], metadata["name"], LISTED)
    )
    message = update()

    await ns[handler](message, TOKEN, chain_id=4663)

    ns["container"].robinhood_assets.check_onchain.assert_awaited_once_with(
        TOKEN, RUN_ALL_DEADLINE_SECONDS
    )
    report = message.message.reply_text.await_args.args[0]
    assert ("\N{BULLET} Impersonates official" in report) is flagged
    assert "*Official Token Check:*" in report
    published = ns["container"].verdict_publisher.publish_fire_and_forget.call_args.args[2]
    assert published["impostor_check"]["status"] == status


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
async def test_a_4663_bot_scan_checks_alongside_the_analyzers(bot_scan_functions, handler):
    ns = bot_scan_functions
    checking = asyncio.Event()

    async def run_all(ctx):
        await asyncio.wait_for(checking.wait(), 1)
        return []

    ns["container"].registry.run_all = run_all
    ns["container"].robinhood_assets.check_onchain = AsyncMock(side_effect=lambda *args: checking.set() or IMPOSTOR)

    await ns[handler](update(), TOKEN, chain_id=4663)

    published = ns["container"].verdict_publisher.publish_fire_and_forget.call_args.args[2]
    assert published["impostor_check"] == IMPOSTOR


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
async def test_other_chain_bot_scans_are_not_checked(bot_scan_functions, handler):
    await bot_scan_functions[handler](update(), TOKEN, chain_id=56)

    bot_scan_functions["container"].robinhood_assets.check_onchain.assert_not_awaited()
