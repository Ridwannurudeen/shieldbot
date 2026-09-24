"""Robinhood Chain scans, launch records, alerts and bot reports carry the official-token check."""

from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from agent.hunter import Hunter
from agent.tools import AgentTools
from core.database import Database
from core.telegram_formatter import format_full_report
from services.robinhood_assets import check_token
from tests.test_bot_app import CHAIN, CHAT_A, TOKENS, _scan, _subscribe, alerts, bot_module  # noqa: F401
from tests.test_guard_rescan import confirmed, measurement, now, publisher_for  # noqa: F401
from tests.test_robinhood_assets import AMD, LISTED, NVDA
from tests.test_telegram_markdown import assert_literal
from tests.test_verdict_wiring import bot_scan_functions, update  # noqa: F401

TOKEN = TOKENS[0]
IMPOSTOR = check_token(TOKEN, "NVDA", "NVIDIA", LISTED)
NO_MATCH = check_token(TOKEN, "MOON", "Moon", LISTED)
UNKNOWN = check_token(TOKEN, None, None, LISTED)


# --- AgentTools: the scan every hunter path uses ---------------------------------------------


def _tools(check):
    container = MagicMock()
    container.registry.run_all = AsyncMock(return_value=[])
    container.risk_engine.compute_from_results = MagicMock(
        return_value={"rug_probability": 20, "critical_flags": ["New pair (<24h)"]}
    )
    container.robinhood_assets.check_onchain = AsyncMock(return_value=check)
    return AgentTools(container), container


@pytest.mark.asyncio
async def test_a_4663_scan_leads_with_the_impostor_flag_and_keeps_its_score():
    tools, container = _tools(IMPOSTOR)

    result = await tools.scan_contract("0x" + "Ab" * 20, chain_id=4663)

    container.robinhood_assets.check_onchain.assert_awaited_once_with("0x" + "ab" * 20)
    assert result == {
        "rug_probability": 20,
        "critical_flags": ["Impersonates official NVDA token", "New pair (<24h)"],
        "honeypot_data": None,
        "impostor_check": IMPOSTOR,
    }


@pytest.mark.asyncio
async def test_other_chains_are_not_checked():
    tools, container = _tools(IMPOSTOR)

    result = await tools.scan_contract(TOKEN, chain_id=56)

    container.robinhood_assets.check_onchain.assert_not_awaited()
    assert "impostor_check" not in result


# --- Hunter: the check is stored with the launch -----------------------------------------------


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


def test_an_impostor_launch_alert_is_labelled_first(bot_module):
    text = bot_module.format_launch_alert({**ITEM, "scan": CLEARED, "impostor_check": IMPOSTOR})

    assert text.splitlines()[4] == "• Impersonates official NVDA token"


def test_a_blocked_launch_carrying_the_flag_is_labelled_once(bot_module):
    flags = ["Impersonates official NVDA token", "Honeypot detected"]
    scan = {**CLEARED, "outcome": "blocked", "risk_score": 90, "flags": flags}

    text = bot_module.format_launch_alert({**ITEM, "scan": scan, "impostor_check": IMPOSTOR})

    assert [line for line in text.splitlines() if line.startswith("• ")] == [
        f"• {flag}" for flag in flags
    ]


@pytest.mark.parametrize("check", [None, NO_MATCH, UNKNOWN, check_token(NVDA, None, None, LISTED)])
def test_other_launches_are_not_labelled(bot_module, check):
    text = bot_module.format_launch_alert({**ITEM, "scan": CLEARED, "impostor_check": check})

    assert "Impersonates" not in text


@pytest.mark.asyncio
async def test_a_queued_alert_carries_the_stored_check(bot_module, alerts):
    await _subscribe(alerts.db, CHAT_A, "all")
    await _scan(alerts.db, TOKEN, "cleared", 10, at=990.0)
    await alerts.db.record_launch_impostor_check(CHAIN, TOKEN, IMPOSTOR)
    await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)

    await bot_module.deliver_launch_alerts(alerts.bot)

    assert (
        "• Impersonates official NVDA token"
        in alerts.bot.send_message.await_args.kwargs["text"].splitlines()
    )


# --- Bot /scan and /token reports -------------------------------------------------------------

RISK = {
    "rug_probability": 20,
    "risk_level": "LOW",
    "status": "ok",
    "coverage": {"structural": 1},
    "critical_flags": [],
}


@pytest.mark.parametrize(
    "check, line",
    [
        (
            IMPOSTOR,
            f"Official Token Check: ⚠ Impersonates official NVDA token; the official one is {NVDA}",
        ),
        (
            check_token(NVDA, None, None, LISTED),
            "Official Token Check: Official NVDA token on Robinhood Chain",
        ),
        (NO_MATCH, "Official Token Check: No match among official Robinhood Chain tokens"),
        (UNKNOWN, "Official Token Check: Unknown (Token symbol or name unavailable)"),
    ],
)
def test_a_report_states_the_check(check, line):
    rendered = assert_literal(
        format_full_report({**RISK, "impostor_check": check}, {}, {}, {}, address=TOKEN)
    )

    assert line in rendered.splitlines()


def test_a_report_without_the_check_has_no_line():
    assert "Official Token Check" not in format_full_report(RISK, {}, {}, {}, address=TOKEN)


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
async def test_a_4663_bot_scan_checks_the_token_it_read(bot_scan_functions, handler):
    ns = bot_scan_functions
    ns["format_full_report"] = format_full_report
    ns["web3_client"].get_token_info = AsyncMock(
        return_value={"name": "Advanced Micro Dog", "symbol": "AMD"}
    )
    ns["container"].robinhood_assets.check = AsyncMock(
        side_effect=lambda *args: check_token(*args, LISTED)
    )
    message = update()

    await ns[handler](message, TOKEN, chain_id=4663)

    ns["container"].robinhood_assets.check.assert_awaited_once_with(
        TOKEN, "AMD", "Advanced Micro Dog"
    )
    report = message.message.reply_text.await_args.args[0]
    assert f"Impersonates official AMD token; the official one is `{AMD}`" in report
    assert "• Impersonates official AMD token" in report
    published = ns["container"].verdict_publisher.publish_fire_and_forget.call_args.args[2]
    assert published["impostor_check"]["symbol"] == "AMD"


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
async def test_other_chain_bot_scans_are_not_checked(bot_scan_functions, handler):
    await bot_scan_functions[handler](update(), TOKEN, chain_id=56)

    bot_scan_functions["container"].robinhood_assets.check.assert_not_awaited()
