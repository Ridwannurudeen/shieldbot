"""Hunter findings: stored before a pair reads blocked, and never held up by the AI narrative."""

import asyncio
import logging
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from agent.hunter import NARRATIVE_TIMEOUT_SECONDS, Hunter
from agent.launch_watch import POLL_INTERVAL_SECONDS
from core.database import Database

DAY = 24 * 3600


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "findings.db"))
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture(autouse=True)
def unpaced():
    with patch("agent.hunter.SCAN_INTERVAL_SECONDS", 0):
        yield


def blocked_result():
    return {
        "rug_probability": 90,
        "risk_level": "HIGH",
        "critical_flags": ["rug"],
        "status": "ok",
        "coverage": {"structural": 1, "honeypot": 1},
        "coverage_reasons": {},
    }


def make_hunter(db, ai=None):
    tools = MagicMock()
    tools.scan_contract = AsyncMock(return_value=blocked_result())
    tools.auto_watch_deployer = AsyncMock()
    return Hunter(
        tools=tools, db=db, ai_analyzer=ai or MagicMock(is_available=MagicMock(return_value=False)),
        sentinel=MagicMock(),
    )


async def watching(db, pair, chain_id):
    await db.upsert_tracked_pair(pair, token_address=pair, chain_id=chain_id, deployer="0xdeployer")
    await db._db.execute(
        "UPDATE tracked_pairs SET last_checked = ? WHERE pair_address = ?", (time.time() - DAY, pair)
    )
    await db._db.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [56, 4663])
async def test_a_recheck_stores_its_finding_before_the_pair_reads_blocked(db, chain_id):
    await watching(db, "0xpair", chain_id)
    hunter = make_hunter(db)
    seen = []
    update_status = db.update_tracked_pair_status

    async def spy(pair_address, status):
        seen.append((status, [finding["address"] for finding in await db.get_agent_findings()]))
        await update_status(pair_address, status)

    db.update_tracked_pair_status = spy

    assert await hunter._recheck_warn_contracts("sweep") == ["0xpair"]

    assert seen == [("blocked", ["0xpair"])]
    assert [row["pair_address"] for row in await db.get_tracked_pairs(status="blocked")] == ["0xpair"]
    hunter.tools.auto_watch_deployer.assert_awaited_once()


def hung_ai(cancelled):
    async def chat(**kwargs):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    return MagicMock(is_available=MagicMock(return_value=True), chat=chat)


@pytest.mark.asyncio
async def test_a_hung_ai_narrative_is_abandoned_and_the_finding_is_stored_without_it(db, caplog):
    cancelled = []
    hunter = make_hunter(db, ai=hung_ai(cancelled))

    with patch("agent.hunter.NARRATIVE_TIMEOUT_SECONDS", 0.05), caplog.at_level(logging.WARNING):
        await asyncio.wait_for(
            hunter._log_finding("sweep", "0xtoken", None, 90, blocked_result(), "blocked", chain_id=4663),
            timeout=5,
        )

    assert [(f["address"], f["narrative"], f["action_taken"]) for f in await db.get_agent_findings()] == [
        ("0xtoken", None, "blocked")
    ]
    assert cancelled == [True]
    assert "Hunter: AI narrative failed: TimeoutError" in caplog.text


@pytest.mark.asyncio
async def test_a_blocked_recheck_completes_while_the_ai_narrative_hangs(db):
    await watching(db, "0xpair", 4663)
    hunter = make_hunter(db, ai=hung_ai([]))

    with patch("agent.hunter.NARRATIVE_TIMEOUT_SECONDS", 0.05):
        assert await asyncio.wait_for(hunter._recheck_warn_contracts("sweep"), timeout=5) == ["0xpair"]

    assert [row["pair_address"] for row in await db.get_tracked_pairs(status="blocked")] == ["0xpair"]
    assert [f["narrative"] for f in await db.get_agent_findings()] == [None]


def test_a_hung_narrative_holds_the_launch_lock_for_at_most_one_poll_interval():
    assert NARRATIVE_TIMEOUT_SECONDS <= POLL_INTERVAL_SECONDS
