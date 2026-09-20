"""The hunter hands every final 4663 launch scan result to an optional verdict publisher."""

import logging
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from agent.hunter import Hunter
from agent.launch_watch import LaunchWatch
from core.database import Database
from services.rpc_guard import BREAKER_FAILURE_THRESHOLD, RpcGuard

DAY = 24 * 3600
LAUNCH_TOKEN = "0x" + "0" * 39 + "1"


class FakePublisher:
    """Stand-in with the publisher's contract: publish(chain_id, subject, scan_result, honeypot_data=None)."""

    def __init__(self, error=None):
        self.calls = []
        self.error = error

    async def publish(self, chain_id, subject, scan_result, honeypot_data=None):
        self.calls.append((chain_id, subject, scan_result))
        if self.error is not None:
            raise self.error
        return {"subject": subject}


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "verdicts.db"))
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture(autouse=True)
def unpaced():
    with patch("agent.hunter.SCAN_INTERVAL_SECONDS", 0):
        yield


def result(score, complete=True):
    return {
        "rug_probability": score,
        "risk_level": "LOW" if score <= 30 else "HIGH",
        "critical_flags": [],
        "status": "ok" if complete else "unknown",
        "coverage": {"structural": 1, "honeypot": 1 if complete else 0},
        "coverage_reasons": {} if complete else {"honeypot": "Honeypot simulation unavailable"},
    }


def launch(pool="0x" + "ab" * 32):
    return {
        "token_address": LAUNCH_TOKEN,
        "source": "uniswap_v4",
        "launchpad": "Uniswap v4",
        "source_rank": 2,
        "pool_id": pool,
        "block_number": 65_000_000,
        "tx_hash": "0x" + "cd" * 32,
        "block_timestamp": 1_789_000_000,
    }


def make_hunter(db, publisher, scan=None, guard=None):
    tools = MagicMock()
    tools.scan_contract = AsyncMock(side_effect=scan) if scan else AsyncMock(return_value=result(10, False))
    tools.auto_watch_deployer = AsyncMock()
    return Hunter(
        tools=tools, db=db, ai_analyzer=MagicMock(is_available=MagicMock(return_value=False)),
        sentinel=MagicMock(), discovery=MagicMock(run=AsyncMock(return_value=None)),
        rpc_guard=guard, verdict_publisher=publisher,
    )


async def watching(db, pair, chain_id):
    await db.upsert_tracked_pair(pair, token_address=pair, chain_id=chain_id)
    await db._db.execute(
        "UPDATE tracked_pairs SET last_checked = ? WHERE pair_address = ?", (time.time() - DAY, pair)
    )
    await db._db.commit()


async def scan_status(db):
    cursor = await db._db.execute("SELECT scan_status FROM discovered_launches WHERE token_address = ?", (LAUNCH_TOKEN,))
    return (await cursor.fetchone())[0]


# --- the first-scan site ---


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome,status", [
    (result(85), "blocked"), (result(10, False), "unknown"), (result(50), "watching"), (result(10), "cleared"),
])
async def test_each_first_scan_result_is_published_once(db, outcome, status):
    await db.upsert_discovered_launches(4663, [launch()])
    publisher = FakePublisher()
    hunter = make_hunter(db, publisher)
    hunter.tools.scan_contract = AsyncMock(return_value=outcome)

    assert await hunter.scan_launch("inv", launch()) == status

    assert publisher.calls == [(4663, LAUNCH_TOKEN, outcome)]


@pytest.mark.asyncio
async def test_a_scan_that_errors_is_never_published(db):
    await db.upsert_discovered_launches(4663, [launch()])
    publisher = FakePublisher()
    hunter = make_hunter(db, publisher)
    hunter.tools.scan_contract = AsyncMock(side_effect=RuntimeError("provider down"))

    assert await hunter.scan_launch("inv", launch()) == "error"

    assert publisher.calls == []


@pytest.mark.asyncio
async def test_a_launch_the_breaker_refuses_is_never_published(db):
    await db.upsert_discovered_launches(4663, [launch()])
    publisher = FakePublisher()
    guard = RpcGuard("Robinhood Chain")
    for _ in range(BREAKER_FAILURE_THRESHOLD):
        guard.record_failure("HTTP 429")
    hunter = make_hunter(db, publisher, guard=guard)

    assert await hunter._scan_new_pairs("sweep") == []

    assert publisher.calls == []


@pytest.mark.asyncio
async def test_a_launch_scanned_by_the_watch_is_published(db):
    await db.upsert_discovered_launches(4663, [launch()])
    publisher = FakePublisher()
    hunter = make_hunter(db, publisher)
    hunter.discovery.poll = AsyncMock(
        return_value={"target": 65_000_100, "launches": [], "swaps": {launch()["pool_id"]: 2}}
    )
    watch = LaunchWatch(hunter)
    hunter.launch_watch = watch

    await watch.cycle()

    assert publisher.calls == [(4663, LAUNCH_TOKEN, result(10, False))]


# --- the recheck site ---


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [result(85), result(10), result(50), result(10, False)])
async def test_every_4663_recheck_result_is_published_and_other_chains_never_are(db, outcome):
    await watching(db, "0xbsc", 56)
    await watching(db, "0xrh", 4663)
    publisher = FakePublisher()
    hunter = make_hunter(db, publisher)
    hunter.tools.scan_contract = AsyncMock(return_value=outcome)

    await hunter._recheck_warn_contracts("sweep")

    assert hunter.tools.scan_contract.await_count == 2
    assert publisher.calls == [(4663, "0xrh", outcome)]


@pytest.mark.asyncio
async def test_a_recheck_whose_scan_errors_is_never_published(db, caplog):
    await watching(db, "0xrh", 4663)
    publisher = FakePublisher()
    hunter = make_hunter(db, publisher)
    hunter.tools.scan_contract = AsyncMock(side_effect=RuntimeError("provider down"))

    with caplog.at_level(logging.DEBUG):
        await hunter._recheck_warn_contracts("sweep")

    assert publisher.calls == []
    # There was no verdict to lose, so nothing reports one dropped.
    assert dropped_verdicts(caplog) == []


def dropped_verdicts(caplog):
    return [
        record.getMessage() for record in caplog.records
        if record.levelno == logging.WARNING and "not published" in record.getMessage()
    ]


@pytest.mark.asyncio
async def test_a_recheck_that_fails_after_scanning_reports_the_verdict_it_dropped(db, caplog):
    """The scan produced a verdict, but a failure before publishing it loses it: say which one."""
    await watching(db, "0xrh", 4663)
    publisher = FakePublisher()
    hunter = make_hunter(db, publisher)
    hunter.tools.scan_contract = AsyncMock(return_value=result(10))
    hunter.db.update_tracked_pair_status = AsyncMock(side_effect=RuntimeError("rows locked: secret detail"))

    with caplog.at_level(logging.DEBUG):
        await hunter._recheck_warn_contracts("sweep")

    assert publisher.calls == []
    [dropped] = dropped_verdicts(caplog)
    assert "0xrh" in dropped and "4663" in dropped
    assert "secret detail" not in caplog.text


# --- a failing publisher ---


@pytest.mark.asyncio
async def test_a_raising_publisher_never_breaks_the_hunter(db, caplog):
    await db.upsert_discovered_launches(4663, [launch()])
    await watching(db, "0xrh1", 4663)
    await watching(db, "0xrh2", 4663)
    publisher = FakePublisher(error=RuntimeError("publisher secret detail"))
    hunter = make_hunter(db, publisher)

    with caplog.at_level(logging.DEBUG):
        assert await hunter.scan_launch("inv", launch()) == "unknown"
        hunter.tools.scan_contract = AsyncMock(return_value=result(90))
        flagged = await hunter._recheck_warn_contracts("sweep")

    assert await scan_status(db) == "unknown"
    assert sorted(flagged) == ["0xrh1", "0xrh2"]
    assert {row["pair_address"] for row in await db.get_tracked_pairs(status="blocked")} == {"0xrh1", "0xrh2"}
    assert len(publisher.calls) == 3
    assert "RuntimeError" in caplog.text
    assert "publisher secret detail" not in caplog.text


@pytest.mark.asyncio
async def test_without_a_publisher_nothing_is_published(db):
    await db.upsert_discovered_launches(4663, [launch()])
    hunter = make_hunter(db, None)

    assert await hunter.scan_launch("inv", launch()) == "unknown"
    assert hunter.verdict_publisher is None
