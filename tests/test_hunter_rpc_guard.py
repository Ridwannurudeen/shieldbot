"""The hunter's Robinhood Chain work under the shared RPC budget and circuit breaker."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from agent.hunter import RECHECK_MIN_INTERVAL_SECONDS, RECHECK_PAIRS_PER_SWEEP, SCAN_REQUEST_COST, Hunter
from core.database import Database
from services.rpc_guard import BREAKER_BASE_COOLDOWN_SECONDS, BREAKER_FAILURE_THRESHOLD, CLOSED, OPEN, RpcGuard

_real_sleep = asyncio.sleep
DAY = 24 * 3600


class FakeClock:
    def __init__(self):
        self.now = 1_000.0

    def monotonic(self):
        return self.now


@pytest.fixture(autouse=True)
def no_waiting():
    """Budget pacing and scan spacing return at once; the budget is asserted through acquire()."""

    async def sleep(delay):
        await _real_sleep(0)

    with patch("agent.hunter.SCAN_INTERVAL_SECONDS", 0), patch("services.rpc_guard.asyncio.sleep", sleep):
        yield


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def guard(clock):
    guard = RpcGuard("Robinhood Chain", clock=clock.monotonic)
    guard.acquire = AsyncMock(wraps=guard.acquire)
    return guard


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "hunter.db"))
    await database.initialize()
    yield database
    await database.close()


def scan_result(score, complete=True):
    return {
        "rug_probability": score,
        "risk_level": "LOW" if score <= 30 else "HIGH",
        "critical_flags": [],
        "status": "ok" if complete else "unknown",
        "coverage": {"structural": 1, "honeypot": 1 if complete else 0},
        "coverage_reasons": {} if complete else {"honeypot": "Honeypot simulation unavailable"},
    }


def launch(index):
    return {
        "token_address": "0x" + f"{index + 1:040x}",
        "source": "uniswap_v4",
        "launchpad": "Uniswap v4",
        "source_rank": 2,
        "pool_id": None,
        "block_number": 65_000_000 + index,
        "tx_hash": "0x" + f"{index + 1:064x}",
        "block_timestamp": 1_789_000_000 + index,
    }


def make_hunter(db, guard, discovery=None, scan=None):
    tools = MagicMock()
    tools.scan_contract = AsyncMock(side_effect=scan) if scan else AsyncMock(return_value=scan_result(10, False))
    tools.auto_watch_deployer = AsyncMock()
    ai = MagicMock(is_available=MagicMock(return_value=False))
    if discovery is None:
        discovery = MagicMock(run=AsyncMock(return_value=None), probe=AsyncMock(return_value=False))
    return Hunter(tools=tools, db=db, ai_analyzer=ai, sentinel=MagicMock(), discovery=discovery, rpc_guard=guard)


def open_breaker(guard):
    for _ in range(BREAKER_FAILURE_THRESHOLD):
        guard.record_failure("HTTP 429")
    assert guard.state == OPEN


async def watching(db, pair, chain_id, checked_ago=DAY):
    await db.upsert_tracked_pair(pair, token_address=pair, chain_id=chain_id)
    await db._db.execute(
        "UPDATE tracked_pairs SET last_checked = ? WHERE pair_address = ?", (time.time() - checked_ago, pair)
    )
    await db._db.commit()


async def last_checked(db, pair):
    cursor = await db._db.execute("SELECT last_checked FROM tracked_pairs WHERE pair_address = ?", (pair,))
    return (await cursor.fetchone())[0]


async def unscanned(db):
    return [row["token_address"] for row in await db.get_unscanned_launches(4663, limit=100)]


def scanned(hunter):
    return [(call.args[0], call.kwargs["chain_id"]) for call in hunter.tools.scan_contract.await_args_list]


# --- the shared budget ---


@pytest.mark.asyncio
async def test_each_4663_scan_reserves_its_worst_case_requests_and_other_chains_reserve_nothing(db, guard):
    await db.upsert_discovered_launches(4663, [launch(index) for index in range(3)])
    await watching(db, "0xbsc", 56)
    await watching(db, "0xrh", 4663)
    hunter = make_hunter(db, guard)

    await hunter._scan_new_pairs("sweep")
    await hunter._recheck_warn_contracts("sweep")

    assert len(scanned(hunter)) == 5
    assert [call.args for call in guard.acquire.await_args_list] == [(SCAN_REQUEST_COST,)] * 4


def test_the_reservation_is_the_no_retry_worst_case_of_one_scan():
    # Structural RPC reads: get_code twice, owner() and its raw re-read, the creation transaction
    # and its block. Simulation: pool lookup batch, V2 reserves, block number, three Initialize log
    # windows, then up to three pools simulated twice each.
    assert SCAN_REQUEST_COST == 6 + (1 + 1 + 1 + 3 + 3 * 2)


# --- the breaker pauses 4663 discovery and scans ---


@pytest.mark.asyncio
async def test_an_open_breaker_pauses_launch_discovery_and_scans_and_records_nothing(db, guard):
    await db.upsert_discovered_launches(4663, [launch(0), launch(1)])
    hunter = make_hunter(db, guard)
    open_breaker(guard)

    assert await hunter._scan_new_pairs("sweep") == []

    hunter.discovery.run.assert_not_awaited()
    hunter.discovery.probe.assert_not_awaited()
    hunter.tools.scan_contract.assert_not_awaited()
    assert sorted(await unscanned(db)) == sorted([launch(0)["token_address"], launch(1)["token_address"]])


@pytest.mark.asyncio
@pytest.mark.parametrize("probe_closes", [True, False])
async def test_after_the_cooldown_the_sweep_probes_once_and_resumes_only_if_it_closed(db, guard, clock, probe_closes):
    await db.upsert_discovered_launches(4663, [launch(0)])

    async def probe():
        await guard.acquire(1, probe=True)
        if probe_closes:
            guard.record_success()
        else:
            guard.record_failure("HTTP 429")
        return guard.state == CLOSED

    discovery = MagicMock(run=AsyncMock(return_value=None), probe=AsyncMock(side_effect=probe))
    hunter = make_hunter(db, guard, discovery=discovery)
    open_breaker(guard)
    clock.now += BREAKER_BASE_COOLDOWN_SECONDS

    await hunter._scan_new_pairs("sweep")

    discovery.probe.assert_awaited_once()
    if probe_closes:
        discovery.run.assert_awaited_once()
        assert scanned(hunter) == [(launch(0)["token_address"], 4663)]
    else:
        discovery.run.assert_not_awaited()
        hunter.tools.scan_contract.assert_not_awaited()
        assert await unscanned(db) == [launch(0)["token_address"]]


@pytest.mark.asyncio
async def test_a_launch_refused_when_the_breaker_opens_mid_sweep_stays_unscanned(db, guard):
    await db.upsert_discovered_launches(4663, [launch(0), launch(1), launch(2)])

    async def scan(token, chain_id):
        open_breaker(guard)
        return scan_result(10, complete=False)

    hunter = make_hunter(db, guard, scan=scan)

    await hunter._scan_new_pairs("sweep")

    newest = launch(2)["token_address"]
    assert scanned(hunter) == [(newest, 4663)]
    assert sorted(await unscanned(db)) == sorted([launch(0)["token_address"], launch(1)["token_address"]])
    watching_rows = await db.get_tracked_pairs(status="watching")
    assert [row["token_address"] for row in watching_rows] == [newest]


@pytest.mark.asyncio
async def test_an_open_breaker_skips_4663_rechecks_without_marking_them_but_not_other_chains(db, guard):
    await watching(db, "0xbsc", 56)
    await watching(db, "0xrh", 4663)
    before = await last_checked(db, "0xrh")
    hunter = make_hunter(db, guard)
    open_breaker(guard)

    await hunter._recheck_warn_contracts("sweep")

    assert scanned(hunter) == [("0xbsc", 56)]
    assert await last_checked(db, "0xrh") == before
    assert [row["pair_address"] for row in await db.get_recheck_pairs("watching", 4663, 10, time.time())] == ["0xrh"]


@pytest.mark.asyncio
async def test_4663_rechecks_run_after_every_other_chain(db, guard):
    for pair, chain in (("0xeth", 1), ("0xrh", 4663), ("0xbase", 8453), ("0xarb", 42161)):
        await watching(db, pair, chain)
    hunter = make_hunter(db, guard)

    await hunter._recheck_warn_contracts("sweep")

    assert scanned(hunter) == [("0xeth", 1), ("0xbase", 8453), ("0xarb", 42161), ("0xrh", 4663)]


# --- with the fast launch watch running ---


@pytest.mark.asyncio
async def test_with_the_watch_running_the_sweep_hands_4663_to_it_and_keeps_other_chains(db, guard):
    await db.upsert_discovered_launches(4663, [launch(0)])
    for index in range(RECHECK_PAIRS_PER_SWEEP):
        await watching(db, f"0xbsc{index}", 56, DAY + index)
    await watching(db, "0xrh", 4663)
    hunter = make_hunter(db, guard)
    hunter.launch_watch = MagicMock(is_running=True)

    assert await hunter._scan_new_pairs("sweep") == []
    await hunter._recheck_warn_contracts("sweep")

    hunter.discovery.run.assert_not_awaited()
    # The chains still share the sweep quota as before; 4663's share goes to the watch.
    assert [chain for _, chain in scanned(hunter)] == [56] * (RECHECK_PAIRS_PER_SWEEP // 2)
    (queued,) = hunter.launch_watch.queue_rechecks.call_args.args
    assert [pair["pair_address"] for pair in queued] == ["0xrh"]
    assert await last_checked(db, "0xrh") < time.time() - RECHECK_MIN_INTERVAL_SECONDS
    assert await unscanned(db) == [launch(0)["token_address"]]
