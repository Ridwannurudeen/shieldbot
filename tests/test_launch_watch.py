"""The fast Robinhood Chain launch watch: polling, triage, rechecks, breaker and lifecycle."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from agent.hunter import Hunter
from agent.launch_watch import POLL_INTERVAL_SECONDS, TRIAGE_WINDOW_BLOCKS, LaunchWatch
from core.database import Database
from services.launch_discovery import LaunchDiscovery, RpcUnavailableError
from services.rpc_guard import BREAKER_BASE_COOLDOWN_SECONDS, BREAKER_FAILURE_THRESHOLD, OPEN, RpcGuard

_real_sleep = asyncio.sleep
TARGET = 65_100_000


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "watch.db"))
    await database.initialize()
    yield database
    await database.close()


def launch(index, pool=True, block=None):
    return {
        "token_address": "0x" + f"{index + 1:040x}",
        "source": "uniswap_v4",
        "launchpad": "Uniswap v4",
        "source_rank": 2,
        "pool_id": "0x" + f"{index + 1:064x}" if pool else None,
        "block_number": TARGET - 100 + index if block is None else block,
        "tx_hash": "0x" + f"{index + 1:064x}",
        "block_timestamp": 1_789_000_000 + index,
    }


def token(index):
    return launch(index)["token_address"]


def pool(index):
    return launch(index)["pool_id"]


def incomplete():
    return {
        "rug_probability": 10,
        "risk_level": "LOW",
        "critical_flags": [],
        "status": "unknown",
        "coverage": {"structural": 1, "honeypot": 0},
        "coverage_reasons": {"honeypot": "Honeypot simulation unavailable"},
    }


class Polls:
    """discovery.poll stand-in returning queued swap counts at the fixed target."""

    def __init__(self, *swaps):
        self.swaps = list(swaps)
        self.pools = []

    async def __call__(self, pools=()):
        self.pools.append(set(pools))
        return {"target": TARGET, "launches": [], "swaps": self.swaps.pop(0) if self.swaps else {}}


def make_watch(db, polls=None, scan=None, guard=None, discovery=None):
    tools = MagicMock()
    tools.scan_contract = AsyncMock(side_effect=scan) if scan else AsyncMock(return_value=incomplete())
    tools.auto_watch_deployer = AsyncMock()
    if discovery is None:
        polls = polls or Polls()
        discovery = MagicMock(poll=AsyncMock(side_effect=polls.__call__), probe=AsyncMock(return_value=False))
    hunter = Hunter(
        tools=tools, db=db, ai_analyzer=MagicMock(is_available=MagicMock(return_value=False)),
        sentinel=MagicMock(), discovery=discovery, rpc_guard=guard,
    )
    watch = LaunchWatch(hunter)
    hunter.launch_watch = watch
    return watch


def scanned(watch):
    return [call.args[0] for call in watch.hunter.tools.scan_contract.await_args_list]


async def unscanned(db):
    return sorted(row["token_address"] for row in await db.get_unscanned_launches(4663, limit=1000))


# --- triage ---


@pytest.mark.asyncio
async def test_only_launches_whose_pool_swapped_are_scanned_busiest_first_then_newest(db):
    await db.upsert_discovered_launches(4663, [launch(0), launch(1), launch(2), launch(3), launch(4, pool=False)])
    watch = make_watch(db, Polls({pool(0): 1, pool(1): 5, pool(2): 1, "0x" + "ee" * 32: 9}))

    await watch.cycle()

    assert scanned(watch) == [token(1), token(2), token(0)]
    # No swap, or no pool to swap in: discovered but unscanned, never clean.
    assert await unscanned(db) == [token(3), token(4)]
    assert await db.get_tracked_pairs(status="cleared") == []


@pytest.mark.asyncio
async def test_launches_outside_the_triage_window_are_never_scanned_and_stay_unscanned(db):
    old = launch(0, block=TARGET - TRIAGE_WINDOW_BLOCKS)
    await db.upsert_discovered_launches(4663, [old, launch(1)])
    watch = make_watch(db, Polls({pool(0): 50, pool(1): 1}))

    await watch.cycle()

    assert scanned(watch) == [token(1)]
    assert await unscanned(db) == [token(0)]


@pytest.mark.asyncio
async def test_swaps_accumulate_across_polls_for_the_pools_in_the_window(db):
    await db.upsert_discovered_launches(4663, [launch(0), launch(1), launch(2)])
    polls = Polls({}, {pool(0): 1}, {pool(1): 2})
    watch = make_watch(db, polls)

    await watch.cycle()
    assert scanned(watch) == []
    await watch.cycle()
    assert scanned(watch) == [token(0)]
    await watch.cycle()
    assert scanned(watch) == [token(0), token(1)]

    # The first poll knew no target yet; later polls ask for the window's unscanned pools.
    assert polls.pools[0] == set()
    assert polls.pools[1] == {pool(0), pool(1), pool(2)}
    assert polls.pools[2] == {pool(1), pool(2)}


@pytest.mark.asyncio
async def test_a_launch_is_scanned_once_and_through_the_hunter_outcome_logic(db):
    await db.upsert_discovered_launches(4663, [launch(0)])
    watch = make_watch(db, Polls({pool(0): 1}, {pool(0): 3}))

    await watch.cycle()
    await watch.cycle()

    assert scanned(watch) == [token(0)]
    assert watch.hunter.tools.scan_contract.await_args.kwargs == {"chain_id": 4663}
    rows = await db.get_tracked_pairs(status="watching")
    assert [(row["token_address"], row["chain_id"]) for row in rows] == [(token(0), 4663)]
    cursor = await db._db.execute("SELECT scan_status FROM discovered_launches WHERE token_address = ?", (token(0),))
    assert (await cursor.fetchone())[0] == "unknown"


# --- rechecks queued by the sweep ---


@pytest.mark.asyncio
async def test_queued_rechecks_alternate_with_launch_scans(db):
    await db.upsert_discovered_launches(4663, [launch(0), launch(1), launch(2)])
    for pair in ("0xrh1", "0xrh2"):
        await db.upsert_tracked_pair(pair, token_address=pair, chain_id=4663)
    watch = make_watch(db, Polls({pool(0): 3, pool(1): 2, pool(2): 1}))
    rows = {row["pair_address"]: row for row in await db.get_tracked_pairs(status="watching")}
    watch.queue_rechecks([rows["0xrh1"], rows["0xrh2"]])
    watch.queue_rechecks([rows["0xrh1"]])

    await watch.cycle()

    assert scanned(watch) == [token(0), "0xrh1", token(1), "0xrh2", token(2)]
    assert all(call.kwargs == {"chain_id": 4663} for call in watch.hunter.tools.scan_contract.await_args_list)


# --- the breaker ---


def guarded_discovery(db, clock):
    discovery = LaunchDiscovery(db, rpc_url="https://rpc.invalid", guard=RpcGuard("Robinhood Chain", clock=clock))
    discovery._post = AsyncMock(return_value=(200, {"jsonrpc": "2.0", "id": 1, "result": hex(TARGET + 600)}))
    return discovery


@pytest.fixture
def no_waiting():
    async def sleep(delay):
        await _real_sleep(0)

    with patch("services.rpc_guard.asyncio.sleep", sleep):
        yield


@pytest.mark.asyncio
async def test_no_rpc_call_or_scan_happens_while_the_breaker_is_open_then_one_probe(db, no_waiting):
    now = [1_000.0]
    discovery = guarded_discovery(db, lambda: now[0])
    await db.upsert_discovered_launches(4663, [launch(0)])
    watch = make_watch(db, guard=discovery.guard, discovery=discovery)
    for _ in range(BREAKER_FAILURE_THRESHOLD):
        discovery.guard.record_failure("HTTP 429")

    await watch.cycle()

    discovery._post.assert_not_awaited()
    watch.hunter.tools.scan_contract.assert_not_awaited()

    now[0] += BREAKER_BASE_COOLDOWN_SECONDS
    discovery._post = AsyncMock(return_value=(429, None))
    await watch.cycle()

    # Exactly one probe, which failed: nothing else was sent and nothing was scanned.
    assert [call.args[0]["method"] for call in discovery._post.await_args_list] == ["eth_blockNumber"]
    assert discovery.guard.state == OPEN
    watch.hunter.tools.scan_contract.assert_not_awaited()
    assert await unscanned(db) == [token(0)]


@pytest.mark.asyncio
async def test_a_throttled_poll_opens_the_breaker_and_skips_the_cycle_scans(db):
    await db.upsert_discovered_launches(4663, [launch(0)])
    guard = RpcGuard("Robinhood Chain")
    polls = Polls({pool(0): 1})

    async def throttled(pools=()):
        await polls(pools)
        for _ in range(BREAKER_FAILURE_THRESHOLD):
            guard.record_failure("HTTP 429")
        raise RpcUnavailableError("RPC breaker open")

    watch = make_watch(db, guard=guard, discovery=MagicMock(poll=AsyncMock(side_effect=throttled)))
    watch._target = TARGET
    watch._swaps = {pool(0): 1}

    await watch.cycle()

    watch.hunter.tools.scan_contract.assert_not_awaited()
    assert await unscanned(db) == [token(0)]


# --- no duplicate scans between the watch and the sweep ---


@pytest.mark.asyncio
async def test_the_sweep_and_a_watch_cycle_never_scan_the_same_launch(db):
    await db.upsert_discovered_launches(4663, [launch(index) for index in range(6)])

    async def slow_scan(address, chain_id):
        await _real_sleep(0.01)
        return incomplete()

    watch = make_watch(db, Polls({pool(index): 1 for index in range(6)}), scan=slow_scan)
    watch.hunter.discovery.run = AsyncMock(return_value=None)

    with patch("agent.hunter.SCAN_INTERVAL_SECONDS", 0):
        await asyncio.gather(watch.hunter._scan_new_pairs("sweep"), watch.cycle())

    assert sorted(scanned(watch)) == sorted(token(index) for index in range(6))
    assert await unscanned(db) == []


@pytest.mark.asyncio
async def test_while_the_watch_runs_the_sweep_does_no_launch_work(db):
    await db.upsert_discovered_launches(4663, [launch(0)])
    watch = make_watch(db)
    watch.hunter.discovery.run = AsyncMock(return_value=None)
    with patch("agent.launch_watch.POLL_INTERVAL_SECONDS", 3600):
        await watch.start()
        try:
            await _real_sleep(0.05)
            watch.hunter.tools.scan_contract.reset_mock()
            assert await watch.hunter._scan_new_pairs("sweep") == []
        finally:
            await watch.stop()

    watch.hunter.discovery.run.assert_not_awaited()
    watch.hunter.tools.scan_contract.assert_not_awaited()


# --- lifecycle ---


@pytest.mark.asyncio
async def test_start_polls_repeatedly_and_stop_cancels_the_loop(db):
    watch = make_watch(db)
    with patch("agent.launch_watch.POLL_INTERVAL_SECONDS", 0.01):
        await watch.start()
        await watch.start()
        assert watch.is_running
        await _real_sleep(0.1)
        await watch.stop()

    assert not watch.is_running
    polls = watch.hunter.discovery.poll.await_count
    assert polls >= 2
    await _real_sleep(0.05)
    assert watch.hunter.discovery.poll.await_count == polls


@pytest.mark.asyncio
async def test_stop_before_start_is_harmless(db):
    watch = make_watch(db)
    await watch.stop()
    assert not watch.is_running


@pytest.mark.asyncio
async def test_stopping_mid_scan_cancels_it_and_records_nothing(db):
    await db.upsert_discovered_launches(4663, [launch(0)])
    started = asyncio.Event()

    async def hang(address, chain_id):
        started.set()
        await asyncio.Event().wait()

    watch = make_watch(db, Polls({pool(0): 1}), scan=hang)
    await watch.start()
    await asyncio.wait_for(started.wait(), timeout=5)
    await watch.stop()

    assert not watch.is_running
    assert await unscanned(db) == [token(0)]
    assert not watch.hunter.launch_lock.locked()


@pytest.mark.asyncio
async def test_a_failing_cycle_does_not_stop_the_loop(db):
    watch = make_watch(db)
    polls = Polls()

    async def fail_once(pools=()):
        if not polls.pools:
            polls.pools.append(set(pools))
            raise RuntimeError("boom")
        return await polls(pools)

    watch.hunter.discovery.poll = AsyncMock(side_effect=fail_once)
    with patch("agent.launch_watch.POLL_INTERVAL_SECONDS", 0.01):
        await watch.start()
        await _real_sleep(0.1)
        await watch.stop()

    assert watch.hunter.discovery.poll.await_count >= 2


def test_the_poll_interval_keeps_discovery_within_two_minutes_of_a_launch():
    # A launch is visible once it is CONFIRMATIONS (600 blocks, 60 s) deep; one interval more
    # plus a scan's budget wait keeps discovery inside two minutes.
    from services.launch_discovery import CONFIRMATIONS
    from agent.hunter import SCAN_REQUEST_COST
    from services.rpc_guard import RPC_BUDGET_RPS

    assert CONFIRMATIONS * 0.1 + POLL_INTERVAL_SECONDS + SCAN_REQUEST_COST / RPC_BUDGET_RPS <= 120
