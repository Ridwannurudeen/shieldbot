"""Launch discovery that has fallen far behind the head keeps moving forward.

On 2026-09-23 the 4663 feed stopped for hours at a time and a restart did not resume it: once the
cursors were more than one fast-path range behind, every sweep read MAX_BLOCKS_PER_SWEEP blocks per
source (about 900 launches) and then needed their block headers. Batches of 50 header calls drew
HTTP 429 from the public RPC, three of them in a row opened the breaker, and the whole sweep was
discarded with no cursor moved, so the next attempt reread the same range.
"""

import asyncio
from unittest.mock import patch

import pytest
import pytest_asyncio

from core.database import Database
from services.launch_discovery import (
    CHAIN_ID,
    CONFIRMATIONS,
    HEADER_BATCH,
    MAX_BLOCKS_PER_SWEEP,
    SOURCES,
    LaunchDiscovery,
    LaunchDiscoveryError,
)
from services.rpc_guard import CLOSED, RPC_BUDGET_RPS, RpcGuard

_real_sleep = asyncio.sleep

LAUNCHER = next(source for source in SOURCES if source.name == "liquidity_launcher")
HEAD = 71_000_000
TARGET = HEAD - CONFIRMATIONS
BEHIND = TARGET - MAX_BLOCKS_PER_SWEEP
# One launch every 100 blocks, about the measured density of 900 launches per 50,000 blocks.
LAUNCH_BLOCKS = list(range(BEHIND + 50, TARGET + 1, 100))
# Calls a second the fake RPC serves before answering HTTP 429. On 2026-09-24 the public RPC
# served 29 header calls a second for thirty requests and refused 50 a second within six.
CALLS_PER_SECOND = 29


def block_hash(number):
    return "0x" + f"{number:064x}"


def launch_log(number):
    return {
        "address": LAUNCHER.address,
        "topics": [LAUNCHER.topic, "0x" + f"{number:064x}"],
        "data": "0x",
        "blockNumber": hex(number),
        "transactionHash": "0x" + f"{number + 1:064x}",
        "blockHash": block_hash(number),
        "removed": False,
    }


def token_of(number):
    return "0x" + f"{number:040x}"


class Clock:
    def __init__(self):
        self.now = 1_000.0

    def monotonic(self):
        return self.now

    async def sleep(self, seconds):
        self.now += seconds
        await _real_sleep(0)


class CatchupRpc:
    """Serves one LiquidityLauncher launch every 100 blocks and every header, at a call rate limit."""

    def __init__(self, clock=None):
        self.clock = clock
        self.calls_by_second = {}
        self.rejected = 0
        self.failing_block = None
        self.failed_batches = []

    async def __call__(self, payload):
        calls = len(payload) if isinstance(payload, list) else 1
        if self.clock is not None:
            second = int(self.clock.now)
            if self.calls_by_second.get(second, 0) + calls > CALLS_PER_SECOND:
                self.rejected += 1
                return 429, None
            self.calls_by_second[second] = self.calls_by_second.get(second, 0) + calls
        if isinstance(payload, list):
            numbers = [int(call["params"][0], 16) for call in payload]
            if self.failing_block in numbers:
                self.failed_batches.append(numbers)
                return 503, None
            return 200, [
                {
                    "jsonrpc": "2.0",
                    "id": call["id"],
                    "result": {
                        "number": hex(number),
                        "hash": block_hash(number),
                        "timestamp": hex(number // 10),
                    },
                }
                for call, number in zip(payload, numbers)
            ]
        method = payload["method"]
        if method == "eth_chainId":
            result = hex(CHAIN_ID)
        elif method == "eth_blockNumber":
            result = hex(HEAD)
        else:
            query = payload["params"][0]
            start, end = int(query["fromBlock"], 16), int(query["toBlock"], 16)
            wanted = query["address"] == LAUNCHER.address and query["topics"][0] == LAUNCHER.topic
            result = [
                launch_log(number) for number in LAUNCH_BLOCKS if wanted and start <= number <= end
            ]
        return 200, {"jsonrpc": "2.0", "id": payload["id"], "result": result}


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "catchup.db"))
    await database.initialize()
    for source in SOURCES:
        await database.set_launch_cursor(CHAIN_ID, source.name, BEHIND)
    yield database
    await database.close()


async def cursors(db):
    return {source.name: await db.get_launch_cursor(CHAIN_ID, source.name) for source in SOURCES}


async def recorded(db):
    return {row["token_address"] for row in await db.get_unscanned_launches(CHAIN_ID, limit=10_000)}


@pytest.mark.asyncio
async def test_far_behind_sweep_reads_its_headers_within_the_rpc_call_rate(db):
    clock = Clock()
    guard = RpcGuard("Robinhood Chain", clock=clock.monotonic)
    rpc = CatchupRpc(clock)
    discovery = LaunchDiscovery(db, rpc_url="https://rpc.invalid", guard=guard)
    discovery._post = rpc
    started = clock.now
    with (
        patch("services.launch_discovery.asyncio.sleep", clock.sleep),
        patch("services.rpc_guard.asyncio.sleep", clock.sleep),
    ):
        polled = await discovery.poll()

    assert rpc.rejected == 0
    # The guard grants one request per call at its rate, with a burst of one reservation.
    calls = sum(rpc.calls_by_second.values())
    assert calls <= RPC_BUDGET_RPS * (clock.now - started) + HEADER_BATCH
    assert guard.state == CLOSED
    assert len(polled["launches"]) == len(LAUNCH_BLOCKS)
    assert await recorded(db) == {token_of(number) for number in LAUNCH_BLOCKS}
    assert await cursors(db) == {source.name: TARGET for source in SOURCES}


@pytest.mark.asyncio
async def test_a_failed_header_read_keeps_the_launches_confirmed_before_it(db):
    rpc = CatchupRpc()
    rpc.failing_block = LAUNCH_BLOCKS[len(LAUNCH_BLOCKS) // 2]
    discovery = LaunchDiscovery(db, rpc_url="https://rpc.invalid")
    discovery._post = rpc
    with patch("services.launch_discovery.asyncio.sleep", Clock().sleep):
        with pytest.raises(LaunchDiscoveryError):
            await discovery.poll()

        first_unconfirmed = rpc.failed_batches[0][0]
        confirmed = [number for number in LAUNCH_BLOCKS if number < first_unconfirmed]
        assert confirmed
        assert await recorded(db) == {token_of(number) for number in confirmed}
        assert await cursors(db) == {source.name: first_unconfirmed - 1 for source in SOURCES}

        rpc.failing_block = None
        await discovery.poll()

    assert await recorded(db) == {token_of(number) for number in LAUNCH_BLOCKS}
    assert await cursors(db) == {source.name: TARGET for source in SOURCES}
