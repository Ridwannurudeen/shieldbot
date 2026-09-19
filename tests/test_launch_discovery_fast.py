"""Fast-path launch discovery: guarded requests, the breaker probe and the combined poll."""

import asyncio
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
import pytest_asyncio

from core.database import Database
from services.launch_discovery import (
    CHAIN_ID,
    CHUNK_BLOCKS,
    SOURCES,
    SWAP_V2_TOPIC,
    SWAP_V4_TOPIC,
    LaunchDiscovery,
    LaunchDiscoveryError,
    RpcUnavailableError,
)
from services.rpc_guard import (
    BREAKER_BASE_COOLDOWN_SECONDS,
    BREAKER_FAILURE_THRESHOLD,
    CLOSED,
    OPEN,
    RPC_BUDGET_RPS,
    RpcGuard,
)
from tests.test_launch_discovery import EXPECTED, HEAD, HEADERS, LOGS, TARGET, pool_of

POOL_MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951"
V2_PAIR = "0x3ca67d8d53b9668a3ae36d0e3ad72495b48281d2"
LONG_POOL = pool_of("v4_initialize_long")
GENERIC_POOL = pool_of("v4_initialize_generic")
UNRELATED_POOL = "0x" + "ab" * 32
# Every recorded launch except the LiquidityLauncher one (block 65,507,086) lies after this block.
RECENT = 65_516_000
SOURCE_ADDRESSES = [source.address for source in SOURCES]
SOURCE_TOPICS = [source.topic for source in SOURCES]
_real_sleep = asyncio.sleep


def swap_log(address, topics, block, removed=False):
    return {
        "address": address,
        "topics": topics,
        "data": "0x",
        "blockNumber": hex(block),
        "transactionHash": "0x" + "cd" * 32,
        "blockHash": "0x" + "ef" * 32,
        "removed": removed,
    }


def v4_swap(pool, block, removed=False):
    return swap_log(POOL_MANAGER, [SWAP_V4_TOPIC, pool, "0x" + "00" * 12 + "11" * 20], block, removed)


def v2_swap(pair, block):
    word = "0x" + "00" * 12 + "22" * 20
    return swap_log(pair, [SWAP_V2_TOPIC, word, word], block)


SWAPS = [
    v4_swap(LONG_POOL, 65_516_800),
    v4_swap(LONG_POOL, 65_516_900),
    v4_swap(GENERIC_POOL, 65_516_950),
    v4_swap(UNRELATED_POOL, 65_516_800),
    v4_swap(LONG_POOL, 65_516_990, removed=True),
    v2_swap(V2_PAIR, 65_516_700),
]


class FastRpc:
    """JSON-RPC stand-in serving recorded launch logs and swaps to single or combined queries."""

    def __init__(self, logs=None, head=HEAD):
        self.logs = list(LOGS.values()) + SWAPS if logs is None else list(logs)
        self.head = head
        self.payloads = []
        self.reject_combined = False

    def methods(self):
        return ["batch" if isinstance(p, list) else p["method"] for p in self.payloads]

    def log_queries(self):
        return [p["params"][0] for p in self.payloads if isinstance(p, dict) and p["method"] == "eth_getLogs"]

    async def __call__(self, payload):
        self.payloads.append(payload)
        if isinstance(payload, list):
            return 200, [
                {"jsonrpc": "2.0", "id": call["id"], "result": HEADERS.get(int(call["params"][0], 16))}
                for call in payload
            ]
        method, params = payload["method"], payload["params"]
        if method == "eth_chainId":
            result = hex(CHAIN_ID)
        elif method == "eth_blockNumber":
            result = hex(self.head)
        else:
            query = params[0]
            combined = isinstance(query["address"], list)
            if combined and self.reject_combined:
                return 200, {
                    "jsonrpc": "2.0", "id": payload["id"],
                    "error": {"code": -32000, "message": "logs matched by query exceeds limit of 10000"},
                }
            addresses = query["address"] if combined else [query["address"]]
            topics = query["topics"][0] if combined else [query["topics"][0]]
            start, end = int(query["fromBlock"], 16), int(query["toBlock"], 16)
            result = [
                log for log in self.logs
                if log["address"] in addresses and log["topics"][0] in topics
                and start <= int(log["blockNumber"], 16) <= end
            ]
        return 200, {"jsonrpc": "2.0", "id": payload["id"], "result": result}


class FakeClock:
    """A frozen clock; asyncio.sleep() records its delay and returns at once."""

    def __init__(self):
        self.now = 1_000.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    async def sleep(self, delay):
        self.sleeps.append(delay)
        await _real_sleep(0)


@pytest.fixture(autouse=True)
def clock():
    fake = FakeClock()
    with patch("services.launch_discovery.asyncio.sleep", fake.sleep):
        yield fake


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "fast.db"))
    await database.initialize()
    yield database
    await database.close()


def guarded(db, rpc, clock):
    discovery = LaunchDiscovery(
        db, rpc_url="https://rpc.invalid", guard=RpcGuard("Robinhood Chain", clock=clock.monotonic)
    )
    discovery._post = rpc
    return discovery


def open_breaker(discovery):
    for _ in range(BREAKER_FAILURE_THRESHOLD):
        discovery.guard.record_failure("HTTP 429")
    assert discovery.guard.state == OPEN


async def set_cursors(db, block):
    for source in SOURCES:
        await db.set_launch_cursor(CHAIN_ID, source.name, block)


async def cursors(db):
    return {source.name: await db.get_launch_cursor(CHAIN_ID, source.name) for source in SOURCES}


async def launches(db):
    return {row["token_address"]: row for row in await db.get_unscanned_launches(CHAIN_ID, limit=1000)}


def answer(result="0x1"):
    return 200, {"jsonrpc": "2.0", "id": 1, "result": result}


def rate_limited():
    return 200, {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "request rate exceeded"}}


# --- the shared budget and the breaker ---


@pytest.mark.asyncio
async def test_every_request_takes_one_request_of_the_shared_budget(db, clock):
    rpc = FastRpc()
    await guarded(db, rpc, clock).run()

    # With the clock frozen, request n waits until n / rate seconds after the first.
    assert len(rpc.payloads) > 10
    assert clock.sleeps == pytest.approx([n / RPC_BUDGET_RPS for n in range(1, len(rpc.payloads))])


@pytest.mark.asyncio
async def test_http_429s_open_the_breaker_and_stop_the_retries(db, clock):
    discovery = guarded(db, None, clock)
    discovery._post = AsyncMock(return_value=(429, None))

    with pytest.raises(RpcUnavailableError):
        await discovery._call("eth_blockNumber", [])

    assert discovery._post.await_count == BREAKER_FAILURE_THRESHOLD
    assert discovery.guard.state == OPEN


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [
    (503, None),
    (502, None),
    aiohttp.ClientConnectionError("connection reset"),
    asyncio.TimeoutError(),
])
async def test_server_and_transport_failures_count_and_an_answer_resets_them(db, clock, failure):
    discovery = guarded(db, None, clock)
    no_result = (200, {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "execution error"}})
    discovery._post = AsyncMock(side_effect=[failure, failure, no_result] * 2 + [failure] * 3)

    for _ in range(2):
        with pytest.raises(LaunchDiscoveryError):
            await discovery._call("eth_blockNumber", [])
        assert discovery.guard.state == CLOSED
    with pytest.raises(RpcUnavailableError):
        await discovery._call("eth_blockNumber", [])

    assert discovery.guard.state == OPEN


@pytest.mark.asyncio
async def test_rate_limit_messages_are_retried_but_never_reach_the_breaker(db, clock):
    discovery = guarded(db, None, clock)
    discovery._post = AsyncMock(side_effect=[rate_limited()] * 3 + [answer("0x7")])

    assert await discovery._call("eth_blockNumber", []) == "0x7"
    assert discovery.guard.state == CLOSED

    # Neither a failure nor an answer: two 429s, a message-only rate limit, then a third 429 opens.
    discovery._post = AsyncMock(side_effect=[(429, None), (429, None), rate_limited(), (429, None)])
    with pytest.raises(RpcUnavailableError):
        await discovery._call("eth_blockNumber", [])
    assert discovery._post.await_count == 4
    assert discovery.guard.state == OPEN


@pytest.mark.asyncio
async def test_an_open_breaker_sends_nothing(db, clock):
    rpc = FastRpc()
    discovery = guarded(db, rpc, clock)
    open_breaker(discovery)

    with pytest.raises(RpcUnavailableError):
        await discovery.run()
    with pytest.raises(RpcUnavailableError):
        await discovery.poll()
    assert await discovery.probe() is False

    assert rpc.payloads == []
    assert await cursors(db) == {source.name: None for source in SOURCES}


@pytest.mark.asyncio
async def test_the_probe_is_one_block_number_request_that_closes_the_breaker(db, clock):
    rpc = FastRpc()
    discovery = guarded(db, rpc, clock)
    open_breaker(discovery)
    clock.now += BREAKER_BASE_COOLDOWN_SECONDS

    assert await discovery.probe() is True

    assert rpc.methods() == ["eth_blockNumber"]
    assert discovery.guard.state == CLOSED


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [(429, None), rate_limited()])
async def test_a_failed_or_inconclusive_probe_reopens_with_a_longer_cooldown(db, clock, response):
    discovery = guarded(db, None, clock)
    discovery._post = AsyncMock(return_value=response)
    open_breaker(discovery)
    clock.now += BREAKER_BASE_COOLDOWN_SECONDS

    assert await discovery.probe() is False

    assert discovery._post.await_count == 1
    assert discovery.guard.state == OPEN
    clock.now += BREAKER_BASE_COOLDOWN_SECONDS
    assert not discovery.guard.probe_due
    clock.now += BREAKER_BASE_COOLDOWN_SECONDS
    assert discovery.guard.probe_due


# --- the combined poll ---


@pytest.mark.asyncio
async def test_poll_reads_every_source_and_the_triaged_swaps_in_one_request(db, clock):
    await set_cursors(db, RECENT)
    rpc = FastRpc()

    polled = await guarded(db, rpc, clock).poll(pools=[LONG_POOL, V2_PAIR])

    assert rpc.methods() == ["eth_chainId", "eth_blockNumber", "eth_getLogs", "batch"]
    (query,) = rpc.log_queries()
    assert query == {
        "fromBlock": hex(RECENT + 1),
        "toBlock": hex(TARGET),
        "address": SOURCE_ADDRESSES + [V2_PAIR],
        "topics": [SOURCE_TOPICS + [SWAP_V4_TOPIC, SWAP_V2_TOPIC]],
    }
    # The generic pool is new in this range, so its swap counts; removed and unrelated swaps do not.
    assert polled["swaps"] == {LONG_POOL: 2, GENERIC_POOL: 1, V2_PAIR: 1}
    assert polled["target"] == TARGET
    recent = {token: row for token, row in EXPECTED.items() if row[3] > RECENT}
    assert {row["token_address"] for row in polled["launches"]} == set(recent)
    rows = await launches(db)
    assert {token: (rows[token]["source"], rows[token]["pool_id"], rows[token]["block_number"])
            for token in rows} == {token: (row[0], row[2], row[3]) for token, row in recent.items()}
    assert await cursors(db) == {source.name: TARGET for source in SOURCES}


@pytest.mark.asyncio
async def test_later_polls_skip_the_chain_check_and_an_idle_poll_reads_only_the_head(db, clock):
    await set_cursors(db, RECENT)
    rpc = FastRpc()
    discovery = guarded(db, rpc, clock)
    await discovery.poll()
    rpc.payloads.clear()

    assert await discovery.poll() == {"target": TARGET, "launches": [], "swaps": {}}

    assert rpc.methods() == ["eth_blockNumber"]


@pytest.mark.asyncio
@pytest.mark.parametrize("setup", ["first run", "cursors disagree", "far behind"])
async def test_poll_catches_up_per_source_when_the_cursors_are_not_ready(db, clock, setup):
    if setup == "cursors disagree":
        await set_cursors(db, RECENT)
        await db.set_launch_cursor(CHAIN_ID, "uniswap_v2", RECENT - 1)
    elif setup == "far behind":
        await set_cursors(db, TARGET - CHUNK_BLOCKS - 1)
    rpc = FastRpc()

    polled = await guarded(db, rpc, clock).poll(pools=[LONG_POOL])

    assert polled["swaps"] == {}
    assert all(isinstance(query["address"], str) for query in rpc.log_queries())
    assert await cursors(db) == {source.name: TARGET for source in SOURCES}


@pytest.mark.asyncio
async def test_a_rejected_combined_read_falls_back_to_the_per_source_sweep(db, clock):
    await set_cursors(db, RECENT)
    rpc = FastRpc()
    rpc.reject_combined = True

    polled = await guarded(db, rpc, clock).poll(pools=[LONG_POOL])

    queries = rpc.log_queries()
    assert isinstance(queries[0]["address"], list)
    assert [query["address"] for query in queries[1:]] == SOURCE_ADDRESSES
    assert polled["swaps"] == {}
    assert {row["token_address"] for row in polled["launches"]} == {
        token for token, row in EXPECTED.items() if row[3] > RECENT
    }
    assert await cursors(db) == {source.name: TARGET for source in SOURCES}


@pytest.mark.asyncio
async def test_a_throttled_poll_records_nothing_and_moves_no_cursor(db, clock):
    await set_cursors(db, RECENT)
    rpc = FastRpc()
    discovery = guarded(db, rpc, clock)
    await discovery._check_chain()
    discovery._chain_checked = True
    rpc.payloads.clear()

    async def throttle_logs(payload):
        if isinstance(payload, dict) and payload["method"] == "eth_getLogs":
            rpc.payloads.append(payload)
            return 429, None
        return await rpc(payload)

    discovery._post = throttle_logs
    with pytest.raises(RpcUnavailableError):
        await discovery.poll(pools=[LONG_POOL])

    assert rpc.methods() == ["eth_blockNumber"] + ["eth_getLogs"] * BREAKER_FAILURE_THRESHOLD
    assert discovery.guard.state == OPEN
    assert await launches(db) == {}
    assert await cursors(db) == {source.name: RECENT for source in SOURCES}


@pytest.mark.asyncio
async def test_a_log_nobody_asked_for_is_rejected_before_anything_is_written(db, clock):
    await set_cursors(db, RECENT)
    stray = v2_swap("0x" + "99" * 20, 65_516_700)
    rpc = FastRpc()

    async def serve_stray(payload):
        status, body = await rpc(payload)
        if isinstance(payload, dict) and payload["method"] == "eth_getLogs":
            body = {**body, "result": body["result"] + [stray]}
        return status, body

    discovery = guarded(db, rpc, clock)
    discovery._post = serve_stray
    with pytest.raises(LaunchDiscoveryError):
        await discovery.poll(pools=[V2_PAIR])

    assert await launches(db) == {}
    assert await cursors(db) == {source.name: RECENT for source in SOURCES}
