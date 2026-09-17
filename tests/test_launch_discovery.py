"""Robinhood Chain launch discovery against logs recorded from the live 4663 RPC."""

import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiosqlite
import pytest
import pytest_asyncio
from eth_utils import keccak

from core.database import Database
from services.launch_discovery import (
    BACKFILL_BLOCKS,
    CHAIN_ID,
    CHUNK_BLOCKS,
    CONFIRMATIONS,
    MAX_ATTEMPTS,
    MAX_BLOCKS_PER_SWEEP,
    SOURCES,
    LaunchDiscovery,
    LaunchDiscoveryError,
    _decode_log,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "launch_discovery_4663.json").read_text(encoding="utf-8")
)
LOGS = FIXTURE["logs"]
HEADERS = {int(number): header for number, header in FIXTURE["headers"].items()}
SOURCE = {source.name: source for source in SOURCES}
HEAD = 65_517_600
TARGET = HEAD - CONFIRMATIONS
ANCHOR = TARGET - BACKFILL_BLOCKS
WETH = "0x0bd7d308f8e1639fab988df18a8011f41eacad73"
NATIVE = "0x" + "0" * 40

LONG_TOKEN = "0xcde854116e1be8d52612c03d099e2415dc921e18"
LONG_NUMERAIRE = "0xfe09fb328be1c286b4f597ed34764b7472ae72c5"
DOPPLER_NUMERAIRE = "0x91a2dae9699f0b82540b5886b0d8759c22820ba3"


def pool_of(key):
    return LOGS[key]["topics"][1]


def tx_of(key):
    return LOGS[key]["transactionHash"]


# token -> (source, launchpad, pool id or pair, block, tx hash, block timestamp).
# Tokens, blocks and timestamps were read by hand from the recorded topics and headers;
# 32-byte pool ids and tx hashes are taken from the recorded log they belong to.
EXPECTED = {
    LONG_TOKEN: (
        "long",
        "LONG",
        pool_of("v4_initialize_long"),
        65516739,
        tx_of("long_launch_created"),
        1789663182,
    ),
    "0x5b176c065b4df03ff85eb16fe6422fdfeeb93ba3": (
        "doppler",
        "Doppler",
        pool_of("v4_initialize_doppler"),
        65516490,
        tx_of("doppler_create"),
        1789663157,
    ),
    "0x1494579948063af3a6c06e2a1766d3ab255a4733": (
        "doppler",
        "Doppler",
        pool_of("v4_initialize_doppler_weth"),
        65516824,
        tx_of("doppler_create_weth"),
        1789663191,
    ),
    "0xa21caef80ac546a3d2ec8e37c39dbd3356601347": (
        "liquidity_launcher",
        "Uniswap LiquidityLauncher",
        pool_of("v4_initialize_liquidity_launcher"),
        65507086,
        tx_of("liquidity_launcher_token_created"),
        1789662210,
    ),
    "0xb3dfee4fba0df3fcad0ab42f17ddf10396361e18": (
        "uniswap_v4",
        "Uniswap v4",
        pool_of("v4_initialize_native"),
        65516744,
        tx_of("v4_initialize_native"),
        1789663183,
    ),
    "0x5fc5360d0400a0fd4f2af552add042d716f1d168": (
        "uniswap_v4",
        "Uniswap v4",
        pool_of("v4_initialize_generic"),
        65516383,
        tx_of("v4_initialize_generic"),
        1789663146,
    ),
    "0x77d52dca2f9fa31408042901e086c8b713063387": (
        "uniswap_v4",
        "Uniswap v4",
        pool_of("v4_initialize_generic"),
        65516383,
        tx_of("v4_initialize_generic"),
        1789663146,
    ),
    "0x0ec5cc8c070fea2f4a9c6657ea540f7412907777": (
        "uniswap_v2",
        "Uniswap V2",
        "0x3ca67d8d53b9668a3ae36d0e3ad72495b48281d2",
        65516600,
        tx_of("v2_pair_created_weth"),
        1789663168,
    ),
}


class FakeRpc:
    """JSON-RPC stand-in serving recorded logs and headers; records every payload."""

    def __init__(self, logs=None, head=HEAD, headers=None, chain_id=CHAIN_ID):
        self.logs = list(LOGS.values()) if logs is None else list(logs)
        self.head = head
        self.headers = dict(HEADERS if headers is None else headers)
        self.chain_id = chain_id
        self.payloads = []
        self.throttled = set()
        self.failing_ranges = set()

    def log_queries(self, source_name):
        address = SOURCE[source_name].address
        return [
            (int(payload["params"][0]["fromBlock"], 16), int(payload["params"][0]["toBlock"], 16))
            for payload in self.payloads
            if isinstance(payload, dict)
            and payload["method"] == "eth_getLogs"
            and payload["params"][0]["address"] == address
        ]

    async def __call__(self, payload):
        self.payloads.append(payload)
        if isinstance(payload, list):
            return 200, [
                {
                    "jsonrpc": "2.0",
                    "id": call["id"],
                    "result": self.headers.get(int(call["params"][0], 16)),
                }
                for call in payload
            ]
        method, params = payload["method"], payload["params"]
        if method == "eth_chainId":
            result = hex(self.chain_id)
        elif method == "eth_blockNumber":
            result = hex(self.head)
        else:
            query = params[0]
            start, end = int(query["fromBlock"], 16), int(query["toBlock"], 16)
            if (
                query["address"] in self.throttled
                or (query["address"], start) in self.failing_ranges
            ):
                return 429, None
            result = [
                log
                for log in self.logs
                if log["address"] == query["address"]
                and log["topics"][0] == query["topics"][0]
                and start <= int(log["blockNumber"], 16) <= end
            ]
        return 200, {"jsonrpc": "2.0", "id": payload["id"], "result": result}


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "launches.db"))
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture(autouse=True)
def sleep():
    with (
        patch("services.launch_discovery.asyncio.sleep", new_callable=AsyncMock) as mock,
        patch("services.launch_discovery.REQUEST_INTERVAL", 0),
    ):
        yield mock


def discovery_with(db, rpc):
    discovery = LaunchDiscovery(db, rpc_url="https://rpc.invalid")
    discovery._post = rpc
    return discovery


async def launches(db):
    return {
        row["token_address"]: row for row in await db.get_unscanned_launches(CHAIN_ID, limit=1000)
    }


async def cursors(db):
    return {source.name: await db.get_launch_cursor(CHAIN_ID, source.name) for source in SOURCES}


def as_expected(row):
    return (
        row["source"],
        row["launchpad"],
        row["pool_id"],
        row["block_number"],
        row["tx_hash"],
        row["block_timestamp"],
    )


# --- verified sources and decoding ---


VERIFIED_EVENTS = {
    "long": (
        "0x1eef016f22a943abc7dd11422edee9d235942104",
        "LaunchCreated(address,address,address,address,address,bytes32,uint48,uint48,string)",
        "long_launch_created",
    ),
    "doppler": (
        "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544",
        "Create(address,address,address)",
        "doppler_create",
    ),
    "liquidity_launcher": (
        "0x0000ffffbe8efe702c8703ae3477ff5de3d319c0",
        "TokenCreated(address)",
        "liquidity_launcher_token_created",
    ),
    "uniswap_v4": (
        "0x8366a39cc670b4001a1121b8f6a443a643e40951",
        "Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)",
        "v4_initialize_generic",
    ),
    "uniswap_v2": (
        "0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f",
        "PairCreated(address,address,address,uint256)",
        "v2_pair_created_weth",
    ),
}


@pytest.mark.parametrize("name", sorted(VERIFIED_EVENTS))
def test_sources_follow_the_verified_contract_and_event(name):
    address, signature, recorded = VERIFIED_EVENTS[name]
    source = SOURCE[name]
    assert source.address == address == LOGS[recorded]["address"]
    assert source.topic == "0x" + keccak(text=signature).hex() == LOGS[recorded]["topics"][0]


def test_sources_rank_launchpads_above_generic_pools():
    assert [source.name for source in sorted(SOURCES, key=lambda source: -source.rank)] == [
        "long",
        "doppler",
        "liquidity_launcher",
        "uniswap_v4",
        "uniswap_v2",
    ]
    assert set(SOURCE) == set(VERIFIED_EVENTS)


@pytest.mark.parametrize(
    "name,recorded,tokens,pool",
    [
        ("long", "long_launch_created", [LONG_TOKEN], None),
        ("doppler", "doppler_create_long", [LONG_TOKEN], None),
        ("doppler", "doppler_create_weth", ["0x1494579948063af3a6c06e2a1766d3ab255a4733"], None),
        (
            "liquidity_launcher",
            "liquidity_launcher_token_created",
            ["0xa21caef80ac546a3d2ec8e37c39dbd3356601347"],
            None,
        ),
        (
            "uniswap_v4",
            "v4_initialize_long",
            [LONG_TOKEN, LONG_NUMERAIRE],
            pool_of("v4_initialize_long"),
        ),
        (
            "uniswap_v4",
            "v4_initialize_native",
            [NATIVE, "0xb3dfee4fba0df3fcad0ab42f17ddf10396361e18"],
            pool_of("v4_initialize_native"),
        ),
        (
            "uniswap_v2",
            "v2_pair_created_weth",
            [WETH, "0x0ec5cc8c070fea2f4a9c6657ea540f7412907777"],
            "0x3ca67d8d53b9668a3ae36d0e3ad72495b48281d2",
        ),
    ],
)
def test_decodes_recorded_launch_logs(name, recorded, tokens, pool):
    log = LOGS[recorded]
    block = int(log["blockNumber"], 16)
    assert _decode_log(SOURCE[name], log, block, block) == (tokens, pool)


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda log: log.update(address=SOURCE["doppler"].address),
        lambda log: log["topics"].pop(),
        lambda log: log["topics"].__setitem__(0, SOURCE["uniswap_v4"].topic),
        lambda log: log["topics"].__setitem__(2, "0x" + "ff" * 32),
        lambda log: log.update(removed=True),
        lambda log: log.update(blockNumber="0x0"),
        lambda log: log.update(transactionHash="0x1234"),
        lambda log: log.update(blockHash=None),
        lambda log: log.update(data="0x"),
    ],
)
def test_malformed_or_foreign_logs_are_rejected(corrupt):
    log = copy.deepcopy(LOGS["v2_pair_created_weth"])
    corrupt(log)
    with pytest.raises(LaunchDiscoveryError):
        _decode_log(SOURCE["uniswap_v2"], log, 65516600, 65516600)


# --- sweeps ---


@pytest.mark.asyncio
async def test_first_sweep_records_each_token_once_with_its_most_specific_launchpad(db):
    await discovery_with(db, FakeRpc()).run()

    rows = await launches(db)
    assert {token: as_expected(row) for token, row in rows.items()} == EXPECTED
    # A launchpad's numeraire in the same transaction is a quote asset, not a launch.
    assert LONG_NUMERAIRE not in rows and DOPPLER_NUMERAIRE not in rows


@pytest.mark.asyncio
async def test_quote_assets_are_never_recorded_as_launches(db):
    await discovery_with(db, FakeRpc()).run()

    rows = await launches(db)
    assert WETH not in rows and NATIVE not in rows
    assert "0xb3dfee4fba0df3fcad0ab42f17ddf10396361e18" in rows
    assert "0x0ec5cc8c070fea2f4a9c6657ea540f7412907777" in rows


@pytest.mark.asyncio
async def test_first_run_backfill_is_bounded_behind_the_confirmed_head(db):
    rpc = FakeRpc()
    await discovery_with(db, rpc).run()

    for source in SOURCES:
        queries = rpc.log_queries(source.name)
        assert queries[0][0] == ANCHOR + 1
        assert queries[-1][1] == TARGET
    assert BACKFILL_BLOCKS < MAX_BLOCKS_PER_SWEEP
    assert await cursors(db) == {source.name: TARGET for source in SOURCES}


@pytest.mark.asyncio
async def test_sweep_chunks_within_rpc_limit_and_stops_at_the_sweep_cap(db):
    behind = TARGET - 3 * MAX_BLOCKS_PER_SWEEP
    for source in SOURCES:
        await db.set_launch_cursor(CHAIN_ID, source.name, behind)
    rpc = FakeRpc()
    await discovery_with(db, rpc).run()

    for source in SOURCES:
        queries = rpc.log_queries(source.name)
        assert queries[0][0] == behind + 1
        assert all(end - start + 1 <= CHUNK_BLOCKS for start, end in queries)
        assert all(nxt[0] == prev[1] + 1 for prev, nxt in zip(queries, queries[1:]))
        assert queries[-1][1] == behind + MAX_BLOCKS_PER_SWEEP
    assert await cursors(db) == {source.name: behind + MAX_BLOCKS_PER_SWEEP for source in SOURCES}


@pytest.mark.asyncio
async def test_throttled_source_keeps_its_cursor_while_other_sources_advance(db, sleep):
    rpc = FakeRpc()
    rpc.throttled.add(SOURCE["long"].address)
    await discovery_with(db, rpc).run()

    assert await cursors(db) == {**{source.name: TARGET for source in SOURCES}, "long": ANCHOR}
    assert len(rpc.log_queries("long")) == MAX_ATTEMPTS
    assert [call.args[0] for call in sleep.await_args_list] == [1, 2, 4]
    # Without the LONG event the token keeps its Doppler label until LONG catches up.
    assert (await launches(db))[LONG_TOKEN]["launchpad"] == "Doppler"

    rpc.throttled.clear()
    await discovery_with(db, rpc).run()

    assert await cursors(db) == {source.name: TARGET for source in SOURCES}
    assert as_expected((await launches(db))[LONG_TOKEN]) == EXPECTED[LONG_TOKEN]


@pytest.mark.asyncio
async def test_failure_mid_range_stops_after_the_last_completed_chunk(db):
    rpc = FakeRpc()
    rpc.failing_ranges.add((SOURCE["uniswap_v2"].address, ANCHOR + 1 + CHUNK_BLOCKS))
    await discovery_with(db, rpc).run()

    assert (await cursors(db))["uniswap_v2"] == ANCHOR + CHUNK_BLOCKS
    assert rpc.log_queries("uniswap_v2")[-1][0] == ANCHOR + 1 + CHUNK_BLOCKS


@pytest.mark.asyncio
async def test_generic_pool_first_then_launchpad_upgrades_label_and_keeps_pool(db):
    rpc = FakeRpc(logs=[LOGS["v4_initialize_long"]])
    await discovery_with(db, rpc).run()
    assert as_expected((await launches(db))[LONG_TOKEN])[:2] == ("uniswap_v4", "Uniswap v4")

    await db.set_launch_cursor(CHAIN_ID, "long", ANCHOR)
    rpc.logs = [LOGS["long_launch_created"]]
    await discovery_with(db, rpc).run()

    assert as_expected((await launches(db))[LONG_TOKEN]) == EXPECTED[LONG_TOKEN]


@pytest.mark.asyncio
async def test_lower_ranked_event_never_downgrades_a_launchpad_label(db):
    long_row = {
        "token_address": LONG_TOKEN,
        "source": "long",
        "launchpad": "LONG",
        "source_rank": 5,
        "pool_id": None,
        "block_number": 65516739,
        "tx_hash": tx_of("long_launch_created"),
        "block_timestamp": 1789663182,
    }
    later_pool = {
        **long_row,
        "source": "uniswap_v4",
        "launchpad": "Uniswap v4",
        "source_rank": 2,
        "pool_id": "0x" + "ab" * 32,
        "block_number": 65520000,
        "tx_hash": "0x" + "cd" * 32,
        "block_timestamp": 1789663500,
    }
    await db.upsert_discovered_launches(CHAIN_ID, [long_row])
    await db.upsert_discovered_launches(CHAIN_ID, [later_pool])

    assert as_expected((await launches(db))[LONG_TOKEN]) == (
        "long",
        "LONG",
        "0x" + "ab" * 32,
        65516739,
        tx_of("long_launch_created"),
        1789663182,
    )

    other_pool_earlier_block = {
        **later_pool,
        "pool_id": "0x" + "ef" * 32,
        "block_number": 65516000,
        "tx_hash": "0x" + "12" * 32,
        "block_timestamp": 1789663100,
    }
    await db.upsert_discovered_launches(CHAIN_ID, [other_pool_earlier_block])

    assert as_expected((await launches(db))[LONG_TOKEN]) == (
        "long",
        "LONG",
        "0x" + "ab" * 32,
        65516000,
        "0x" + "12" * 32,
        1789663100,
    )


@pytest.mark.asyncio
async def test_reprocessing_a_range_does_not_duplicate_launches(db):
    rpc = FakeRpc()
    await discovery_with(db, rpc).run()
    first = await launches(db)
    for source in SOURCES:
        await db.set_launch_cursor(CHAIN_ID, source.name, ANCHOR)

    await discovery_with(db, rpc).run()

    assert await launches(db) == first
    cursor = await db._db.execute(
        "SELECT COUNT(*) FROM discovered_launches WHERE chain_id = ?", (CHAIN_ID,)
    )
    assert (await cursor.fetchone())[0] == len(EXPECTED)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {number: {**header, "hash": "0x" + "ee" * 32} for number, header in HEADERS.items()},
    ],
)
async def test_missing_or_reorged_headers_record_nothing_and_advance_no_cursor(db, headers):
    rpc = FakeRpc(headers=headers)
    with pytest.raises(LaunchDiscoveryError):
        await discovery_with(db, rpc).run()

    assert await launches(db) == {}
    assert await cursors(db) == {source.name: ANCHOR for source in SOURCES}


@pytest.mark.asyncio
async def test_wrong_chain_is_rejected_before_cursors_or_log_reads(db):
    rpc = FakeRpc(chain_id=56)
    with pytest.raises(LaunchDiscoveryError):
        await discovery_with(db, rpc).run()

    assert await cursors(db) == {source.name: None for source in SOURCES}
    assert all(payload["method"] != "eth_getLogs" for payload in rpc.payloads)


# --- RPC retry ---


@pytest.mark.asyncio
async def test_http_429_backs_off_exponentially_then_returns_the_result(db, sleep):
    discovery = LaunchDiscovery(db, rpc_url="https://rpc.invalid")
    discovery._post = AsyncMock(
        side_effect=[
            (429, None),
            (429, None),
            (200, {"jsonrpc": "2.0", "id": 1, "result": "0x1237"}),
        ]
    )

    assert await discovery._call("eth_chainId", []) == "0x1237"
    assert [call.args[0] for call in sleep.await_args_list] == [1, 2]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        {"code": -32005, "message": "limit exceeded"},
        {"code": -32000, "message": "Too Many Requests"},
    ],
)
async def test_json_rpc_rate_limit_errors_are_retried(db, sleep, error):
    discovery = LaunchDiscovery(db, rpc_url="https://rpc.invalid")
    discovery._post = AsyncMock(
        side_effect=[
            (200, {"jsonrpc": "2.0", "id": 1, "error": error}),
            (200, {"jsonrpc": "2.0", "id": 1, "result": "0x1237"}),
        ]
    )

    assert await discovery._call("eth_chainId", []) == "0x1237"
    assert [call.args[0] for call in sleep.await_args_list] == [1]


@pytest.mark.asyncio
async def test_retries_are_bounded_and_end_in_an_error(db, sleep):
    discovery = LaunchDiscovery(db, rpc_url="https://rpc.invalid")
    discovery._post = AsyncMock(return_value=(429, None))

    with pytest.raises(LaunchDiscoveryError):
        await discovery._call("eth_blockNumber", [])
    assert discovery._post.await_count == MAX_ATTEMPTS
    assert [call.args[0] for call in sleep.await_args_list] == [1, 2, 4]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        (200, {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "invalid params"}}),
        (200, {"jsonrpc": "2.0", "id": 1, "result": None}),
        (400, None),
    ],
)
async def test_non_retryable_failures_raise_without_waiting(db, sleep, response):
    discovery = LaunchDiscovery(db, rpc_url="https://rpc.invalid")
    discovery._post = AsyncMock(return_value=response)

    with pytest.raises(LaunchDiscoveryError):
        await discovery._call("eth_blockNumber", [])
    assert discovery._post.await_count == 1
    sleep.assert_not_awaited()


# --- persistence ---


@pytest.mark.asyncio
async def test_unscanned_launches_are_newest_first_and_scans_are_recorded(db):
    await discovery_with(db, FakeRpc()).run()
    newest = await db.get_unscanned_launches(CHAIN_ID, limit=3)
    assert [row["block_number"] for row in newest] == [65516824, 65516744, 65516739]

    await db.record_launch_scan(CHAIN_ID, newest[0]["token_address"], "unknown", 12.5)

    remaining = await db.get_unscanned_launches(CHAIN_ID, limit=1000)
    assert newest[0]["token_address"] not in {row["token_address"] for row in remaining}
    cursor = await db._db.execute(
        "SELECT scan_status, risk_score, scanned_at FROM discovered_launches WHERE token_address = ?",
        (newest[0]["token_address"],),
    )
    status, score, scanned_at = await cursor.fetchone()
    assert (status, score) == ("unknown", 12.5) and scanned_at is not None


@pytest.mark.asyncio
async def test_rediscovery_keeps_a_recorded_scan_outcome(db):
    rpc = FakeRpc()
    await discovery_with(db, rpc).run()
    await db.record_launch_scan(CHAIN_ID, LONG_TOKEN, "watching", 45.0)
    for source in SOURCES:
        await db.set_launch_cursor(CHAIN_ID, source.name, ANCHOR)

    await discovery_with(db, rpc).run()

    assert LONG_TOKEN not in await launches(db)


@pytest.mark.asyncio
async def test_tracked_pairs_migration_tags_legacy_rows_as_bsc(tmp_path):
    path = str(tmp_path / "legacy.db")
    async with aiosqlite.connect(path) as legacy:
        await legacy.execute("""
            CREATE TABLE tracked_pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pair_address TEXT UNIQUE NOT NULL,
                token_address TEXT,
                deployer TEXT,
                liquidity_usd REAL,
                first_seen REAL NOT NULL,
                last_checked REAL,
                status TEXT NOT NULL DEFAULT 'watching'
            )
        """)
        await legacy.execute(
            "INSERT INTO tracked_pairs (pair_address, token_address, first_seen) VALUES ('0xpair', '0xtoken', 1)"
        )
        await legacy.commit()

    database = Database(path)
    await database.initialize()
    try:
        await database.upsert_tracked_pair(LONG_TOKEN, token_address=LONG_TOKEN, chain_id=CHAIN_ID)
        rows = {
            row["pair_address"]: row for row in await database.get_tracked_pairs(status="watching")
        }
        assert rows["0xpair"]["chain_id"] == 56
        assert rows[LONG_TOKEN]["chain_id"] == CHAIN_ID
    finally:
        await database.close()

    reopened = Database(path)
    await reopened.initialize()
    try:
        assert {row["chain_id"] for row in await reopened.get_tracked_pairs()} == {56, CHAIN_ID}
    finally:
        await reopened.close()
