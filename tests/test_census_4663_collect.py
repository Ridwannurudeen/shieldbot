"""Collector durability, provider boundaries, and chain identity checks."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import aiosqlite
import pytest

from scripts.census_4663.collect import Collector, Rpc, RpcError
from scripts.census_4663.events import POOL_MANAGER, V2_FACTORY, WETH, ZERO
from scripts.census_4663.storage import data_directory, initialize, load_data
from tests.test_census_4663_events import OTHER, PAIR, POOL_ID, TOKEN, log_fixture


class FakeRpc:
    def __init__(self):
        self.chain_id = 4663
        self.tip = 110
        self.hashes = {}
        self.entries = []
        self.transactions = {}
        self.receipts = {}
        self.queries = []

    def header(self, number):
        return {
            "number": hex(number),
            "hash": self.hashes.get(number, "0x" + f"{number:064x}"),
            "timestamp": hex(1700000000 + number),
        }

    async def call(self, method, params):
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.tip)
        if method == "eth_getBlockByNumber":
            return self.header(int(params[0], 16))
        if method == "eth_getTransactionByHash":
            return self.transactions[params[0]]
        if method == "eth_getTransactionReceipt":
            return self.receipts[params[0]]
        raise AssertionError(f"Unexpected method {method}")

    async def batch(self, calls):
        return [await self.call(method, params) for method, params in calls]

    async def logs(self, query):
        self.queries.append(query)
        addresses = (
            query["address"]
            if isinstance(query["address"], list)
            else [query["address"]]
        )
        return [
            log
            for log in self.entries
            if log["address"] in addresses
            and int(query["fromBlock"], 16)
            <= int(log["blockNumber"], 16)
            <= int(query["toBlock"], 16)
            and log["topics"][0] in query["topics"][0]
        ]

    def creation(
        self, number=100, token=TOKEN, pool_id=POOL_ID, tx_id=1, transfers=None
    ):
        log = log_fixture(
            "Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)",
            ["bytes32", "address", "address"],
            [bytes.fromhex(pool_id[2:]), WETH, token],
            ["uint24", "int24", "address", "uint160", "int24"],
            [3000, 60, ZERO, 2**96, 0],
        )
        log.update(
            blockNumber=hex(number),
            blockHash=self.header(number)["hash"],
            transactionHash="0x" + f"{tx_id:064x}",
            logIndex="0x5",
        )
        self.entries.append(log)
        tx_hash = log["transactionHash"]
        receipt_logs = [log]
        for index, sender in enumerate(transfers or []):
            transfer = log_fixture(
                "Transfer(address,address,uint256)",
                ["address", "address"],
                [sender, OTHER],
                ["uint256"],
                [10**18],
            )
            transfer.update(
                address=token,
                blockNumber=hex(number),
                blockHash=log["blockHash"],
                transactionHash=tx_hash,
                logIndex=hex(index),
            )
            receipt_logs.append(transfer)
        self.transactions[tx_hash] = {
            "hash": tx_hash,
            "blockHash": log["blockHash"],
            "from": OTHER,
            "to": PAIR,
        }
        self.receipts[tx_hash] = {
            "transactionHash": tx_hash,
            "blockHash": log["blockHash"],
            "blockNumber": hex(number),
            "status": "0x1",
            "logs": receipt_logs,
        }
        return log


def test_data_directory_rejects_checkout():
    with pytest.raises(ValueError, match="outside the repository"):
        data_directory(Path(__file__).resolve().parents[1] / "census-output")


def test_data_directory_rejects_other_git_checkout(tmp_path):
    (tmp_path / ".git").write_text("gitdir: worktree", encoding="utf-8")
    with pytest.raises(ValueError, match="outside any repository"):
        data_directory(tmp_path / "output")


@pytest.mark.asyncio
async def test_report_data_loader_rejects_database_without_chain_binding(tmp_path):
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
    with pytest.raises(ValueError, match="not bound to chain 4663"):
        await load_data(tmp_path)


@pytest.mark.asyncio
async def test_report_data_loader_rejects_wrong_chain(tmp_path):
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        await db.execute("INSERT INTO meta VALUES ('chain_id', '1')")
        await db.commit()
    with pytest.raises(ValueError, match="not bound to chain 4663"):
        await load_data(tmp_path)


@pytest.mark.asyncio
async def test_report_data_loader_does_not_create_empty_census(tmp_path):
    with pytest.raises(ValueError, match="No census database"):
        await load_data(tmp_path)
    assert not (tmp_path / "census.sqlite3").exists()


@pytest.mark.asyncio
async def test_cursor_persists_across_connection_restart(tmp_path):
    rpc = FakeRpc()
    rpc.creation()
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        assert (
            await Collector(rpc, db, confirmations=2, chunk_size=4).run_once(100, 104)
            == 104
        )
    rpc.queries.clear()
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        assert (
            await Collector(rpc, db, confirmations=2, chunk_size=4).run_once(
                to_block=107
            )
            == 107
        )
    data = await load_data(tmp_path)
    assert data["meta"]["cursor"] == "107"
    assert len(data["pools"]) == len(data["events"]) == 1
    assert all(int(query["fromBlock"], 16) >= 105 for query in rpc.queries)


@pytest.mark.asyncio
async def test_reorg_replaces_orphan_pool_events_and_evidence(tmp_path):
    rpc = FakeRpc()
    rpc.creation(number=103)
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        collector = Collector(rpc, db, confirmations=2)
        await collector.run_once(100, 104)
        rpc.entries.clear()
        rpc.hashes.update({103: "0x" + "aa" * 32, 104: "0x" + "bb" * 32})
        replacement = "0x" + "11" * 32
        rpc.creation(number=103, token=OTHER, pool_id=replacement, tx_id=2)
        await collector.run_once(to_block=104)
    data = await load_data(tmp_path)
    assert [pool["pool_key"] for pool in data["pools"]] == [replacement]
    assert [event["pool_key"] for event in data["events"]] == [replacement]
    assert [item["tx_hash"] for item in data["evidence"]] == ["0x" + f"{2:064x}"]
    assert data["meta"]["cursor"] == "104"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "senders,expected", [([ZERO], "atomic"), ([OTHER, ZERO], "prior"), ([], "prior")]
)
async def test_launch_evidence_uses_first_transfer_in_creation_receipt(
    tmp_path, senders, expected
):
    rpc = FakeRpc()
    rpc.creation(transfers=senders)
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        await Collector(rpc, db, confirmations=2).run_once(100, 101)
    evidence = (await load_data(tmp_path))["evidence"][0]["data"]
    assert evidence["from"] == OTHER
    assert evidence["to"] == PAIR
    assert evidence["tokens"] == {
        TOKEN: {"first_transfer_mint": expected == "atomic", "launch_source": expected}
    }
    assert evidence["emitters"] == sorted(
        [POOL_MANAGER, TOKEN] if senders else [POOL_MANAGER]
    )


@pytest.mark.asyncio
async def test_wrong_rpc_chain_is_rejected_before_log_requests(tmp_path):
    rpc = FakeRpc()
    rpc.chain_id = 1
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        with pytest.raises(ValueError, match="RPC chain mismatch"):
            await Collector(rpc, db).run_once(100, 101)
        assert await (await db.execute("SELECT count(*) FROM meta")).fetchone() == (0,)
    assert not rpc.queries


@pytest.mark.asyncio
async def test_failed_range_does_not_advance_cursor(tmp_path):
    rpc = FakeRpc()
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        collector = Collector(rpc, db, confirmations=2)
        await collector.run_once(100, 102)
        rpc.logs = AsyncMock(side_effect=RpcError("provider unavailable"))
        with pytest.raises(RpcError, match="provider unavailable"):
            await collector.run_once(to_block=104)
    data = await load_data(tmp_path)
    assert data["meta"]["cursor"] == "102"
    assert max(row["number"] for row in data["blocks"]) == 102


@pytest.mark.asyncio
async def test_confirmation_depth_limits_collection(tmp_path):
    rpc = FakeRpc()
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        assert await Collector(rpc, db, confirmations=4).run_once(100, 110) == 106
    assert max(int(query["toBlock"], 16) for query in rpc.queries) == 106


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corruption", ["log_hash", "receipt_hash", "receipt_status", "receipt_log_hash"]
)
async def test_inconsistent_creation_data_is_not_committed(tmp_path, corruption):
    rpc = FakeRpc()
    log = rpc.creation(transfers=[ZERO])
    receipt = rpc.receipts[log["transactionHash"]]
    if corruption == "log_hash":
        log["blockHash"] = "0x" + "ff" * 32
    elif corruption == "receipt_hash":
        receipt["blockHash"] = "0x" + "ff" * 32
    elif corruption == "receipt_status":
        receipt["status"] = "0x0"
    else:
        receipt["logs"][1]["blockHash"] = "0x" + "ff" * 32
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        with pytest.raises(RpcError, match="mismatch"):
            await Collector(rpc, db, confirmations=2).run_once(100, 101)
    data = await load_data(tmp_path)
    assert data["meta"]["cursor"] == "99"
    assert not data["events"] and not data["pools"] and not data["evidence"]


@pytest.mark.asyncio
async def test_untracked_v4_swap_is_ignored(tmp_path):
    rpc = FakeRpc()
    log = log_fixture(
        "Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)",
        ["bytes32", "address"],
        [bytes.fromhex(POOL_ID[2:]), TOKEN],
        ["int128", "int128", "uint160", "uint128", "int24", "uint24"],
        [-1, 1, 2**96, 100, 0, 3000],
    )
    log.update(blockNumber="0x64", blockHash=rpc.header(100)["hash"])
    rpc.entries.append(log)
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        await Collector(rpc, db, confirmations=2).run_once(100, 101)
    data = await load_data(tmp_path)
    assert not data["events"] and not data["pools"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        "block range too large",
        "{'code': -32000, 'message': 'logs matched by query exceeds limit of 10000'}",
    ],
)
async def test_rpc_bounded_range_fallback_preserves_every_block(error):
    rpc = Rpc(MagicMock())
    calls = []

    async def respond(method, params):
        query = params[0]
        lower, upper = int(query["fromBlock"], 16), int(query["toBlock"], 16)
        calls.append((lower, upper))
        if upper - lower > 1:
            raise RpcError(error)
        return list(range(lower, upper + 1))

    rpc.call = AsyncMock(side_effect=respond)
    assert await rpc.logs(
        {"fromBlock": "0xa", "toBlock": "0x11", "address": POOL_MANAGER}
    ) == list(range(10, 18))
    assert calls == [
        (10, 17),
        (10, 13),
        (10, 11),
        (12, 13),
        (14, 17),
        (14, 15),
        (16, 17),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response", [{"id": 1}, {"id": 1, "result": None}, {"id": 2, "result": []}]
)
async def test_rpc_missing_results_never_become_empty_logs(response):
    rpc = Rpc(MagicMock())
    rpc._post = AsyncMock(return_value=response)
    with pytest.raises(RpcError, match="Missing RPC result"):
        await rpc.call("eth_getLogs", [{}])


@pytest.mark.asyncio
async def test_rpc_batch_reorders_response_ids():
    rpc = Rpc(MagicMock())
    rpc._post = AsyncMock(
        return_value=[{"id": 2, "result": "second"}, {"id": 1, "result": "first"}]
    )
    assert await rpc.batch([("eth_chainId", []), ("eth_blockNumber", [])]) == [
        "first",
        "second",
    ]


@pytest.mark.asyncio
async def test_rpc_transport_retries_with_timeout_and_exponential_backoff():
    session = MagicMock()
    session.post.side_effect = aiohttp.ClientConnectionError("offline")
    rpc = Rpc(session)
    with patch(
        "scripts.census_4663.collect.asyncio.sleep", new_callable=AsyncMock
    ) as sleep:
        with pytest.raises(RpcError, match="after 6 attempts"):
            await rpc.call("eth_chainId", [])
    assert session.post.call_count == 6
    assert [call.args[0] for call in sleep.call_args_list if call.args[0] >= 1] == [
        1,
        2,
        4,
        8,
        16,
    ]
    assert all(
        call.kwargs["timeout"].total == 45 for call in session.post.call_args_list
    )


@pytest.mark.asyncio
async def test_rpc_server_rate_limit_retries_same_request():
    rpc = Rpc(MagicMock())
    rpc._post = AsyncMock(
        side_effect=[
            {"id": 1, "error": {"message": "rate limit"}},
            {"id": 1, "result": "0x1237"},
        ]
    )
    with patch(
        "scripts.census_4663.collect.asyncio.sleep", new_callable=AsyncMock
    ) as sleep:
        assert await rpc.call("eth_chainId", []) == "0x1237"
    sleep.assert_awaited_once_with(1)
    assert rpc._post.call_args_list[0] == rpc._post.call_args_list[1]


@pytest.mark.asyncio
async def test_reorg_after_empty_log_fetch_does_not_advance_cursor(tmp_path):
    rpc = FakeRpc()

    async def empty_logs_then_reorg(query):
        rpc.hashes[101] = "0x" + "aa" * 32
        return []

    rpc.logs = AsyncMock(side_effect=empty_logs_then_reorg)
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        with pytest.raises(RpcError, match="changed|mismatch"):
            await Collector(rpc, db, confirmations=2).run_once(100, 101)
    data = await load_data(tmp_path)
    assert data["meta"]["cursor"] == "99"
    assert not data["blocks"]


@pytest.mark.asyncio
async def test_receipt_must_contain_the_creation_log(tmp_path):
    rpc = FakeRpc()
    log = rpc.creation(transfers=[ZERO])
    receipt = rpc.receipts[log["transactionHash"]]
    receipt["logs"] = [item for item in receipt["logs"] if item is not log]
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        with pytest.raises(RpcError, match="[Cc]reation|[Rr]eceipt"):
            await Collector(rpc, db, confirmations=2).run_once(100, 101)
    data = await load_data(tmp_path)
    assert data["meta"]["cursor"] == "99"
    assert not data["pools"] and not data["evidence"]


@pytest.mark.asyncio
async def test_v2_creation_queries_new_pair_and_records_same_chunk_activity(tmp_path):
    rpc = FakeRpc()
    creation = log_fixture(
        "PairCreated(address,address,address,uint256)",
        ["address", "address"],
        [WETH, TOKEN],
        ["address", "uint256"],
        [PAIR, 1],
    )
    creation.update(
        address=V2_FACTORY,
        blockNumber="0x64",
        blockHash=rpc.header(100)["hash"],
        logIndex="0x0",
    )
    rpc.entries.append(creation)
    for index, (signature, indexed_types, indexed_values, types, values) in enumerate(
        [
            (
                "Mint(address,uint256,uint256)",
                ["address"],
                [OTHER],
                ["uint256", "uint256"],
                [10**18, 10**20],
            ),
            ("Sync(uint112,uint112)", [], [], ["uint112", "uint112"], [10**18, 10**20]),
            (
                "Swap(address,uint256,uint256,uint256,uint256,address)",
                ["address", "address"],
                [OTHER, OTHER],
                ["uint256"] * 4,
                [10**16, 0, 0, 10**18],
            ),
        ],
        1,
    ):
        log = log_fixture(signature, indexed_types, indexed_values, types, values)
        log.update(
            address=PAIR,
            blockNumber="0x64",
            blockHash=rpc.header(100)["hash"],
            logIndex=hex(index),
        )
        rpc.entries.append(log)
    tx_hash = creation["transactionHash"]
    rpc.transactions[tx_hash] = {
        "hash": tx_hash,
        "blockHash": creation["blockHash"],
        "from": OTHER,
        "to": PAIR,
    }
    rpc.receipts[tx_hash] = {
        "transactionHash": tx_hash,
        "blockHash": creation["blockHash"],
        "blockNumber": "0x64",
        "status": "0x1",
        "logs": rpc.entries.copy(),
    }
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        await Collector(rpc, db, confirmations=2).run_once(100, 101)
    data = await load_data(tmp_path)
    assert [(row["source"], row["pool_key"]) for row in data["pools"]] == [("v2", PAIR)]
    assert [row["name"] for row in data["events"]] == [
        "PairCreated",
        "Mint",
        "Sync",
        "Swap",
    ]
    assert any(query["address"] == [PAIR] for query in rpc.queries)


@pytest.mark.asyncio
async def test_v3_measurement_cannot_be_changed_after_cursor_exists(tmp_path):
    rpc = FakeRpc()
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        await Collector(rpc, db, confirmations=2).run_once(100, 101)
        with pytest.raises(ValueError, match="Cannot change v3 factory"):
            await Collector(rpc, db, confirmations=2, v3_factory=PAIR).run_once(
                to_block=103
            )
    assert not any(query["address"] == PAIR for query in rpc.queries)


@pytest.mark.asyncio
async def test_wrong_database_chain_is_rejected(tmp_path):
    rpc = FakeRpc()
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        await db.execute("INSERT INTO meta VALUES ('chain_id', '56')")
        await db.commit()
        with pytest.raises(ValueError, match="database chain mismatch"):
            await Collector(rpc, db).run_once(100, 101)
    assert not rpc.queries


@pytest.mark.asyncio
@pytest.mark.parametrize("timing", ["before_headers", "during_logs"])
async def test_cross_chunk_reorg_stops_then_replays_committed_orphan(tmp_path, timing):
    rpc = FakeRpc()
    rpc.creation(number=101)
    original_logs = rpc.logs
    changed = False
    replacement_pool = "0x" + "22" * 32

    def replace_chain():
        nonlocal changed
        changed = True
        rpc.entries.clear()
        rpc.hashes[101] = "0x" + "aa" * 32
        rpc.hashes[102] = "0x" + "bb" * 32
        rpc.hashes[103] = "0x" + "cc" * 32
        rpc.creation(number=101, token=OTHER, pool_id=replacement_pool, tx_id=2)

    async def reorg_when_next_chunk_starts(query):
        if (
            timing == "during_logs"
            and int(query["fromBlock"], 16) == 102
            and not changed
        ):
            replace_chain()
        return await original_logs(query)

    rpc.logs = AsyncMock(side_effect=reorg_when_next_chunk_starts)
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        collector = Collector(rpc, db, confirmations=2, chunk_size=2)
        original_chunk = collector._chunk

        async def reorg_before_next_chunk(start, end):
            if timing == "before_headers" and start == 102 and not changed:
                replace_chain()
            await original_chunk(start, end)

        collector._chunk = AsyncMock(side_effect=reorg_before_next_chunk)
        with pytest.raises(RpcError, match="changed|mismatch"):
            await collector.run_once(100, 103)
        cursor = await (
            await db.execute("SELECT value FROM meta WHERE key='cursor'")
        ).fetchone()
        assert cursor == ("101",)
        assert await collector.run_once(to_block=103) == 103
    data = await load_data(tmp_path)
    assert [pool["pool_key"] for pool in data["pools"]] == [replacement_pool]
    assert [event["pool_key"] for event in data["events"]] == [replacement_pool]


@pytest.mark.asyncio
async def test_untracked_v4_activity_does_not_fetch_unneeded_block_headers(tmp_path):
    rpc = FakeRpc()
    rpc.tip = 202
    log = log_fixture(
        "Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)",
        ["bytes32", "address"],
        [bytes.fromhex(POOL_ID[2:]), TOKEN],
        ["int128", "int128", "uint160", "uint128", "int24", "uint24"],
        [-1, 1, 2**96, 100, 0, 3000],
    )
    log.update(blockNumber=hex(150), blockHash=rpc.header(150)["hash"])
    rpc.entries.append(log)
    rpc.batch = AsyncMock(wraps=rpc.batch)
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        await Collector(rpc, db, confirmations=2).run_once(100, 200)
    requested_blocks = {
        int(params[0], 16)
        for batch_call in rpc.batch.call_args_list
        for method, params in batch_call.args[0]
        if method == "eth_getBlockByNumber"
    }
    assert requested_blocks == {100, 199, 200}
    data = await load_data(tmp_path)
    assert data["meta"]["cursor"] == "200"
    assert not data["events"] and not data["pools"]


@pytest.mark.asyncio
@pytest.mark.parametrize("has_log_timestamp", [True, False])
async def test_creation_log_timestamp_avoids_header_fetch_with_missing_field_fallback(
    tmp_path, has_log_timestamp
):
    rpc = FakeRpc()
    rpc.tip = 202
    creation = rpc.creation(number=150)
    if has_log_timestamp:
        creation["blockTimestamp"] = rpc.header(150)["timestamp"]
    rpc.batch = AsyncMock(wraps=rpc.batch)
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        await Collector(rpc, db, confirmations=2).run_once(100, 200)
    requested_blocks = {
        int(params[0], 16)
        for batch_call in rpc.batch.call_args_list
        for method, params in batch_call.args[0]
        if method == "eth_getBlockByNumber"
    }
    expected_blocks = {100, 199, 200}
    if not has_log_timestamp:
        expected_blocks.add(150)
    assert requested_blocks == expected_blocks
    data = await load_data(tmp_path)
    assert data["meta"]["cursor"] == "200"
    assert data["pools"][0]["timestamp"] == 1700000150
    assert data["events"][0]["timestamp"] == 1700000150


@pytest.mark.asyncio
@pytest.mark.parametrize("creation_block", [100, 199, 200])
async def test_log_timestamp_must_match_canonical_boundary_header(
    tmp_path, creation_block
):
    rpc = FakeRpc()
    rpc.tip = 202
    creation = rpc.creation(number=creation_block)
    creation["blockTimestamp"] = hex(
        int(rpc.header(creation_block)["timestamp"], 16) + 1
    )
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        with pytest.raises(RpcError, match="[Tt]imestamp|mismatch"):
            await Collector(rpc, db, confirmations=2).run_once(100, 200)
    data = await load_data(tmp_path)
    assert data["meta"]["cursor"] == "99"
    assert not data["pools"] and not data["events"] and not data["blocks"]
