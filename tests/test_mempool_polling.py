"""Mempool polling: how pending transactions are read, parsed and handed to the analysis."""

import asyncio
import logging
import threading
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from hexbytes import HexBytes
from web3.datastructures import AttributeDict

from services import mempool_service
from services.mempool_service import ANALYSIS_YIELD_EVERY, MempoolMonitor, PendingTx
from utils.web3_client import Web3Client

SENDER = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"
TOKEN = "0x" + "22" * 20
APPROVE_UNLIMITED = "0x095ea7b3" + "00" * 12 + "11" * 20 + "ff" * 32


def _pending_block(sealed=False):
    """A pending block as web3 returns it: AttributeDicts carrying HexBytes hashes and inputs.

    A genuine pending block has no hash and no miner yet. Some RPCs answer "pending" with the latest
    sealed block instead, which carries both.
    """
    return AttributeDict.recursive(
        {
            "hash": HexBytes(b"\xbb" * 32) if sealed else None,
            "miner": "0x" + "33" * 20 if sealed else None,
            "transactions": [
                {
                    "hash": HexBytes(b"\x01" * 32),
                    "from": SENDER,
                    "to": TOKEN,
                    "value": 0,
                    "gasPrice": 5,
                    "input": HexBytes(APPROVE_UNLIMITED),
                },
                # A plain transfer has an empty input.
                {
                    "hash": HexBytes(b"\x02" * 32),
                    "from": SENDER,
                    "to": TOKEN,
                    "value": 10**18,
                    "gasPrice": 6,
                    "input": HexBytes(b""),
                },
                # A contract creation has no recipient.
                {
                    "hash": HexBytes(b"\x03" * 32),
                    "from": SENDER,
                    "to": None,
                    "value": 0,
                    "gasPrice": 7,
                    "input": HexBytes("0x6080"),
                },
            ],
        }
    )


@pytest.mark.asyncio
async def test_only_chains_with_a_public_mempool_are_polled():
    client = Web3Client.__new__(Web3Client)
    client._adapters = {chain_id: MagicMock() for chain_id in (56, 1, 8453, 42161, 137, 10, 204, 4663)}
    monitor = MempoolMonitor(client)
    monitor._poll_pending = AsyncMock()

    await monitor.start()
    try:
        assert sorted(monitor.get_stats()["monitored_chains"]) == [1, 56, 137, 204]
        # Nothing has been read yet, so no chain counts as observed.
        assert monitor.get_stats()["unobservable_chains"] == [1, 56, 137, 204]
    finally:
        await monitor.stop()


def _fields(tx):
    return (tx.tx_hash, tx.from_addr, tx.to_addr, tx.value, tx.gas_price, tx.data, tx.chain_id)


@pytest.mark.asyncio
async def test_pending_block_fallback_parses_web3_attribute_dicts():
    w3 = MagicMock()
    w3.eth.get_block.return_value = _pending_block()

    txs = await MempoolMonitor(MagicMock())._get_pending_block(w3, 56)

    w3.eth.get_block.assert_called_once_with("pending", True)
    assert [_fields(tx) for tx in txs] == [
        ("0x" + "01" * 32, SENDER.lower(), TOKEN, 0, 5, APPROVE_UNLIMITED, 56),
        ("0x" + "02" * 32, SENDER.lower(), TOKEN, 10**18, 6, "0x", 56),
        ("0x" + "03" * 32, SENDER.lower(), "", 0, 7, "0x6080", 56),
    ]


@pytest.mark.asyncio
async def test_pending_block_fallback_feeds_the_analysis():
    client = MagicMock()
    w3 = client.get_web3.return_value
    w3.provider.make_request.return_value = {"result": {"pending": {}}}
    w3.eth.get_block.return_value = _pending_block()
    monitor = MempoolMonitor(client)

    await monitor._poll_pending(56)

    assert monitor.get_stats()["pending_count"] == {56: 3}
    assert monitor.get_stats()["unobservable_chains"] == []
    alerts = monitor.get_alerts()
    assert [(a["alert_type"], a["severity"], a["victim_tx"]) for a in alerts] == [
        ("suspicious_approval", "HIGH", "0x" + "01" * 32),
    ]


TXPOOL_WITH_ONE_TX = {"result": {"pending": {SENDER: {"7": {
    "hash": "0x" + "04" * 32, "from": SENDER, "to": TOKEN, "value": "0x0",
    "gasPrice": "0x5", "input": "0x",
}}}}}


@pytest.mark.asyncio
@pytest.mark.parametrize("txpool, pending_block", [
    ({"result": {"pending": {}}}, _pending_block(sealed=True)),
    (RuntimeError("txpool_content is not available"), _pending_block(sealed=True)),
    ({"result": {"pending": {}}}, TimeoutError("RPC timeout")),
    (RuntimeError("txpool_content is not available"), TimeoutError("RPC timeout")),
], ids=["empty-txpool-sealed-block", "txpool-error-sealed-block", "empty-txpool-block-error", "both-fail"])
async def test_a_chain_whose_mempool_cannot_be_read_is_unobservable_until_it_can(txpool, pending_block):
    client = MagicMock()
    w3 = client.get_web3.return_value
    w3.provider.make_request.side_effect = [txpool, TXPOOL_WITH_ONE_TX]
    w3.eth.get_block.side_effect = [pending_block]
    monitor = MempoolMonitor(client)

    await monitor._poll_pending(56)
    assert monitor.get_stats()["unobservable_chains"] == [56]
    assert monitor.get_stats()["pending_count"] == {}

    await monitor._poll_pending(56)
    assert monitor.get_stats()["unobservable_chains"] == []
    assert monitor.get_stats()["pending_count"] == {56: 1}


@pytest.mark.asyncio
async def test_a_genuine_empty_pending_block_is_an_observation():
    client = MagicMock()
    w3 = client.get_web3.return_value
    w3.provider.make_request.return_value = {"result": {"pending": {}}}
    w3.eth.get_block.return_value = AttributeDict({"hash": None, "miner": None, "transactions": []})
    monitor = MempoolMonitor(client)
    monitor._unobservable_chains = {1}

    await monitor._poll_pending(1)

    assert monitor.get_stats()["unobservable_chains"] == []


@pytest.mark.asyncio
async def test_a_failed_poll_leaves_the_chain_unobservable():
    client = MagicMock()
    monitor = MempoolMonitor(client)
    monitor._get_txpool_content = AsyncMock(side_effect=RuntimeError("executor is shut down"))

    await monitor._poll_pending(56)

    assert monitor.get_stats()["unobservable_chains"] == [56]


@pytest.mark.asyncio
async def test_a_sealed_block_answered_for_pending_is_skipped_with_one_warning_per_chain(caplog):
    w3 = MagicMock()
    w3.eth.get_block.return_value = _pending_block(sealed=True)
    monitor = MempoolMonitor(MagicMock())

    with caplog.at_level(logging.WARNING, logger="services.mempool_service"):
        assert await monitor._get_pending_block(w3, 56) is None
        assert await monitor._get_pending_block(w3, 56) is None
        assert await monitor._get_pending_block(w3, 204) is None

    warned = [r.args[0] for r in caplog.records if r.levelno == logging.WARNING]
    assert warned == [56, 204]
    # Once a chain is known to answer with a sealed block, its full block is not fetched again.
    assert w3.eth.get_block.call_count == 2


@pytest.mark.asyncio
async def test_txpool_content_is_parsed_and_built_off_the_event_loop(monkeypatch):
    built_on = []

    def recording_pending_tx(**fields):
        built_on.append(threading.get_ident())
        return PendingTx(**fields)

    monkeypatch.setattr(mempool_service, "PendingTx", recording_pending_tx)
    w3 = MagicMock()
    w3.provider.make_request.return_value = {"result": {"pending": {SENDER: {"7": {
        "hash": "0x" + "04" * 32, "from": SENDER, "to": TOKEN, "value": "0x10",
        "gasPrice": "0x5", "input": APPROVE_UNLIMITED,
    }}}}}

    txs = await MempoolMonitor(MagicMock())._get_txpool_content(w3, 1)

    w3.provider.make_request.assert_called_once_with("txpool_content", [])
    assert [_fields(tx) for tx in txs] == [
        ("0x" + "04" * 32, SENDER.lower(), TOKEN, 16, 5, APPROVE_UNLIMITED, 1),
    ]
    assert built_on and threading.get_ident() not in built_on


@pytest.mark.asyncio
async def test_stop_logs_only_for_a_monitor_that_was_started(caplog):
    """The Telegram bot's container shuts down a monitor it never started."""
    client = Web3Client.__new__(Web3Client)
    client._adapters = {56: MagicMock()}
    never_started = MempoolMonitor(client)
    started = MempoolMonitor(client)
    started._poll_pending = AsyncMock()
    await started.start([56])

    with caplog.at_level(logging.INFO, logger="services.mempool_service"):
        await never_started.stop()
        assert "MempoolMonitor stopped" not in caplog.messages
        await started.stop()
        assert caplog.messages.count("MempoolMonitor stopped") == 1
    assert started._task is None


@pytest.mark.asyncio
async def test_each_chain_poll_logs_its_duration(caplog):
    monitor = MempoolMonitor(MagicMock())
    monitor._running = True
    monitor._monitored_chains = {56, 1}
    cycle_polled = asyncio.Event()

    async def poll(chain_id):
        if monitor._poll_pending.await_count == len(monitor._monitored_chains):
            cycle_polled.set()

    monitor._poll_pending = AsyncMock(side_effect=poll)
    with caplog.at_level(logging.DEBUG, logger="services.mempool_service"):
        loop_task = asyncio.create_task(monitor._monitor_loop())
        await asyncio.wait_for(cycle_polled.wait(), 5)
        # The loop logged the last chain and is now in its real 2 s sleep, which ends on cancel.
        loop_task.cancel()
        await loop_task

    polled = [r for r in caplog.records if r.msg == "Polled chain %s in %.2f s"]
    assert sorted(r.args[0] for r in polled) == [1, 56]
    assert all(r.levelno == logging.DEBUG and r.args[1] >= 0 for r in polled)


def _tx(tx_hash, chain_id=1, seen_at=None):
    """A plain transfer as the txpool reader builds it; seen_at defaults to now."""
    fields = dict(tx_hash=tx_hash, from_addr=SENDER.lower(), to_addr=TOKEN, value=0, gas_price=5, data="0x", chain_id=chain_id)
    return PendingTx(**fields) if seen_at is None else PendingTx(**fields, seen_at=seen_at)


HASH_1, HASH_2, HASH_3 = ("0x" + "0a" * 32, "0x" + "0b" * 32, "0x" + "0c" * 32)


@pytest.mark.asyncio
async def test_a_transaction_that_stays_in_the_pool_is_analysed_once_and_counted_once(monkeypatch):
    """Two loop cycles: HASH_1 has been in the pool for over a minute and stays, HASH_2 leaves, HASH_3 joins."""
    monitor = MempoolMonitor(MagicMock())
    monitor._running = True
    monitor._monitored_chains = {1}
    monitor._analyze_pending_tx = AsyncMock()
    stuck = _tx(HASH_1, seen_at=time.time() - 61)
    monitor._get_txpool_content = AsyncMock(side_effect=[
        [stuck, _tx(HASH_2)],
        [stuck, _tx(HASH_3)],
        asyncio.CancelledError(),
    ])
    monkeypatch.setattr("services.mempool_service.asyncio.sleep", AsyncMock())

    await monitor._monitor_loop()

    assert [call.args[0].tx_hash for call in monitor._analyze_pending_tx.await_args_list] == [HASH_1, HASH_2, HASH_3]
    assert monitor.get_stats()["total_pending_seen"] == 3
    assert monitor.get_stats()["pending_count"] == {1: 2}
    assert set(monitor._pending[1]) == {HASH_1, HASH_3}


@pytest.mark.asyncio
async def test_a_transaction_that_left_the_pool_is_dropped():
    monitor = MempoolMonitor(MagicMock())
    monitor._get_txpool_content = AsyncMock(side_effect=[[_tx(HASH_1), _tx(HASH_2)], [_tx(HASH_2)]])

    await monitor._poll_pending(1)
    assert monitor.get_stats()["pending_count"] == {1: 2}
    await monitor._poll_pending(1)

    assert monitor.get_stats()["pending_count"] == {1: 1}
    assert list(monitor._pending[1]) == [HASH_2]
    assert monitor.get_stats()["total_pending_seen"] == 2


@pytest.mark.asyncio
async def test_a_failed_poll_keeps_the_pending_set():
    """A poll that raises, or reads neither a txpool nor a pending block, is not an empty pool."""
    monitor = MempoolMonitor(MagicMock())
    monitor._get_txpool_content = AsyncMock(side_effect=[[_tx(HASH_1)], RuntimeError("RPC timeout"), []])
    monitor._get_pending_block = AsyncMock(return_value=None)

    await monitor._poll_pending(1)
    assert monitor.get_stats()["unobservable_chains"] == []
    for _ in range(2):
        await monitor._poll_pending(1)
        assert monitor.get_stats()["unobservable_chains"] == [1]
        assert monitor.get_stats()["pending_count"] == {1: 1}
    assert monitor.get_stats()["total_pending_seen"] == 1


@pytest.mark.asyncio
async def test_a_large_snapshot_lets_other_tasks_run_while_it_is_added():
    monitor = MempoolMonitor(MagicMock())
    monitor._get_txpool_content = AsyncMock(return_value=[_tx("0x" + f"{i:064x}") for i in range(20_000)])
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0)

    task = asyncio.create_task(ticker())
    try:
        await monitor._poll_pending(1)
    finally:
        task.cancel()

    assert monitor.get_stats()["pending_count"] == {1: 20_000}
    assert ticks >= 20_000 // ANALYSIS_YIELD_EVERY
