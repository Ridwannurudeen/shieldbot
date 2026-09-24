"""Mempool polling: how pending transactions are read, parsed and handed to the analysis."""

import logging
import threading
from unittest.mock import AsyncMock, MagicMock

import pytest
from hexbytes import HexBytes
from web3.datastructures import AttributeDict

from services import mempool_service
from services.mempool_service import MempoolMonitor, PendingTx
from utils.web3_client import Web3Client

SENDER = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"
TOKEN = "0x" + "22" * 20
APPROVE_UNLIMITED = "0x095ea7b3" + "00" * 12 + "11" * 20 + "ff" * 32


def _pending_block():
    """A pending block as web3 returns it: AttributeDicts carrying HexBytes hashes and inputs."""
    return AttributeDict.recursive(
        {
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
    alerts = monitor.get_alerts()
    assert [(a["alert_type"], a["severity"], a["victim_tx"]) for a in alerts] == [
        ("suspicious_approval", "HIGH", "0x" + "01" * 32),
    ]


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
async def test_each_chain_poll_logs_its_duration(monkeypatch, caplog):
    monitor = MempoolMonitor(MagicMock())
    monitor._running = True
    monitor._monitored_chains = {56, 1}
    monitor._poll_pending = AsyncMock()

    async def stop_after_one_cycle(seconds):
        monitor._running = False

    monkeypatch.setattr("services.mempool_service.asyncio.sleep", stop_after_one_cycle)
    with caplog.at_level(logging.DEBUG, logger="services.mempool_service"):
        await monitor._monitor_loop()

    polled = [r for r in caplog.records if r.msg == "Polled chain %s in %.2f s"]
    assert sorted(r.args[0] for r in polled) == [1, 56]
    assert all(r.levelno == logging.DEBUG and r.args[1] >= 0 for r in polled)
