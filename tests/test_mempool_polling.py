"""Mempool polling: how pending transactions are read, parsed and handed to the analysis."""

from unittest.mock import MagicMock

import pytest
from hexbytes import HexBytes
from web3.datastructures import AttributeDict

from services.mempool_service import MempoolMonitor

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
