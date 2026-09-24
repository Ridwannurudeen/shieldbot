"""check_honeypot and get_tax_info read one honeypot.is reply per token instead of fetching it twice."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from adapters.bsc import BscAdapter
from services.honeypot_service import HoneypotService
from utils.scam_db import ScamDatabase
from utils.web3_client import Web3Client

TOKEN = "0x" + "ab" * 20
OTHER = "0x" + "cd" * 20
SELLABLE = {
    "simulationSuccess": True,
    "honeypotResult": {"isHoneypot": False},
    "simulationResult": {"buyTax": 1, "sellTax": 2.5},
}


def _honeypot_is(*replies):
    """Patch aiohttp so successive honeypot.is requests get `replies` (a (status, body) or an exception)."""
    session = MagicMock()
    contexts = []
    for reply in replies:
        context = MagicMock()
        if isinstance(reply, Exception):
            context.__aenter__ = AsyncMock(side_effect=reply)
        else:
            status, body = reply
            response = MagicMock(status=status)
            response.json = AsyncMock(return_value=body)
            context.__aenter__ = AsyncMock(return_value=response)
        contexts.append(context)
    session.get.side_effect = contexts
    client = patch("adapters.evm_base.aiohttp.ClientSession")
    client.start().return_value.__aenter__ = AsyncMock(return_value=session)
    return client, session


@pytest.mark.asyncio
async def test_one_request_serves_both_checks_with_unchanged_results():
    client, session = _honeypot_is((200, SELLABLE))
    try:
        adapter = BscAdapter(rpc_url="https://rpc.invalid")
        honeypot = await adapter.check_honeypot(TOKEN)
        taxes = await adapter.get_tax_info(TOKEN.upper().replace("0X", "0x"))
    finally:
        client.stop()
    assert session.get.call_count == 1
    assert session.get.call_args.args == (
        f"https://api.honeypot.is/v2/IsHoneypot?address={TOKEN}&chainID=56",
    )
    assert honeypot == {
        "is_honeypot": False,
        "status": "ok",
        "reason": "honeypot.is result",
        "field_providers": {"is_honeypot": "honeypot.is"},
        "simulation_success": True,
    }
    assert taxes == {
        "buy_tax": 1.0,
        "sell_tax": 2.5,
        "status": "ok",
        "reason": "honeypot.is simulation taxes",
        "field_providers": {"buy_tax": "honeypot.is", "sell_tax": "honeypot.is"},
    }


@pytest.mark.asyncio
async def test_http_errors_keep_each_methods_reason():
    client, session = _honeypot_is((404, None))
    try:
        adapter = BscAdapter(rpc_url="https://rpc.invalid")
        honeypot = await adapter.check_honeypot(TOKEN)
        taxes = await adapter.get_tax_info(TOKEN)
    finally:
        client.stop()
    assert session.get.call_count == 1
    assert honeypot["reason"] == "Token not found on honeypot.is"
    assert taxes["reason"] == "honeypot.is HTTP 404"
    assert honeypot["status"] == taxes["status"] == "unknown"


@pytest.mark.asyncio
async def test_a_failed_request_is_not_reused():
    client, session = _honeypot_is(aiohttp.ClientConnectionError(), (200, SELLABLE))
    try:
        adapter = BscAdapter(rpc_url="https://rpc.invalid")
        honeypot = await adapter.check_honeypot(TOKEN)
        taxes = await adapter.get_tax_info(TOKEN)
    finally:
        client.stop()
    assert session.get.call_count == 2
    assert honeypot["reason"] == "Error checking honeypot.is: ClientConnectionError"
    assert taxes["status"] == "ok"


@pytest.mark.asyncio
async def test_each_token_gets_its_own_reply():
    client, session = _honeypot_is((200, SELLABLE), (404, None))
    try:
        adapter = BscAdapter(rpc_url="https://rpc.invalid")
        assert (await adapter.check_honeypot(TOKEN))["status"] == "ok"
        assert (await adapter.check_honeypot(OTHER))["status"] == "unknown"
    finally:
        client.stop()
    assert session.get.call_count == 2


@pytest.mark.asyncio
async def test_a_scan_makes_one_honeypot_is_request():
    client, session = _honeypot_is((200, SELLABLE))
    web3_client = Web3Client()
    web3_client.register_adapter(BscAdapter(rpc_url="https://rpc.invalid"))
    goplus = AsyncMock()
    try:
        with patch.object(ScamDatabase, "fetch_token_security", new=goplus):
            data = await HoneypotService(web3_client).fetch_honeypot_data(TOKEN, chain_id=56)
    finally:
        client.stop()
    assert session.get.call_count == 1
    goplus.assert_not_awaited()
    assert data["status"] == "ok" and data["can_sell"] is True
