"""honeypot.is answers HTTP 400 "Invalid chain" for Arbitrum, Polygon, Optimism and opBNB.

Those chains must make no honeypot.is request, and their sellability must come from GoPlus and
say so: ShieldBot simulates no sell there.
"""

from unittest.mock import AsyncMock, patch

import pytest

from adapters.arbitrum import ArbitrumAdapter
from adapters.base_chain import BaseChainAdapter
from adapters.bsc import BscAdapter
from adapters.eth import EthAdapter
from adapters.opbnb import OpBNBAdapter
from adapters.optimism import OptimismAdapter
from adapters.polygon import PolygonAdapter
from services.honeypot_service import HoneypotService
from utils.scam_db import ScamDatabase
from utils.web3_client import Web3Client

ADDRESS = "0x" + "ab" * 20
GOPLUS_ONLY = [ArbitrumAdapter, PolygonAdapter, OptimismAdapter, OpBNBAdapter]
TRADE_FIELDS = ("is_honeypot", "buy_tax", "sell_tax", "can_buy", "can_sell")
CLEAN_GOPLUS = {
    "is_honeypot": "0",
    "buy_tax": "0.01",
    "sell_tax": "0.02",
    "cannot_buy": "0",
    "cannot_sell_all": "0",
    "transfer_pausable": "0",
}


@pytest.mark.parametrize("adapter_class", [BscAdapter, EthAdapter, BaseChainAdapter])
def test_simulated_chains_keep_honeypot_is(adapter_class):
    adapter = adapter_class(rpc_url="https://rpc.invalid")
    assert adapter._honeypot_chain_id == adapter.chain_id


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_class", GOPLUS_ONLY)
@pytest.mark.parametrize("method", ["check_honeypot", "get_tax_info"])
async def test_goplus_only_chains_make_no_honeypot_is_request(adapter_class, method):
    adapter = adapter_class(rpc_url="https://rpc.invalid")
    with patch("adapters.evm_base.aiohttp.ClientSession") as session:
        result = await getattr(adapter, method)(ADDRESS)
    session.assert_not_called()
    assert adapter._honeypot_chain_id is None
    assert result["status"] == "unknown"
    assert "GoPlus-reported, not simulated by ShieldBot" in result["reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_class", GOPLUS_ONLY)
async def test_goplus_only_chains_take_sellability_from_goplus(adapter_class):
    adapter = adapter_class(rpc_url="https://rpc.invalid")
    client = Web3Client()
    client.register_adapter(adapter)
    goplus = AsyncMock(return_value={"status": "ok", "reason": None, "data": CLEAN_GOPLUS})
    with (
        patch("adapters.evm_base.aiohttp.ClientSession") as session,
        patch.object(ScamDatabase, "fetch_token_security", new=goplus),
    ):
        data = await HoneypotService(client).fetch_honeypot_data(ADDRESS, chain_id=adapter.chain_id)
    session.assert_not_called()
    goplus.assert_awaited_once_with(ADDRESS, adapter.chain_id)
    assert data["status"] == "ok"
    assert data["is_honeypot"] is False and data["can_sell"] is True
    assert {field: data["field_providers"][field] for field in TRADE_FIELDS} == {
        field: "goplus" for field in TRADE_FIELDS
    }
    assert "GoPlus-reported, not simulated by ShieldBot" in data["reason"]
