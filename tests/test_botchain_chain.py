from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests

from adapters.botchain import (
    KNOWN_LOCKERS,
    KNOWN_SPENDERS,
    ROUTER_V2_FACTORIES,
    V2_FACTORY,
    WBOT,
    WHITELISTED_ROUTERS,
    BotChainAdapter,
)

TOKEN = "0x" + "ab" * 20


def test_botchain_adapter_configuration():
    adapter = BotChainAdapter()
    assert adapter.chain_id == 677
    assert adapter.chain_name == "BOT Chain"
    assert adapter.w3.provider.endpoint_uri == "https://rpc.botchain.ai"
    assert adapter._honeypot_chain_id is None
    assert adapter._quote_tokens == [("WBOT", WBOT)]
    assert adapter._factory_address == V2_FACTORY
    assert adapter.get_known_lockers() == KNOWN_LOCKERS
    assert adapter.get_whitelisted_routers() == WHITELISTED_ROUTERS
    assert adapter.get_known_spenders() == KNOWN_SPENDERS
    assert adapter._router_v2_factories == ROUTER_V2_FACTORIES
    assert not set(WHITELISTED_ROUTERS) & set(KNOWN_SPENDERS)


def test_botchain_rpc_url_can_be_configured(monkeypatch):
    monkeypatch.setenv("BOTCHAIN_RPC_URL", "https://rpc.invalid")
    assert BotChainAdapter().w3.provider.endpoint_uri == "https://rpc.invalid"
    assert BotChainAdapter("https://override.invalid").w3.provider.endpoint_uri == "https://override.invalid"


@pytest.mark.asyncio
async def test_botchain_token_info_retries_a_transient_429():
    adapter = BotChainAdapter("https://rpc.invalid")
    adapter.w3 = MagicMock()
    functions = adapter.w3.eth.contract.return_value.functions
    name_call = functions.name.return_value.call
    name_call.side_effect = [
        requests.exceptions.HTTPError(response=MagicMock(status_code=429)),
        "Token",
    ]
    functions.symbol.return_value.call.return_value = "TKN"
    functions.decimals.return_value.call.return_value = 18
    functions.totalSupply.return_value.call.return_value = 100 * 10**18

    with patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock) as sleep:
        info = await adapter.get_token_info(TOKEN)

    assert info == {"name": "Token", "symbol": "TKN", "decimals": 18, "total_supply": 100.0}
    assert name_call.call_count == 2
    assert [call.args[0] for call in sleep.await_args_list] == [1.0]


@pytest.mark.asyncio
async def test_botchain_honeypot_fields_are_unknown_without_a_provider():
    adapter = BotChainAdapter("https://rpc.invalid")
    with patch("adapters.evm_base.aiohttp.ClientSession") as session:
        honeypot = await adapter.check_honeypot(TOKEN)
        taxes = await adapter.get_tax_info(TOKEN)
    session.assert_not_called()
    assert honeypot["status"] == taxes["status"] == "unknown"
    assert honeypot["reason"] == taxes["reason"] == (
        "Sellability unknown: no sell simulation on BOT Chain yet"
    )
    assert adapter.capabilities()["sell_simulation"] == "none"
