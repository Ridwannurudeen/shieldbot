"""Known protocol contracts that are not swap routers (position managers) name a spender but never take a
transaction down the router path, and each chain trusts only the router addresses listed for it."""

import pytest

from adapters.arbitrum import ArbitrumAdapter
from adapters.eth import EthAdapter
from adapters.optimism import OptimismAdapter
from scripts.check_allowlist_code import ADAPTERS
from services.counterparty_service import CounterpartyService
from utils.calldata_decoder import CalldataDecoder
from utils.web3_client import Web3Client

POSITION_MANAGER = "0xc36442b4a4522e871399cd717abdd847ab11fe88"
UNIVERSAL_ROUTER_V2_1_2 = "0x23617e59a5925b2a4bf75d73ff6711cd0b29de85"
# Uniswap lists this Universal Router build for Ethereum, not for Arbitrum or Optimism.
MAINNET_UNIVERSAL_ROUTER_V1_2 = "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad"


def ethereum():
    adapter = EthAdapter()
    client = Web3Client()
    client.register_adapter(adapter)
    return adapter, CounterpartyService(client, None)


def test_a_known_spender_is_named_but_never_takes_the_router_path():
    adapter, counterparty = ethereum()
    assert (
        counterparty.allowlisted_name(POSITION_MANAGER, 1)
        == "Uniswap V3 NonfungiblePositionManager"
    )
    assert (
        CalldataDecoder().is_whitelisted_target(POSITION_MANAGER, chain_id=1, adapter=adapter)
        is None
    )


def test_uniswaps_current_router_is_a_router_and_is_named():
    adapter, counterparty = ethereum()
    name = "Uniswap Universal Router V2.1.2"
    assert (
        CalldataDecoder().is_whitelisted_target(
            UNIVERSAL_ROUTER_V2_1_2, chain_id=1, adapter=adapter
        )
        == name
    )
    assert counterparty.allowlisted_name(UNIVERSAL_ROUTER_V2_1_2, 1) == name


@pytest.mark.parametrize("adapter_class", [ArbitrumAdapter, OptimismAdapter])
def test_the_mainnet_router_address_is_not_trusted_where_uniswap_does_not_list_it(adapter_class):
    assert MAINNET_UNIVERSAL_ROUTER_V1_2 not in adapter_class().get_whitelisted_routers()


@pytest.mark.parametrize("adapter_class", ADAPTERS)
def test_routers_and_known_spenders_are_lowercase_and_never_overlap(adapter_class):
    adapter = adapter_class()
    routers, spenders = adapter.get_whitelisted_routers(), adapter.get_known_spenders()
    assert all(address == address.lower() for address in [*routers, *spenders])
    assert not set(routers) & set(spenders)
