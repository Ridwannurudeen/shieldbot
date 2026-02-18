"""Tests for Ethereum adapter."""

from adapters.eth import EthAdapter, WHITELISTED_ROUTERS, UNISWAP_V2_FACTORY


def test_eth_adapter_chain_id():
    adapter = EthAdapter(rpc_url="https://eth.llamarpc.com")
    assert adapter.chain_id == 1


def test_eth_adapter_chain_name():
    adapter = EthAdapter(rpc_url="https://eth.llamarpc.com")
    assert adapter.chain_name == "Ethereum"


def test_eth_whitelisted_routers():
    adapter = EthAdapter(rpc_url="https://eth.llamarpc.com")
    routers = adapter.get_whitelisted_routers()
    # Uniswap V2 Router should be present
    uniswap_v2 = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".lower()
    assert uniswap_v2 in routers
    assert "Uniswap V2 Router" in routers[uniswap_v2]


def test_eth_adapter_has_factory():
    assert UNISWAP_V2_FACTORY == '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f'


def test_eth_adapter_known_lockers():
    adapter = EthAdapter(rpc_url="https://eth.llamarpc.com")
    assert len(adapter._known_lockers) >= 3
