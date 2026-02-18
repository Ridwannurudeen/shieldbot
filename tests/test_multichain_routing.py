"""Tests for multichain adapter routing in Web3Client."""

from unittest.mock import MagicMock, patch
from utils.web3_client import Web3Client
from adapters.bsc import BscAdapter
from adapters.eth import EthAdapter
from adapters.base_chain import BaseChainAdapter


def test_bsc_adapter_registered_by_default():
    with patch.dict('os.environ', {'BSC_RPC_URL': 'https://bsc-dataseed1.binance.org/'}):
        client = Web3Client()
        adapter = client._get_adapter(56)
        assert adapter is not None
        assert adapter.chain_id == 56


def test_register_eth_adapter():
    with patch.dict('os.environ', {'BSC_RPC_URL': 'https://bsc-dataseed1.binance.org/'}):
        client = Web3Client()
        eth = EthAdapter(rpc_url="https://eth.llamarpc.com")
        client.register_adapter(eth)
        adapter = client._get_adapter(1)
        assert adapter is not None
        assert adapter.chain_id == 1
        assert adapter.chain_name == "Ethereum"


def test_register_base_adapter():
    with patch.dict('os.environ', {'BSC_RPC_URL': 'https://bsc-dataseed1.binance.org/'}):
        client = Web3Client()
        base = BaseChainAdapter(rpc_url="https://mainnet.base.org")
        client.register_adapter(base)
        adapter = client._get_adapter(8453)
        assert adapter is not None
        assert adapter.chain_name == "Base"


def test_unsupported_chain_returns_none():
    with patch.dict('os.environ', {'BSC_RPC_URL': 'https://bsc-dataseed1.binance.org/'}):
        client = Web3Client()
        assert client._get_adapter(999) is None


def test_get_supported_chain_ids():
    with patch.dict('os.environ', {'BSC_RPC_URL': 'https://bsc-dataseed1.binance.org/'}):
        client = Web3Client()
        eth = EthAdapter(rpc_url="https://eth.llamarpc.com")
        base = BaseChainAdapter(rpc_url="https://mainnet.base.org")
        client.register_adapter(eth)
        client.register_adapter(base)
        chains = client.get_supported_chain_ids()
        assert 56 in chains
        assert 1 in chains
        assert 8453 in chains


def test_calldata_decoder_whitelisted_with_adapter():
    """Calldata decoder uses adapter's router list when provided."""
    from utils.calldata_decoder import CalldataDecoder
    decoder = CalldataDecoder()

    # BSC PancakeSwap router
    bsc_router = "0x10ED43C718714eb63d5aA57B78B54704E256024E"
    assert decoder.is_whitelisted_target(bsc_router, chain_id=56) is not None

    # Uniswap on ETH — without adapter, chain_id=1 returns None
    uniswap_v2 = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
    assert decoder.is_whitelisted_target(uniswap_v2, chain_id=1) is None

    # With adapter, should find it
    eth_adapter = EthAdapter(rpc_url="https://eth.llamarpc.com")
    result = decoder.is_whitelisted_target(uniswap_v2, chain_id=1, adapter=eth_adapter)
    assert result is not None
    assert "Uniswap" in result
