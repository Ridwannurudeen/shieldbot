"""Tests for multichain adapter routing in Web3Client."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from utils.web3_client import UnsupportedChainError, Web3Client
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


def test_unsupported_chain_raises():
    with patch.dict('os.environ', {'BSC_RPC_URL': 'https://bsc-dataseed1.binance.org/'}):
        client = Web3Client()
        with pytest.raises(UnsupportedChainError, match="Unsupported chain ID 999"):
            client._get_adapter(999)


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


ROUTING_METHODS = [
    "is_contract", "is_token_contract", "get_bytecode", "is_verified_contract",
    "get_contract_creation_info", "get_token_info", "can_transfer_token",
    "get_ownership_info", "get_liquidity_info", "check_honeypot", "get_tax_info",
]


def test_get_web3_rejects_unknown_chain_before_provider():
    client = Web3Client()
    client._bsc_adapter.w3 = MagicMock()
    client.bsc_web3 = client._bsc_adapter.w3
    with pytest.raises(UnsupportedChainError, match="Unsupported chain ID 999999"):
        client.get_web3(999999)
    client._bsc_adapter.w3.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ROUTING_METHODS)
async def test_every_routing_wrapper_rejects_unknown_chain(method):
    client = Web3Client()
    client._bsc_adapter = MagicMock()
    client._adapters[56] = client._bsc_adapter
    client.bsc_web3 = client._bsc_adapter.w3
    with pytest.raises(UnsupportedChainError, match="Unsupported chain ID 999999"):
        await getattr(client, method)("0x000000000000000000000000000000000000dEaD", 999999)
    assert not client._bsc_adapter.mock_calls


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [56, 204])
@pytest.mark.parametrize("method", [m for m in ROUTING_METHODS if m not in {"is_token_contract", "can_transfer_token"}])
async def test_registered_chain_preserves_adapter_result(chain_id, method):
    client = Web3Client()
    adapter = MagicMock(chain_id=chain_id, chain_name="test")
    result = {"provider_value": None}
    setattr(adapter, method, AsyncMock(return_value=result))
    client.register_adapter(adapter)
    assert client.get_web3(chain_id) is adapter.w3
    assert await getattr(client, method)("address", chain_id) is result
    getattr(adapter, method).assert_awaited_once_with("address")


@pytest.mark.asyncio
async def test_mempool_start_excludes_robinhood():
    from services.mempool_service import MempoolMonitor
    client = Web3Client()
    client.register_adapter(MagicMock(chain_id=4663, chain_name="Robinhood Chain"))
    monitor = MempoolMonitor(client)
    monitor._poll_pending = AsyncMock()
    await monitor.start([56, 4663])
    try:
        assert monitor._monitored_chains == {56}
    finally:
        await monitor.stop()
    monitor._poll_pending.assert_not_awaited()


@pytest.mark.asyncio
async def test_mempool_empty_chain_list_does_not_fall_back():
    from services.mempool_service import MempoolMonitor
    monitor = MempoolMonitor(Web3Client())
    await monitor.start([])
    try:
        assert monitor._monitored_chains == set()
        assert monitor._task is None
    finally:
        await monitor.stop()


@pytest.mark.asyncio
async def test_mempool_unknown_chain_rejected_before_start():
    from services.mempool_service import MempoolMonitor
    monitor = MempoolMonitor(Web3Client())
    try:
        with pytest.raises(UnsupportedChainError, match="Unsupported chain ID 999999"):
            await monitor.start([999999])
        assert not monitor._running
        assert monitor._task is None
    finally:
        await monitor.stop()


@pytest.mark.parametrize("chain_id", [True, 56.0, "56", None, [], {}])
def test_registry_rejects_non_integer_chain_ids(chain_id):
    client = Web3Client()
    with pytest.raises(UnsupportedChainError, match="Supported chain IDs: 56"):
        client.validate_chain_id(chain_id)


@pytest.mark.parametrize("chain_id,error", [
    (4663, "pending-transaction monitoring is not available on this chain"),
    (999999, "Unsupported chain ID 999999"),
])
def test_mempool_alerts_reject_unavailable_chain(chain_id, error):
    from services.mempool_service import MempoolMonitor
    client = Web3Client()
    client.register_adapter(MagicMock(chain_id=4663, chain_name="Robinhood Chain"))
    monitor = MempoolMonitor(client)
    with pytest.raises(ValueError, match=error):
        monitor.get_alerts(chain_id=chain_id)


@pytest.mark.asyncio
async def test_mempool_loop_preserves_routing_error(monkeypatch):
    from services.mempool_service import MempoolMonitor

    client = Web3Client.__new__(Web3Client)
    client._adapters = {}
    monitor = MempoolMonitor(client)
    monitor._running = True
    monitor._monitored_chains = {56}
    sleep = AsyncMock(side_effect=RuntimeError("unexpected retry"))
    monkeypatch.setattr("services.mempool_service.asyncio.sleep", sleep)
    with pytest.raises(UnsupportedChainError):
        await monitor._monitor_loop()
    sleep.assert_not_awaited()
