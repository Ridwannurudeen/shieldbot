"""Tests for RPC Proxy."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from rpc.proxy import RPCProxy


@pytest.fixture
def mock_container():
    """Create a mock container for RPC proxy testing."""
    container = MagicMock()

    # Mock web3_client
    adapter = MagicMock()
    adapter.w3.provider.endpoint_uri = "https://bsc-dataseed1.binance.org/"
    container.web3_client._get_adapter.return_value = adapter
    container.web3_client.get_supported_chain_ids.return_value = [56, 1, 8453]

    # Mock registry
    container.registry.run_all = AsyncMock(return_value=[])

    # Mock risk engine
    container.risk_engine.compute_from_results.return_value = {
        'rug_probability': 10,
        'risk_level': 'LOW',
        'risk_archetype': 'legitimate',
        'critical_flags': [],
        'confidence_level': 50,
        'category_scores': {},
    }

    return container


@pytest.fixture
def proxy(mock_container):
    return RPCProxy(mock_container)


@pytest.mark.asyncio
async def test_transparent_proxy_for_eth_chainId(proxy):
    """Non-intercepted methods should be forwarded transparently."""
    proxy._forward = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0x38"})

    result = await proxy.handle_request(56, {
        "jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": [],
    })

    assert result["result"] == "0x38"
    proxy._forward.assert_called_once()


@pytest.mark.asyncio
async def test_safe_tx_forwarded(proxy, mock_container):
    """LOW risk transactions should be forwarded."""
    proxy._forward = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0xabc"})
    mock_container.risk_engine.compute_from_results.return_value = {
        'rug_probability': 10, 'risk_level': 'LOW',
    }

    result = await proxy.handle_request(56, {
        "jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction",
        "params": [{"to": "0x" + "a" * 40, "from": "0x" + "b" * 40, "value": "0x0"}],
    })

    assert "error" not in result
    proxy._forward.assert_called_once()


@pytest.mark.asyncio
async def test_honeypot_blocked(proxy, mock_container):
    """HIGH risk transactions should be blocked."""
    mock_container.risk_engine.compute_from_results.return_value = {
        'rug_probability': 92, 'risk_level': 'HIGH',
    }

    result = await proxy.handle_request(56, {
        "jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction",
        "params": [{"to": "0x" + "d" * 40, "from": "0x" + "b" * 40, "value": "0x100"}],
    })

    assert "error" in result
    assert "blocked" in result["error"]["message"].lower()


@pytest.mark.asyncio
async def test_unsupported_chain_id(proxy, mock_container):
    """Unsupported chain_id should return an error."""
    mock_container.web3_client._get_adapter.return_value = None

    result = await proxy.handle_request(999, {
        "jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": [],
    })

    assert "error" in result
    assert "Unsupported" in result["error"]["message"]


@pytest.mark.asyncio
async def test_batched_requests(proxy):
    """Batch requests should all be processed."""
    proxy._forward = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0x38"})

    results = await proxy.handle_batch(56, [
        {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
        {"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber", "params": []},
    ])

    assert len(results) == 2


@pytest.mark.asyncio
async def test_contract_creation_forwarded(proxy):
    """Contract creation (no 'to') should be forwarded without analysis."""
    proxy._forward = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0xhash"})

    result = await proxy.handle_request(56, {
        "jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction",
        "params": [{"from": "0x" + "b" * 40, "data": "0x608060405234"}],
    })

    assert "error" not in result
    proxy._forward.assert_called_once()
