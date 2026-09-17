"""Tests for RPC Proxy."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from eth_account import Account
from web3 import Web3
from rpc.proxy import RPCProxy
from utils.web3_client import Web3Client


@pytest.fixture
def mock_container():
    """Create a mock container for RPC proxy testing."""
    container = MagicMock()

    # Mock web3_client
    adapter = MagicMock()
    adapter.w3.provider.endpoint_uri = "https://bsc-dataseed1.binance.org/"
    container.web3_client = Web3Client.__new__(Web3Client)
    container.web3_client._adapters = {56: adapter, 1: adapter, 8453: adapter}

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


# -- Helper to build a signed raw tx hex for testing --
def _build_raw_tx(to: str, value: int = 0, data: bytes = b"") -> str:
    """Sign a dummy transaction and return the raw hex."""
    # Deterministic throwaway key (never used on mainnet)
    key = "0x" + "ab" * 32
    tx = {
        "to": Web3.to_checksum_address(to),
        "value": value,
        "gas": 21000,
        "gasPrice": 5_000_000_000,
        "nonce": 0,
        "chainId": 56,
        "data": data,
    }
    signed = Account.sign_transaction(tx, key)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return raw.hex()


@pytest.mark.asyncio
async def test_raw_tx_honeypot_blocked(proxy, mock_container):
    """eth_sendRawTransaction to a HIGH-risk address should be blocked."""
    mock_container.risk_engine.compute_from_results.return_value = {
        'rug_probability': 95, 'risk_level': 'HIGH',
    }

    to_addr = "0x" + "dd" * 20
    raw_hex = _build_raw_tx(to_addr, value=10**18)

    result = await proxy.handle_request(56, {
        "jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction",
        "params": [raw_hex],
    })

    assert "error" in result
    assert "blocked" in result["error"]["message"].lower()


@pytest.mark.asyncio
async def test_raw_tx_safe_forwarded(proxy, mock_container):
    """eth_sendRawTransaction to a LOW-risk address should be forwarded."""
    proxy._forward = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0xtxhash"})
    mock_container.risk_engine.compute_from_results.return_value = {
        'rug_probability': 5, 'risk_level': 'LOW',
    }

    to_addr = "0x" + "aa" * 20
    raw_hex = _build_raw_tx(to_addr, value=10**17)

    result = await proxy.handle_request(56, {
        "jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction",
        "params": [raw_hex],
    })

    assert "error" not in result
    proxy._forward.assert_called_once()


@pytest.mark.asyncio
async def test_unknown_chain_lists_registry_and_does_not_forward(proxy, mock_container):
    proxy._forward = AsyncMock()
    result = await proxy.handle_request(999999, {
        "jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction", "params": [],
    })
    assert "Supported" in result["error"]["message"]
    assert "56" in result["error"]["message"]
    mock_container.registry.run_all.assert_not_awaited()
    proxy._forward.assert_not_awaited()


@pytest.mark.asyncio
async def test_robinhood_rpc_routes_registered_provider(proxy, mock_container):
    adapter = MagicMock()
    adapter.w3.provider.endpoint_uri = "https://rpc.mainnet.chain.robinhood.com"
    mock_container.web3_client._adapters[4663] = adapter
    payload = {"jsonrpc": "2.0", "id": 7, "method": "eth_chainId", "params": []}
    proxy._forward = AsyncMock(return_value={"jsonrpc": "2.0", "id": 7, "result": "0x1237"})
    result = await proxy.handle_request(4663, payload)
    assert result["result"] == "0x1237"
    proxy._forward.assert_awaited_once_with(adapter.w3.provider.endpoint_uri, payload, 4663)


def test_rpc_unknown_chain_rejected_before_auth_database_work(proxy, mock_container):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from rpc.router import rpc_router

    app = FastAPI()
    app.state.rpc_proxy = proxy
    app.include_router(rpc_router)
    mock_container.auth_manager.validate_key = AsyncMock(return_value={"key_id": "test"})
    mock_container.auth_manager.check_rate_limit = AsyncMock(return_value=True)
    mock_container.auth_manager.record_usage = AsyncMock()
    with TestClient(app) as client:
        response = client.post('/rpc/999999', json={
            "jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": [],
        }, headers={"x-api-key": "test"})
    assert response.status_code == 400
    assert "Supported" in response.json()["error"]["message"]
    mock_container.auth_manager.validate_key.assert_not_awaited()
    mock_container.auth_manager.record_usage.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["is_token_contract", "is_verified_contract", "registry"])
async def test_rpc_analysis_routing_error_never_forwards(proxy, mock_container, method):
    from utils.web3_client import UnsupportedChainError

    error = UnsupportedChainError("removed chain")
    mock_container.web3_client.is_token_contract = AsyncMock(return_value=True)
    mock_container.web3_client.is_verified_contract = AsyncMock(return_value=True)
    if method == "registry":
        mock_container.registry.run_all.side_effect = error
    else:
        getattr(mock_container.web3_client, method).side_effect = error
    proxy._forward = AsyncMock()
    with pytest.raises(UnsupportedChainError) as exc:
        await proxy.handle_request(56, {
            "jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction",
            "params": [{"to": "0x" + "a" * 40, "from": "0x" + "b" * 40}],
        })
    assert exc.value is error
    proxy._forward.assert_not_awaited()
    mock_container.risk_engine.compute_from_results.assert_not_called()


SYNTHETIC_RPC_KEY = "SYNTHETIC-RPC-KEY-4f2c9e"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["forward", "analysis", "decode"])
async def test_rpc_failures_log_chain_and_class_without_secrets(proxy, mock_container, caplog, failure):
    import logging
    import aiohttp

    leaky = f"https://rpc.example/v2/{SYNTHETIC_RPC_KEY}"
    adapter = MagicMock()
    adapter.w3.provider.endpoint_uri = leaky
    mock_container.web3_client._adapters[4663] = adapter
    session = MagicMock()
    session.post.side_effect = aiohttp.ClientConnectionError(f"Cannot connect to {leaky}")
    proxy._get_session = AsyncMock(return_value=session)
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
    if failure == "analysis":
        mock_container.web3_client.is_token_contract = AsyncMock(return_value=True)
        mock_container.web3_client.is_verified_contract = AsyncMock(return_value=True)
        mock_container.registry.run_all.side_effect = RuntimeError(f"request to {leaky} failed")
        payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction",
                   "params": [{"to": "0x" + "a" * 40, "from": "0x" + "b" * 40}]}
    elif failure == "decode":
        payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": ["0x02c0"]}
    with caplog.at_level(logging.DEBUG, logger="rpc.proxy"):
        if failure == "decode":
            with patch("rpc.proxy.rlp.decode", side_effect=ValueError(f"bad payload from {leaky}")):
                result = await proxy.handle_request(4663, payload)
        else:
            result = await proxy.handle_request(4663, payload)
    assert "error" in result
    assert SYNTHETIC_RPC_KEY not in caplog.text
    assert "rpc.example" not in caplog.text
    expected = {"forward": "ClientConnectionError", "analysis": "RuntimeError", "decode": "ValueError"}[failure]
    assert expected in caplog.text
    if failure == "forward":
        assert "4663" in caplog.text
