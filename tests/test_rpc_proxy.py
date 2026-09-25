"""Tests for RPC Proxy."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from eth_account import Account
from web3 import Web3
from core.analyzer import AnalyzerResult
from core.policy import PolicyEngine
from core.risk_engine import RiskEngine
from rpc.proxy import RPCProxy
from utils.scam_db import ScamDatabase
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

    container.web3_client.get_bytecode = AsyncMock(return_value="0x6080604052")

    # Mock registry
    container.registry.run_all = AsyncMock(return_value=[])
    container.policy_engine = PolicyEngine()
    container.scam_db = ScamDatabase()

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


@pytest.mark.asyncio
async def test_failed_verification_lookup_reaches_the_analyzers_as_unknown(proxy, mock_container):
    # A failed explorer lookup is unknown, not unverified: unverified sets a claim() floor of 85.
    mock_container.web3_client.is_token_contract = AsyncMock(return_value=False)
    mock_container.web3_client.is_verified_contract = AsyncMock(side_effect=RuntimeError("explorer down"))
    proxy._forward = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0xabc"})
    await proxy.handle_request(56, {
        "jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction",
        "params": [{"to": "0x" + "a" * 40, "from": "0x" + "b" * 40, "data": "0x4e71d92d", "value": "0x1"}],
    })
    ctx = mock_container.registry.run_all.await_args.args[0]
    assert ctx.extra["is_verified"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("code, is_contract, verified", [
    ("0x6080604052", True, True),
    ("0x", False, False),
    ("ef0100" + "5" * 40, False, False),
    (None, None, True),
], ids=["contract", "wallet", "delegated-wallet", "code-unknown"])
async def test_the_proxy_tells_the_analyzers_whether_the_target_is_a_contract(
    proxy, mock_container, code, is_contract, verified,
):
    mock_container.web3_client.get_bytecode = AsyncMock(return_value=code)
    mock_container.web3_client.is_token_contract = AsyncMock(return_value=False)
    mock_container.web3_client.is_verified_contract = AsyncMock(return_value=(False, None))
    proxy._forward = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0xabc"})
    await proxy.handle_request(56, {
        "jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction",
        "params": [{"to": "0x" + "a" * 40, "from": "0x" + "b" * 40, "data": "0x40c10f19", "value": "0x1"}],
    })
    ctx = mock_container.registry.run_all.await_args.args[0]
    assert ctx.extra["is_contract"] is is_contract
    mock_container.web3_client.get_bytecode.assert_awaited_once_with("0x" + "a" * 40, chain_id=56)
    if verified:
        mock_container.web3_client.is_verified_contract.assert_awaited_once_with("0x" + "a" * 40, chain_id=56, code=code)
    else:
        mock_container.web3_client.is_verified_contract.assert_not_awaited()
        assert ctx.extra["is_verified"] is None


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


TARGET = "0x" + "c" * 40
SEND = {
    "jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction",
    "params": [{"to": TARGET, "from": "0x" + "b" * 40, "value": "0x0"}],
}


def _analysis(gap=None, failed=None):
    """The four target analyzers' results, fully covered except `gap` (analyzer, field), with
    `failed` an analyzer that ran past the deadline."""
    data = {
        "structural": {
            "is_contract": True, "is_verified": True, "contract_age_days": 400, "scam_matches": [],
            "coverage": {"is_verified": True, "contract_age_days": True, "scam_database": True},
        },
        "market": {"liquidity_usd": 50_000},
        "behavioral": {"reputation_score": 50},
        "honeypot": {
            "is_honeypot": False, "can_sell": True, "buy_tax": 0, "sell_tax": 0,
            "coverage": {"is_honeypot": True, "can_sell": True, "buy_tax": True, "sell_tax": True},
        },
    }
    weights = {"structural": 0.40, "market": 0.25, "behavioral": 0.20, "honeypot": 0.15}
    results = []
    for name, weight in weights.items():
        if name == failed:
            results.append(AnalyzerResult(name, weight, 50, error=f"{name} analysis unavailable (TimeoutError)"))
            continue
        fields = {**data[name], "status": "ok"}
        if gap and gap[0] == name:
            fields = {**fields, gap[1]: None, "coverage": {**fields["coverage"], gap[1]: False}, "status": "unknown"}
        results.append(AnalyzerResult(name, weight, 0, data=fields))
    return results


def _judging(mock_container, mode, results):
    """The proxy with the real risk engine, a policy engine in `mode` and the analyzers' `results`."""
    mock_container.registry.run_all = AsyncMock(return_value=results)
    mock_container.risk_engine = RiskEngine()
    mock_container.policy_engine = PolicyEngine(mode)
    mock_container.scam_db = ScamDatabase()
    proxy = RPCProxy(mock_container)
    proxy._forward = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0xhash"})
    return proxy


@pytest.mark.asyncio
async def test_a_strict_server_refuses_a_transaction_whose_required_check_is_unknown(mock_container):
    proxy = _judging(mock_container, "STRICT", _analysis(gap=("honeypot", "can_sell")))

    result = await proxy.handle_request(56, SEND)

    assert result["error"]["code"] == -32003
    proxy._forward.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_strict_server_still_forwards_a_complete_low_risk_transaction(mock_container):
    proxy = _judging(mock_container, "STRICT", _analysis())

    result = await proxy.handle_request(56, SEND)

    assert result == {"jsonrpc": "2.0", "id": 1, "result": "0xhash"}


@pytest.mark.asyncio
async def test_an_admin_listed_target_is_refused_even_when_its_structural_analyzer_times_out(mock_container):
    proxy = _judging(mock_container, "BALANCED", _analysis(failed="structural"))
    proxy._container.scam_db.known_scams[(None, TARGET)] = {"source": "admin", "reports": 0, "expires_at": None}

    result = await proxy.handle_request(56, SEND)

    assert result["error"]["code"] == -32003
    assert "(HIGH)" in result["error"]["message"]
    proxy._forward.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_balanced_server_forwards_a_medium_risk_transaction(mock_container):
    proxy = _judging(mock_container, "BALANCED", [])
    mock_container.risk_engine = MagicMock()
    mock_container.risk_engine.compute_from_results.return_value = {'rug_probability': 40, 'risk_level': 'MEDIUM'}

    result = await proxy.handle_request(56, SEND)

    assert result == {"jsonrpc": "2.0", "id": 1, "result": "0xhash"}


@pytest.mark.asyncio
async def test_an_analysis_without_a_risk_level_is_never_forwarded(mock_container):
    proxy = _judging(mock_container, "BALANCED", [])
    mock_container.risk_engine = MagicMock()
    mock_container.risk_engine.compute_from_results.return_value = {'rug_probability': 10}

    result = await proxy.handle_request(56, SEND)

    assert result["error"]["code"] == -32003
    proxy._forward.assert_not_awaited()
