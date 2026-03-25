"""Tests for the agent firewall API endpoints."""

import pytest
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


@pytest.fixture
def mock_container():
    """Mock ServiceContainer with agent firewall dependencies."""
    c = MagicMock()
    c.db = MagicMock()
    c.db.get_agent_policy = AsyncMock(return_value={
        "agent_id": "agent:1",
        "owner_address": "0xowner",
        "owner_telegram": "@owner",
        "tier": "agent",
        "policy": {
            "mode": "threshold",
            "auto_allow_below": 25,
            "auto_block_above": 70,
            "max_spend_per_tx_usd": 500,
            "max_spend_daily_usd": 5000,
            "max_slippage": 0.05,
            "always_allow": [],
            "always_block": [],
        },
        "daily_spend_used_usd": 0,
    })
    c.db.get_agent_daily_spend = AsyncMock(return_value=0)
    c.db.record_agent_firewall_event = AsyncMock()
    c.db.record_agent_spend = AsyncMock()
    c.db.upsert_agent_policy = AsyncMock()
    c.db.get_agent_firewall_history = AsyncMock(return_value=[])
    c.db.get_contract_score = AsyncMock(return_value=None)
    c.db.upsert_contract_score = AsyncMock()

    c.cache = MagicMock()
    c.cache.get_verdict = AsyncMock(return_value=None)
    c.cache.set_verdict = AsyncMock()
    c.cache.check_rate_limit = AsyncMock(return_value=True)

    c.registry = MagicMock()
    c.registry.run_all = AsyncMock(return_value=[])

    c.risk_engine = MagicMock()
    c.risk_engine.compute_from_results = MagicMock(return_value={
        "risk_score": 12, "risk_level": "LOW", "flags": [],
        "category_scores": {}, "confidence": 0.9,
    })

    c.auth_manager = MagicMock()
    c.auth_manager.validate_key = AsyncMock(return_value={
        "key_id": "k1", "owner": "test", "tier": "agent", "rpm_limit": 500, "daily_limit": 50000,
    })
    c.auth_manager.check_rate_limit = AsyncMock(return_value=True)
    c.auth_manager.record_usage = AsyncMock()

    c.web3_client = MagicMock()
    c.web3_client.is_valid_address = MagicMock(return_value=True)
    c.web3_client.is_contract = AsyncMock(return_value=True)
    c.web3_client.is_token_contract = AsyncMock(return_value=True)

    c.tenderly_simulator = MagicMock()
    c.tenderly_simulator.is_enabled = MagicMock(return_value=False)

    c.calldata_decoder = MagicMock()
    c.calldata_decoder.decode = MagicMock(return_value={
        "selector": "0x38ed1739", "function_name": "swapExactTokensForTokens",
        "category": "swap", "risk": "low", "params": {},
        "is_approval": False, "is_unlimited_approval": False,
    })

    return c


@pytest.fixture
def client(mock_container):
    """Create test client with mocked container."""
    from agent.firewall import create_agent_firewall_router
    from fastapi import FastAPI

    app = FastAPI()
    router = create_agent_firewall_router(mock_container)
    app.include_router(router, prefix="/api/agent")
    return TestClient(app)


def test_agent_firewall_allow(client, mock_container):
    """Transaction to safe contract returns ALLOW."""
    mock_container.risk_engine.compute_from_results.return_value = {
        "risk_score": 12, "risk_level": "LOW", "flags": [],
        "category_scores": {}, "confidence": 0.9,
    }
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "agent:1",
        "transaction": {
            "from": "0xAgentWallet",
            "to": "0xSafeContract",
            "data": "0x38ed1739",
            "value": "0",
            "chain_id": 56,
        },
    }, headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "ALLOW"
    assert body["score"] == 12


def test_agent_firewall_block(client, mock_container):
    """Transaction to high-risk contract returns BLOCK."""
    mock_container.risk_engine.compute_from_results.return_value = {
        "risk_score": 91, "risk_level": "HIGH", "flags": ["honeypot"],
        "category_scores": {}, "confidence": 0.95,
    }
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "agent:1",
        "transaction": {
            "from": "0xAgentWallet",
            "to": "0xScamContract",
            "data": "0x",
            "value": "1000000000000000000",
            "chain_id": 56,
        },
    }, headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "BLOCK"
    assert body["score"] == 91


def test_agent_firewall_no_api_key(client):
    """Request without API key returns 401."""
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "agent:1",
        "transaction": {"from": "0x1", "to": "0x2", "chain_id": 56},
    })
    assert resp.status_code == 401


def test_agent_firewall_unregistered_agent(client, mock_container):
    """Request from unregistered agent returns 404."""
    mock_container.db.get_agent_policy = AsyncMock(return_value=None)
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "unknown_agent",
        "transaction": {"from": "0x1", "to": "0x2", "chain_id": 56},
    }, headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 404


def test_agent_register(client, mock_container):
    """Register a new agent with a policy."""
    resp = client.post("/api/agent/register", json={
        "agent_id": "new_agent",
        "owner_address": "0xOwner",
        "owner_telegram": "@owner",
        "policy": {
            "auto_allow_below": 20,
            "auto_block_above": 75,
            "max_spend_per_tx_usd": 1000,
        },
    }, headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == "new_agent"
    mock_container.db.upsert_agent_policy.assert_called_once()


def test_agent_history(client, mock_container):
    """Get agent firewall history."""
    mock_container.db.get_agent_firewall_history = AsyncMock(return_value=[
        {"id": 1, "verdict": "ALLOW", "score": 12, "created_at": time.time()},
    ])
    resp = client.get("/api/agent/history?agent_id=agent:1",
                      headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    assert len(resp.json()) == 1
