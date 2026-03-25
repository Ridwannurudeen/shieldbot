"""Integration test: agent registers -> checks transaction -> gets verdict -> history recorded."""

import asyncio
import os
import tempfile

import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.database import Database
from agent.firewall import create_agent_firewall_router


@pytest.fixture
def full_client():
    """Test client with real DB, mocked external services."""
    db_path = os.path.join(tempfile.mkdtemp(), "test.db")
    loop = asyncio.new_event_loop()

    class FakeContainer:
        pass

    container = FakeContainer()
    container.db = Database(db_path)

    # Mock external services
    container.cache = MagicMock()
    container.cache.get_verdict = AsyncMock(return_value=None)
    container.cache.set_verdict = AsyncMock()
    container.cache.check_rate_limit = AsyncMock(return_value=True)

    container.auth_manager = MagicMock()
    container.auth_manager.validate_key = AsyncMock(return_value={
        "key_id": "k1", "owner": "test", "tier": "agent",
        "rpm_limit": 500, "daily_limit": 50000,
    })
    container.auth_manager.check_rate_limit = AsyncMock(return_value=True)
    container.auth_manager.record_usage = AsyncMock()

    container.registry = MagicMock()
    container.registry.run_all = AsyncMock(return_value=[])

    container.risk_engine = MagicMock()
    container.risk_engine.compute_from_results = MagicMock(return_value={
        "risk_score": 15, "risk_level": "LOW", "flags": [],
        "category_scores": {}, "confidence": 0.9,
    })

    container.web3_client = MagicMock()
    container.web3_client.is_valid_address = MagicMock(return_value=True)
    container.web3_client.is_contract = AsyncMock(return_value=True)
    container.web3_client.is_token_contract = AsyncMock(return_value=True)

    container.tenderly_simulator = MagicMock()
    container.tenderly_simulator.is_enabled = MagicMock(return_value=False)

    container.calldata_decoder = MagicMock()
    container.calldata_decoder.decode = MagicMock(return_value={
        "selector": "0x38ed1739", "function_name": "swapExactTokensForTokens",
        "category": "swap", "risk": "low", "params": {},
        "is_approval": False, "is_unlimited_approval": False,
    })

    # Init DB synchronously for test
    loop.run_until_complete(container.db.initialize())

    app = FastAPI()
    router = create_agent_firewall_router(container)
    app.include_router(router, prefix="/api/agent")

    yield TestClient(app), container

    loop.run_until_complete(container.db.close())
    loop.close()


def test_full_agent_lifecycle(full_client):
    """Register agent -> check transaction -> verify history."""
    client, container = full_client
    headers = {"X-API-Key": "sb_testkey"}

    # 1. Register
    resp = client.post("/api/agent/register", json={
        "agent_id": "lifecycle_agent",
        "owner_address": "0xOwner",
        "policy": {
            "auto_allow_below": 25,
            "auto_block_above": 70,
            "max_spend_per_tx_usd": 500,
        },
    }, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "registered"

    # 2. Check a safe transaction
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "lifecycle_agent",
        "transaction": {
            "from": "0xAgentWallet",
            "to": "0xSafeToken",
            "data": "0x",
            "value": "0",
            "chain_id": 56,
        },
    }, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "ALLOW"
    assert body["score"] == 15

    # 3. Check history is recorded
    resp = client.get("/api/agent/history?agent_id=lifecycle_agent", headers=headers)
    assert resp.status_code == 200
    history = resp.json()
    assert len(history) == 1
    assert history[0]["verdict"] == "ALLOW"

    # 4. Check a high-risk transaction
    container.risk_engine.compute_from_results.return_value = {
        "risk_score": 91, "risk_level": "HIGH", "flags": ["honeypot"],
        "category_scores": {}, "confidence": 0.95,
    }
    container.cache.get_verdict = AsyncMock(return_value=None)  # no cache

    resp = client.post("/api/agent/firewall", json={
        "agent_id": "lifecycle_agent",
        "transaction": {
            "from": "0xAgentWallet",
            "to": "0xScamToken",
            "data": "0x",
            "value": "1000000000000000000",
            "chain_id": 56,
        },
    }, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "BLOCK"
    assert body["score"] == 91

    # 5. History now has 2 entries
    resp = client.get("/api/agent/history?agent_id=lifecycle_agent", headers=headers)
    assert len(resp.json()) == 2
