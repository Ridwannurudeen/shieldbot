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
        "registered_by_key": "k1",
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
        "status": "ok", "coverage": {"honeypot": 1},
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

    c.threat_graph = MagicMock()
    c.threat_graph.enrich_from_scan = AsyncMock()

    c.reputation_service = MagicMock()
    c.reputation_service.update_from_verdict = AsyncMock()

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
        "status": "ok", "coverage": {"honeypot": 1},
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
        "status": "ok", "coverage": {"honeypot": 1},
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


def test_agent_firewall_cached_verdict(client, mock_container):
    """Transaction with cached verdict skips analyzer pipeline."""
    mock_container.cache.get_verdict = AsyncMock(return_value={
        "score": 45, "flags": ["suspicious"], "status": "ok", "coverage": {"honeypot": 1}, "risk_level": "MEDIUM",
    })
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "agent:1",
        "transaction": {
            "from": "0xAgent",
            "to": "0xTarget",
            "value": "0",
            "chain_id": 56,
        },
    }, headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["cached"] is True
    assert body["score"] == 45
    assert body["flags"] == ["suspicious"]
    # Verify analyzer pipeline was NOT called
    mock_container.registry.run_all.assert_not_called()


def test_agent_history(client, mock_container):
    """Get agent firewall history."""
    mock_container.db.get_agent_firewall_history = AsyncMock(return_value=[
        {"id": 1, "verdict": "ALLOW", "score": 12, "created_at": time.time()},
    ])
    resp = client.get("/api/agent/history?agent_id=agent:1",
                      headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    assert len(resp.json()) == 1


# --- Tenderly simulation tests (Item 4) ---


def _make_firewall_request():
    return {
        "agent_id": "agent:1",
        "transaction": {
            "from": "0xAgentWallet",
            "to": "0xTarget",
            "data": "0x38ed1739",
            "value": "0",
            "chain_id": 56,
        },
    }


def test_agent_firewall_tenderly_enabled_parallel(client, mock_container):
    """Tenderly enabled: simulation runs in parallel, result in response."""
    mock_container.tenderly_simulator.is_enabled.return_value = True
    mock_container.tenderly_simulator.simulate_transaction = AsyncMock(return_value={
        "success": True, "asset_changes": [], "warnings": [], "gas_used": 21000,
    })
    resp = client.post("/api/agent/firewall",
                       json=_make_firewall_request(),
                       headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["simulation"] is not None
    assert body["simulation"]["success"] is True
    assert body["simulation"]["gas_used"] == 21000


def test_agent_firewall_tenderly_revert_floors_risk(client, mock_container):
    """Tenderly revert floors risk_score at 70."""
    mock_container.tenderly_simulator.is_enabled.return_value = True
    mock_container.risk_engine.compute_from_results.return_value = {
        "risk_score": 30, "risk_level": "LOW", "flags": [],
        "status": "ok", "coverage": {"honeypot": 1},
        "category_scores": {}, "confidence": 0.8,
    }
    mock_container.tenderly_simulator.simulate_transaction = AsyncMock(return_value={
        "success": False, "revert_reason": "execution reverted",
        "asset_changes": [], "warnings": [], "gas_used": 0,
    })
    resp = client.post("/api/agent/firewall",
                       json=_make_firewall_request(),
                       headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["score"] >= 70
    assert "simulation_revert" in body["flags"]


def test_agent_firewall_tenderly_failure_nonfatal(client, mock_container):
    """Tenderly API failure is non-fatal — analysis proceeds without simulation."""
    mock_container.tenderly_simulator.is_enabled.return_value = True
    mock_container.tenderly_simulator.simulate_transaction = AsyncMock(
        side_effect=Exception("Tenderly API down"),
    )
    resp = client.post("/api/agent/firewall",
                       json=_make_firewall_request(),
                       headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["simulation"] is None
    assert body["verdict"] in ("ALLOW", "WARN", "BLOCK")


def test_agent_firewall_tenderly_disabled_no_simulation(client, mock_container):
    """Tenderly disabled: no simulation key in response."""
    mock_container.tenderly_simulator.is_enabled.return_value = False
    resp = client.post("/api/agent/firewall",
                       json=_make_firewall_request(),
                       headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("simulation") is None


@pytest.mark.parametrize("reason,fraction", [("Provider unavailable", 0), ("Simulation failed", 0.8)])
@pytest.mark.parametrize("source", ["fresh", "redis", "sqlite"])
def test_agent_incomplete_coverage_survives_caches(client, mock_container, reason, fraction, source):
    metadata = {"status": "unknown", "coverage": {"honeypot": fraction}, "coverage_reasons": {"honeypot": reason}}
    output = {"rug_probability": 0, "risk_level": "UNKNOWN", "critical_flags": [reason], **metadata}
    mock_container.risk_engine.compute_from_results.return_value = output
    if source == "redis":
        mock_container.cache.get_verdict.return_value = {"score": 0, "flags": [reason], **metadata}
    elif source == "sqlite":
        mock_container.db.get_contract_score.return_value = {"risk_score": 0, "risk_level": "UNKNOWN", "flags": [reason], "category_scores": {"_scan_metadata": metadata}}
    resp = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    body = resp.json()
    assert resp.status_code == 200
    assert body["verdict"] == "BLOCK"
    assert body["score"] == 0
    assert body["status"] == "unknown"
    assert body["coverage"] == metadata["coverage"]
    assert body["coverage_reasons"] == metadata["coverage_reasons"]
    assert "Unknown" in body["risk_display"]
    if source == "fresh":
        stored = mock_container.db.upsert_contract_score.call_args.kwargs["category_scores"]["_scan_metadata"]
        assert stored["status"] == "unknown"
    if source != "redis":
        assert mock_container.cache.set_verdict.call_args.args[2]["status"] == "unknown"


def test_agent_legacy_sqlite_cache_rescans(client, mock_container):
    mock_container.db.get_contract_score.return_value = {"risk_score": 0, "risk_level": "LOW", "category_scores": {}}
    resp = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    mock_container.registry.run_all.assert_awaited_once()


@pytest.mark.parametrize("source", ["registry", "simulation"])
def test_agent_routing_errors_propagate(client, mock_container, source):
    from utils.web3_client import UnsupportedChainError
    if source == "registry":
        mock_container.registry.run_all.side_effect = UnsupportedChainError("Unsupported chain")
    else:
        mock_container.tenderly_simulator.is_enabled.return_value = True
        mock_container.tenderly_simulator.simulate_transaction = AsyncMock(side_effect=UnsupportedChainError("Unsupported chain"))
    with pytest.raises(UnsupportedChainError):
        client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    mock_container.cache.set_verdict.assert_not_awaited()


def test_agent_legacy_redis_cache_rescans(client, mock_container):
    mock_container.cache.get_verdict.return_value = {"score": 0, "flags": []}
    response = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    assert response.status_code == 200
    mock_container.registry.run_all.assert_awaited_once()


@pytest.mark.parametrize("simulation", [None, {"success": False}, RuntimeError("offline")])
def test_agent_failed_optional_simulation_blocks(client, mock_container, simulation):
    mock_container.tenderly_simulator.is_enabled.return_value = True
    mock_container.tenderly_simulator.simulate_transaction = AsyncMock(
        side_effect=simulation if isinstance(simulation, Exception) else None,
        return_value=simulation if not isinstance(simulation, Exception) else None,
    )
    response = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    result = response.json()
    assert response.status_code == 200
    assert result["verdict"] == "BLOCK"
    assert result["status"] == "unknown"
    assert result["coverage"]["simulation"] == 0
    assert "simulation" in result["coverage_reasons"]
    assert mock_container.cache.set_verdict.call_args.args[2]["status"] == "unknown"


@pytest.mark.parametrize("source", ["fresh", "redis", "sqlite"])
@pytest.mark.parametrize("uncertainty", [{"risk_level": "UNKNOWN"}, {"partial": True}])
def test_agent_normalizes_inconsistent_unknown_before_policy(client, mock_container, source, uncertainty):
    data = {"risk_level": "LOW", "rug_probability": 0, "critical_flags": [], "status": "ok", "coverage": {"honeypot": 1}, **uncertainty}
    mock_container.risk_engine.compute_from_results.return_value = data
    if source == "redis":
        mock_container.cache.get_verdict.return_value = {**data, "score": 0}
    elif source == "sqlite":
        mock_container.db.get_contract_score.return_value = {
            **data, "risk_score": 0,
            "category_scores": {"_scan_metadata": {key: value for key, value in data.items() if key in ("status", "coverage", "partial")}},
        }
    response = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    assert response.status_code == 200
    assert response.json()["verdict"] == "BLOCK"
    assert response.json()["status"] == "unknown"


def test_agent_exposes_complete_risk_metadata(client, mock_container):
    response = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    assert response.json()["risk_level"] == "LOW"
    assert response.json()["category_scores"] == {}
    assert response.json()["confidence"] == 0.9
    assert mock_container.cache.set_verdict.call_args.args[2]["risk_level"] == "LOW"
