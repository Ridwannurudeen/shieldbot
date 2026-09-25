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


def test_agent_firewall_reentrancy_warning_stores_the_level_of_its_score(client, mock_container):
    """The reentrancy floor raises the score to 80, and the level stored and cached with it follows."""
    mock_container.tenderly_simulator.is_enabled.return_value = True
    mock_container.risk_engine.compute_from_results.return_value = {
        "rug_probability": 40, "risk_level": "MEDIUM", "flags": [],
        "status": "ok", "coverage": {"honeypot": 1},
        "category_scores": {}, "confidence": 0.8,
    }
    mock_container.tenderly_simulator.simulate_transaction = AsyncMock(return_value={
        "success": True, "asset_changes": [], "warnings": ["Possible reentrancy detected"], "gas_used": 21000,
    })
    resp = client.post("/api/agent/firewall",
                       json=_make_firewall_request(),
                       headers={"X-API-Key": "sb_testkey"})
    body = resp.json()
    assert (body["score"], body["risk_level"]) == (80, "HIGH")
    stored = mock_container.db.upsert_contract_score.await_args.kwargs
    assert (stored["risk_score"], stored["risk_level"]) == (80, "HIGH")
    assert mock_container.cache.set_verdict.await_args.args[2]["risk_level"] == "HIGH"


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
    assert body["verdict"] == "WARN"
    assert body["policy_check"]["needs_owner_approval"] is True
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


def test_agent_sqlite_cached_verdict_reports_cached(client, mock_container):
    metadata = {"status": "ok", "coverage": {"honeypot": 1}, "coverage_reasons": {}}
    mock_container.db.get_contract_score.return_value = {
        "risk_score": 12, "risk_level": "LOW", "flags": [], "category_scores": {"_scan_metadata": metadata},
    }
    resp = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    body = resp.json()
    assert resp.status_code == 200
    assert (body["verdict"], body["score"], body["status"]) == ("ALLOW", 12, "ok")
    assert body["cached"] is True
    mock_container.registry.run_all.assert_not_awaited()


def test_agent_fresh_verdict_reports_not_cached(client, mock_container):
    resp = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    assert resp.json()["cached"] is False
    mock_container.registry.run_all.assert_awaited_once()


@pytest.mark.parametrize("row_status", ["raw", "database"])
def test_agent_legacy_sqlite_cache_rescans(client, mock_container, row_status):
    from core.database import _lift_scan_metadata
    row = {"risk_score": 0, "risk_level": "LOW", "category_scores": {}}
    mock_container.db.get_contract_score.return_value = row if row_status == "raw" else _lift_scan_metadata(row)
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


@pytest.mark.parametrize("simulation", [None, RuntimeError("offline")], ids=["unavailable", "exception"])
def test_agent_unavailable_simulation_has_no_coverage_penalty(client, mock_container, simulation):
    mock_container.tenderly_simulator.is_enabled.return_value = True
    mock_container.tenderly_simulator.simulate_transaction = AsyncMock(
        side_effect=simulation if isinstance(simulation, Exception) else None,
        return_value=None,
    )
    response = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    result = response.json()
    assert response.status_code == 200
    assert result["verdict"] == "ALLOW"
    assert result["status"] == "ok"
    assert "transaction_simulation" not in result["coverage"]
    assert mock_container.cache.set_verdict.call_args.args[2]["status"] == "ok"


@pytest.mark.parametrize("simulation", [
    {"gas_used": 21000, "asset_changes": [], "warnings": []},
    {"success": None, "gas_used": 21000, "asset_changes": [], "warnings": []},
], ids=["missing-success", "none-success"])
def test_agent_simulation_without_explicit_failure_has_no_penalty(client, mock_container, simulation):
    mock_container.tenderly_simulator.is_enabled.return_value = True
    mock_container.tenderly_simulator.simulate_transaction = AsyncMock(return_value=simulation)
    response = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    result = response.json()
    assert response.status_code == 200
    assert (result["verdict"], result["score"], result["status"]) == ("ALLOW", 12, "ok")
    assert "transaction_simulation" not in result["coverage"]
    assert "simulation_revert" not in result["flags"]


@pytest.mark.parametrize("revert_reason,expected_reason", [
    ("execution reverted", "execution reverted"),
    (None, "Transaction simulation failed"),
])
def test_agent_reverted_simulation_is_incomplete_and_keeps_risk_floor(client, mock_container, revert_reason, expected_reason):
    mock_container.tenderly_simulator.is_enabled.return_value = True
    mock_container.tenderly_simulator.simulate_transaction = AsyncMock(return_value={
        "success": False, "revert_reason": revert_reason,
        "asset_changes": [], "warnings": [], "gas_used": 0,
    })
    response = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    result = response.json()
    assert response.status_code == 200
    assert result["verdict"] == "WARN"
    assert result["score"] >= 70
    assert result["status"] == "unknown"
    assert result["coverage"]["transaction_simulation"] == 0
    assert result["coverage_reasons"]["transaction_simulation"] == expected_reason
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
    assert response.json()["verdict"] == "WARN"
    assert response.json()["status"] == "unknown"


def test_agent_exposes_complete_risk_metadata(client, mock_container):
    response = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})
    assert response.json()["risk_level"] == "LOW"
    assert response.json()["category_scores"] == {}
    assert response.json()["confidence"] == 0.9
    assert mock_container.cache.set_verdict.call_args.args[2]["risk_level"] == "LOW"


def _value_request(value, chain_id=56):
    request = _make_firewall_request()
    request["transaction"] = {**request["transaction"], "value": value, "chain_id": chain_id}
    return request


def _complete_cached_verdict(mock_container):
    mock_container.cache.get_verdict.return_value = {
        "score": 12, "flags": [], "status": "ok", "coverage": {"honeypot": 1}, "risk_level": "LOW",
    }


@pytest.mark.parametrize("value", ["abc", "", "-1", "1.5", "1e18", "0x", "0xg1", str(2**256), hex(2**256)])
def test_agent_rejects_a_value_that_is_not_wei(client, mock_container, value):
    """A value that is not an integer amount of wei from 0 to 2**256 - 1 is refused, never priced as $0."""
    response = client.post("/api/agent/firewall", json=_value_request(value), headers={"X-API-Key": "sb_testkey"})
    assert response.status_code == 400
    mock_container.cache.get_verdict.assert_not_called()
    mock_container.db.record_agent_firewall_event.assert_not_called()


def test_agent_rejects_a_json_number_value(client, mock_container):
    response = client.post("/api/agent/firewall", json=_value_request(10**18), headers={"X-API-Key": "sb_testkey"})
    assert response.status_code == 422
    mock_container.cache.get_verdict.assert_not_called()


def test_agent_rejects_an_overlong_value_without_a_server_error(client, mock_container):
    """A 400-digit value used to overflow the float price estimate into an uncaught 5xx."""
    response = client.post("/api/agent/firewall", json=_value_request("9" * 400), headers={"X-API-Key": "sb_testkey"})
    assert response.status_code == 422
    mock_container.cache.get_verdict.assert_not_called()


@pytest.mark.parametrize("source", ["fresh", "redis"])
@pytest.mark.parametrize("chain_id", [56, 204])
@pytest.mark.parametrize("value", ["1000000000000000000", "0xde0b6b3a7640000", " 0XDE0B6B3A7640000 "])
def test_agent_prices_bnb_in_decimal_or_hex(client, mock_container, source, chain_id, value):
    """1 BNB is priced at $600 on BSC and opBNB in either notation, over the fixture's $500 limit."""
    if source == "redis":
        _complete_cached_verdict(mock_container)
    response = client.post("/api/agent/firewall", json=_value_request(value, chain_id), headers={"X-API-Key": "sb_testkey"})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["policy_check"]["failed"] == ["spending_limit"]
    assert "$600.00" in body["policy_check"]["checks"]["spending_limit"]
    mock_container.db.record_agent_spend.assert_not_called()


@pytest.mark.parametrize("source", ["fresh", "redis"])
@pytest.mark.parametrize("chain_id", [1, 8453, 42161, 137, 10, 4663])
def test_agent_unpriced_native_value_asks_owner(client, mock_container, source, chain_id):
    """These chains' native tokens have no USD price here, so even 0.001 of one cannot pass the spend limits."""
    if source == "redis":
        _complete_cached_verdict(mock_container)
    response = client.post(
        "/api/agent/firewall", json=_value_request("1000000000000000", chain_id), headers={"X-API-Key": "sb_testkey"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "WARN"
    assert body["policy_check"]["needs_owner_approval"] is True
    assert {"spending_limit", "daily_limit"} <= set(body["policy_check"]["failed"])
    mock_container.db.record_agent_spend.assert_not_called()


@pytest.mark.parametrize("value", ["0", "0x0"])
@pytest.mark.parametrize("chain_id", [1, 4663])
def test_agent_zero_value_is_known_on_every_chain(client, mock_container, value, chain_id):
    response = client.post("/api/agent/firewall", json=_value_request(value, chain_id), headers={"X-API-Key": "sb_testkey"})
    assert response.json()["verdict"] == "ALLOW"
    mock_container.db.record_agent_spend.assert_not_called()


@pytest.mark.parametrize("source", ["fresh", "redis"])
def test_agent_records_allowed_bnb_spend(client, mock_container, source):
    if source == "redis":
        _complete_cached_verdict(mock_container)
    response = client.post(
        "/api/agent/firewall", json=_value_request("100000000000000000"), headers={"X-API-Key": "sb_testkey"},
    )
    assert response.json()["verdict"] == "ALLOW"
    mock_container.db.record_agent_spend.assert_awaited_once_with("agent:1", pytest.approx(60.0))


@pytest.mark.parametrize("can_sell_known, failed", [(True, []), (False, ["honeypot"])])
def test_an_agent_scan_row_names_its_failed_required_checks(client, mock_container, can_sell_known, failed):
    # The firewall's STRICT check reads them from the row, as it does from its own scans' rows.
    from core.analyzer import AnalyzerResult

    mock_container.registry.run_all = AsyncMock(return_value=[
        AnalyzerResult("honeypot", 1.0, 0, data={
            "is_honeypot": False, "can_sell": True if can_sell_known else None,
            "coverage": {"is_honeypot": True, "can_sell": can_sell_known},
        }),
    ])
    resp = client.post("/api/agent/firewall", json=_make_firewall_request(), headers={"X-API-Key": "sb_testkey"})

    assert resp.status_code == 200
    stored = mock_container.db.upsert_contract_score.await_args.kwargs["category_scores"]["_scan_metadata"]
    assert stored["failed_sources"] == failed
