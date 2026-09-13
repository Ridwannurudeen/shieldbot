"""HTTP routing rejects unknown chains before touching providers or persistence."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from utils.web3_client import Web3Client


ADDRESS = "0x" + "a" * 40
BODY_CASES = [
    ("/api/firewall", {"to": ADDRESS, "from": ADDRESS}, "chainId"),
    ("/api/scan", {"address": ADDRESS}, "chainId"),
    ("/api/outcome", {"address": ADDRESS, "user_decision": "block"}, "chainId"),
    ("/api/report", {"address": ADDRESS, "report_type": "scam"}, "chainId"),
    ("/api/agent/chat", {"message": "Check this", "user_id": "user"}, "chain_id"),
    ("/api/admin/watch/deployer", {"address": ADDRESS}, "chain_id"),
]


@pytest.fixture
def routing_api(monkeypatch):
    import api
    from agent.firewall import create_agent_firewall_router
    from mcp_server.server import create_mcp_router
    from services.guardian_router import create_guardian_router

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {
        chain_id: MagicMock(chain_id=chain_id)
        for chain_id in (56, 1, 204, 4663)
    }
    services = MagicMock()
    services.web3_client = registry
    services.settings = SimpleNamespace(trusted_proxies=[], admin_secret="test-admin")
    services.auth_manager.validate_key = AsyncMock(return_value={"key_id": "test-key"})
    services.auth_manager.check_rate_limit = AsyncMock(return_value=True)
    services.auth_manager.record_usage = AsyncMock()
    services.db.record_outcome = AsyncMock()
    services.db.record_community_report = AsyncMock()
    services.db.add_watched_deployer = AsyncMock()
    services.db.remove_watched_deployer = AsyncMock()
    services.advisor.chat = AsyncMock(return_value={"text": "result"})
    services.tx_scanner.scan_address = AsyncMock(return_value={})
    services.rescue_service.scan_approvals = AsyncMock(return_value={})
    services.campaign_service.get_entity_graph = AsyncMock(return_value={})
    services.mempool_monitor.get_alerts.return_value = []
    services.mempool_monitor.get_stats.return_value = {}
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "tx_scanner", services.tx_scanner)
    monkeypatch.setattr(api, "calldata_decoder", services.calldata_decoder)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    monkeypatch.setattr(api, "chat_limiter", api.RateLimiter(1000, 1000))
    monkeypatch.setattr(api, "_report_limiter", api.RateLimiter(1000, 1000))
    monkeypatch.setattr(api.app.router, "routes", list(api.app.router.routes))
    api.app.include_router(create_agent_firewall_router(services), prefix="/api/agent")
    api.app.include_router(create_mcp_router(services), prefix="/mcp")
    api.app.include_router(create_guardian_router(services), prefix="/api/guardian")
    client = TestClient(api.app, raise_server_exceptions=False)
    yield client, registry, services
    client.close()


@pytest.mark.parametrize("path,payload,field", BODY_CASES)
def test_body_models_reject_unknown_chain_before_any_service(routing_api, path, payload, field):
    client, registry, services = routing_api
    response = client.post(
        path,
        json={**payload, field: 999999},
        headers={"x-api-key": "test-key", "x-admin-secret": "test-admin"},
    )
    assert response.status_code == 400
    assert "999999" in response.json()["detail"]
    assert all(str(cid) in response.json()["detail"] for cid in registry.get_supported_chain_ids())
    assert services.mock_calls == []
    for adapter in registry._adapters.values():
        assert adapter.mock_calls == []


@pytest.mark.parametrize("method,path", [
    ("get", f"/api/campaign/{ADDRESS}"),
    ("delete", f"/api/admin/watch/deployer/{ADDRESS}"),
    ("get", "/api/mempool/alerts"),
    ("get", "/api/mempool/stats"),
    ("get", f"/api/rescue/{ADDRESS}"),
    ("get", "/api/threats/feed"),
])
def test_query_chains_rejected_before_services(routing_api, method, path):
    client, _, services = routing_api
    response = getattr(client, method)(
        path, params={"chain_id": 999999}, headers={"x-api-key": "test-key"},
    )
    assert response.status_code == 400
    assert "Supported chain IDs" in response.json()["detail"]
    assert services.mock_calls == []


@pytest.mark.parametrize("path", ["/api/mempool/alerts", "/api/mempool/stats"])
def test_robinhood_mempool_is_explicitly_unavailable(routing_api, path):
    client, _, services = routing_api
    response = client.get(path, params={"chain_id": 4663})
    assert response.status_code == 400
    assert "pending-transaction monitoring is not available on this chain" in response.json()["detail"].lower()
    services.mempool_monitor.get_alerts.assert_not_called()
    services.mempool_monitor.get_stats.assert_not_called()


@pytest.mark.parametrize("path", ["/api/health", "/api/threats/subscribe"])
def test_supported_chain_lists_follow_registry(routing_api, path):
    client, registry, _ = routing_api
    registry.register_adapter(SimpleNamespace(chain_id=9876, chain_name="Test chain"))
    response = client.get(path)
    assert response.status_code == 200
    assert response.json()["supported_chains"] == registry.get_supported_chain_ids()


@pytest.mark.parametrize("chain_id", [56, 204, 4663])
def test_registered_scan_routes_without_changing_chain(routing_api, chain_id):
    client, registry, services = routing_api
    response = client.post("/api/scan", json={"address": ADDRESS, "chainId": chain_id})
    assert response.status_code == 200
    services.tx_scanner.scan_address.assert_awaited_once_with(
        registry.to_checksum_address(ADDRESS), chain_id=chain_id,
    )


def test_nested_agent_transaction_rejected_before_authentication(routing_api):
    client, _, services = routing_api
    response = client.post(
        "/api/agent/firewall",
        json={"agent_id": "test", "transaction": {"to": ADDRESS, "from": ADDRESS, "chain_id": 999999}},
        headers={"x-api-key": "test-key"},
    )
    assert response.status_code == 400
    assert services.mock_calls == []


@pytest.mark.parametrize("chain_id", [True, False, 56.9, 4663.1, "56", "4663", None, [], {}])
def test_malformed_chain_cannot_be_coerced_to_supported_chain(routing_api, chain_id):
    client, _, services = routing_api
    response = client.post("/api/outcome", json={
        "address": ADDRESS, "chainId": chain_id, "user_decision": "block",
    })
    assert response.status_code == 400
    assert services.mock_calls == []


@pytest.mark.parametrize("model_name,payload,field", [
    ("FirewallRequest", BODY_CASES[0][1], "chainId"),
    ("ScanRequest", BODY_CASES[1][1], "chainId"),
    ("OutcomeRequest", BODY_CASES[2][1], "chainId"),
    ("CommunityReportRequest", BODY_CASES[3][1], "chainId"),
    ("ChatRequest", BODY_CASES[4][1], "chain_id"),
    ("WatchDeployerRequest", BODY_CASES[5][1], "chain_id"),
])
def test_request_models_validate_explicit_and_default_chain(routing_api, model_name, payload, field):
    import api

    _, registry, _ = routing_api
    model = getattr(api, model_name)
    assert getattr(model(**payload), field) == 56
    with pytest.raises(HTTPException) as exc:
        model(**{**payload, field: 999999})
    assert exc.value.status_code == 400
    registry._adapters.pop(56)
    with pytest.raises(HTTPException) as exc:
        model(**payload)
    assert exc.value.status_code == 400


@pytest.mark.parametrize("path,payload", [
    ("/rpc/999999", {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}),
    ("/mcp/messages", {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "scan_contract", "arguments": {"address": ADDRESS, "chain_id": 999999}},
    }),
    ("/mcp/messages/", {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "scan_contract", "arguments": {"address": ADDRESS, "chain_id": 999999}},
    }),
    ("/api/agent/firewall/", {
        "agent_id": "test", "transaction": {"to": ADDRESS, "from": ADDRESS, "chain_id": 999999},
    }),
])
def test_nested_protocol_chains_rejected_before_usage_is_recorded(routing_api, path, payload):
    client, _, services = routing_api
    response = client.post(path, json=payload, headers={"x-api-key": "test-key"})
    assert response.status_code == 400
    assert "999999" in response.json()["detail"]
    assert services.mock_calls == []


def test_missing_chain_uses_bsc(routing_api):
    client, _, services = routing_api
    response = client.post("/api/outcome", json={"address": ADDRESS, "user_decision": "block"})
    assert response.status_code == 200
    assert services.db.record_outcome.await_args.kwargs["chain_id"] == 56


def test_size_limit_precedes_body_parsing_and_services(routing_api):
    client, _, services = routing_api
    response = client.post(
        "/api/scan", content="{", headers={"content-type": "application/json", "content-length": "1000001"},
    )
    assert response.status_code == 413
    assert services.mock_calls == []


def test_invalid_json_rejected_before_services(routing_api):
    client, _, services = routing_api
    response = client.post("/api/scan", content="{", headers={"content-type": "application/json"})
    assert response.status_code == 400
    assert services.mock_calls == []


@pytest.mark.parametrize("chain_id", ["4663", 56.5, True, 999999])
def test_guardian_raw_body_rejects_invalid_chain_before_persistence(routing_api, chain_id):
    client, _, services = routing_api
    response = client.post(
        "/api/guardian/wallets",
        json={"wallet_address": ADDRESS, "chain_id": chain_id},
        headers={"x-api-key": "test-key"},
    )
    assert response.status_code == 400
    assert services.mock_calls == []


@pytest.mark.parametrize("chain_id", [4663, 56, 204])
def test_threat_feed_preserves_contract_results_without_unavailable_mempool(routing_api, chain_id):
    from services.mempool_service import MempoolMonitor

    client, registry, services = routing_api
    cursor = SimpleNamespace(fetchall=AsyncMock(return_value=[
        (ADDRESS, chain_id, 90, "HIGH", "honeypot", '["High sell tax"]', 1000),
    ]))
    services.db._db.execute = AsyncMock(return_value=cursor)
    monitor = MempoolMonitor(registry)
    monitor.get_alerts = MagicMock(wraps=monitor.get_alerts)
    services.mempool_monitor = monitor

    response = client.get("/api/threats/feed", params={"chain_id": chain_id})

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["chain_id"] == chain_id
    assert body["threats"] == [{
        "type": "high_risk_contract", "address": ADDRESS, "chain_id": chain_id,
        "risk_score": 90, "risk_level": "HIGH", "archetype": "honeypot",
        "flags": ["High sell tax"], "detected_at": 1000,
    }]
    if chain_id == 4663:
        assert body["mempool_unavailable"] == "Pending-transaction monitoring is not available on this chain"
        monitor.get_alerts.assert_not_called()
    else:
        assert set(body) == {"threats", "count", "chain_id"}
        monitor.get_alerts.assert_called_once_with(chain_id=chain_id, limit=50)
    for adapter in registry._adapters.values():
        assert adapter.mock_calls == []
