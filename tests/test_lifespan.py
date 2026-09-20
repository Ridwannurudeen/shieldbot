"""Integration tests for API startup, mounted routers, and shutdown."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def mock_container(monkeypatch):
    import api

    routes = list(api.app.router.routes)
    lifespan_context = api.app.router.lifespan_context
    had_rpc_proxy = hasattr(api.app.state, "rpc_proxy")
    rpc_proxy = getattr(api.app.state, "rpc_proxy", None)
    globals_before = {
        name: getattr(api, name)
        for name in (
            "container", "web3_client", "ai_analyzer", "tx_scanner",
            "token_scanner", "calldata_decoder", "scam_db", "dex_service",
            "ethos_service", "honeypot_service", "contract_service", "risk_engine",
            "greenfield_service", "tenderly_simulator", "token_gate_service",
            "advisor",
        )
    }
    settings = SimpleNamespace(
        rpc_proxy_enabled=False, trusted_proxies=[], admin_secret="",
    )
    container = MagicMock(settings=settings)
    container.startup = AsyncMock()
    container.shutdown = AsyncMock()
    container.hunter.start = AsyncMock()
    container.hunter.stop = AsyncMock()
    container.launch_watch.start = AsyncMock()
    container.launch_watch.stop = AsyncMock()
    container.verdict_publisher.stop = AsyncMock()
    container.auth_manager.validate_key = AsyncMock(
        return_value={"key_id": "lifespan-key", "tier": "free"},
    )
    container.auth_manager.check_rate_limit = AsyncMock(return_value=True)
    container.auth_manager.record_usage = AsyncMock()
    container.db.get_agent_policy = AsyncMock(return_value={
        "agent_id": "lifespan-agent",
        "registered_by_key": "lifespan-key",
        "policy": {"auto_allow_below": 25},
    })
    container.threat_graph.get_stats = AsyncMock(return_value={
        "total_edges": 3, "total_clusters": 1,
    })
    container.reputation_service.get_leaderboard = AsyncMock(return_value=[
        {"agent_id": "lifespan-agent", "composite_score": 90},
    ])
    container.guardian_service.get_health = AsyncMock(return_value={
        "health_score": 90, "warnings": [],
    })
    monkeypatch.setattr(api, "Settings", MagicMock(return_value=settings))
    monkeypatch.setattr(api, "ServiceContainer", MagicMock(return_value=container))
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter())

    if had_rpc_proxy:
        del api.app.state.rpc_proxy
    try:
        yield container
    finally:
        api.app.router.routes[:] = routes
        api.app.router.lifespan_context = lifespan_context
        for name, value in globals_before.items():
            setattr(api, name, value)
        if hasattr(api.app.state, "rpc_proxy"):
            del api.app.state.rpc_proxy
        if had_rpc_proxy:
            api.app.state.rpc_proxy = rpc_proxy


class TestLifespan:
    def test_startup_mounts_routers_and_shutdown_closes_services(self, mock_container):
        import api

        wallet = "0x0000000000000000000000000000000000000001"

        with TestClient(api.app) as client:
            api.Settings.assert_called_once_with()
            api.ServiceContainer.assert_called_once_with(mock_container.settings)
            mock_container.startup.assert_awaited_once_with()
            mock_container.hunter.start.assert_awaited_once_with()
            mock_container.hunter.stop.assert_not_awaited()
            mock_container.launch_watch.start.assert_awaited_once_with()
            mock_container.launch_watch.stop.assert_not_awaited()
            mock_container.shutdown.assert_not_awaited()

            response = client.get(
                "/api/agent/policy",
                params={"agent_id": "lifespan-agent"},
                headers={"X-API-Key": "test-lifespan-api-key"},
            )
            assert response.status_code == 200
            assert response.json() == {
                "agent_id": "lifespan-agent",
                "registered_by_key": "lifespan-key",
                "policy": {"auto_allow_below": 25},
            }
            mock_container.db.get_agent_policy.assert_awaited_once_with("lifespan-agent")

            response = client.get("/mcp/health")
            assert response.status_code == 200
            assert response.json() == {
                "status": "ok",
                "server": {"name": "shieldbot-mcp", "version": "3.1.0"},
                "active_sessions": 0,
                "max_sessions": 50,
            }

            response = client.get("/api/graph/stats")
            assert response.status_code == 200
            assert response.json() == {"total_edges": 3, "total_clusters": 1}
            mock_container.threat_graph.get_stats.assert_awaited_once_with()

            response = client.get("/api/reputation/leaderboard", params={"limit": 2})
            assert response.status_code == 200
            assert response.json() == [
                {"agent_id": "lifespan-agent", "composite_score": 90},
            ]
            mock_container.reputation_service.get_leaderboard.assert_awaited_once_with(2)

            response = client.get(f"/api/guardian/health/{wallet}", params={"chain_id": 1})
            assert response.status_code == 200
            assert response.json() == {"health_score": 90, "warnings": []}
            mock_container.guardian_service.get_health.assert_awaited_once_with(wallet, 1)

        mock_container.startup.assert_awaited_once_with()
        mock_container.hunter.start.assert_awaited_once_with()
        mock_container.hunter.stop.assert_awaited_once_with()
        mock_container.shutdown.assert_awaited_once_with()
        # The drain starts first and stops last: the watch and the hunter publish verdicts into it.
        loops = [
            call.verdict_publisher.start(),
            call.hunter.start(),
            call.launch_watch.start(),
            call.launch_watch.stop(),
            call.hunter.stop(),
            call.verdict_publisher.stop(),
        ]
        assert [made for made in mock_container.mock_calls if made in loops] == loops
