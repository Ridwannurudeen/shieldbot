"""Tests for threat graph seed endpoint and auto-enrichment."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture
def mock_container():
    c = MagicMock()
    c.settings = MagicMock()
    c.settings.admin_secret = "test_admin_secret"

    c.db = MagicMock()
    c.db.get_all_scored_contracts = AsyncMock(return_value=[
        {
            "address": "0xaaa", "chain_id": 56, "risk_score": 85,
            "risk_level": "HIGH", "flags": ["honeypot"], "deployer": "0xddd",
        },
        {
            "address": "0xbbb", "chain_id": 56, "risk_score": 72,
            "risk_level": "HIGH", "flags": ["rug_pull"],
        },
    ])

    c.auth_manager = MagicMock()
    c.auth_manager.validate_key = AsyncMock(return_value={"key_id": "k1"})

    c.threat_graph = MagicMock()
    c.threat_graph.enrich_from_scan = AsyncMock()
    c.threat_graph.analyze_clusters = AsyncMock()
    c.threat_graph.refresh_hot_cache = AsyncMock()
    c.threat_graph.check_address = AsyncMock(return_value={
        "address": "0xaaa", "connected_to_cluster": False,
        "clusters": [], "edges_found": 0,
    })
    c.threat_graph.get_cluster = AsyncMock(return_value={"cluster_id": "C-1", "size": 0})
    c.threat_graph.get_stats = AsyncMock(return_value={
        "total_edges": 5, "total_clusters": 2,
    })
    c.threat_graph.search = AsyncMock(return_value=[])
    return c


@pytest.fixture
def client(mock_container):
    from services.threat_graph_router import create_threat_graph_router
    from fastapi import FastAPI

    app = FastAPI()
    router = create_threat_graph_router(mock_container)
    app.include_router(router, prefix="/api/graph")
    return TestClient(app)


def test_seed_graph_success(client, mock_container):
    """Seed endpoint enriches scored contracts and rebuilds clusters."""
    resp = client.post(
        "/api/graph/seed?min_risk_score=50&limit=100",
        headers={"X-Admin-Secret": "test_admin_secret"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["seeded"] == 2
    assert body["total_candidates"] == 2
    assert mock_container.threat_graph.enrich_from_scan.await_count == 2
    mock_container.threat_graph.analyze_clusters.assert_awaited_once()
    mock_container.threat_graph.refresh_hot_cache.assert_awaited_once()


def test_seed_graph_no_admin_secret(client):
    """Seed without admin secret returns 401."""
    resp = client.post("/api/graph/seed")
    assert resp.status_code == 401


def test_seed_graph_wrong_secret(client):
    """Seed with wrong admin secret returns 403."""
    resp = client.post(
        "/api/graph/seed",
        headers={"X-Admin-Secret": "wrong_secret"},
    )
    assert resp.status_code == 403


def test_seed_graph_enrichment_failure_nonfatal(client, mock_container):
    """Enrichment failure for one contract doesn't stop the seed."""
    call_count = 0

    async def flaky_enrich(address, chain_id, scan_result):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("DB write failed")

    mock_container.threat_graph.enrich_from_scan = flaky_enrich
    resp = client.post(
        "/api/graph/seed",
        headers={"X-Admin-Secret": "test_admin_secret"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["seeded"] == 1  # Only second one succeeded


def test_stats_returns_graph_info(client, mock_container):
    """Stats endpoint returns graph statistics."""
    resp = client.get("/api/graph/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert "total_edges" in body
