"""Tests for Threat Intelligence Graph service."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from services.threat_graph import ThreatGraphService


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.add_threat_graph_edge = AsyncMock()
    db.get_edges_from = AsyncMock(return_value=[])
    db.get_edges_to = AsyncMock(return_value=[])
    db.get_cluster_for_address = AsyncMock(return_value=None)
    db.get_cluster_members = AsyncMock(return_value=[])
    db.upsert_cluster_member = AsyncMock()
    db.get_graph_stats = AsyncMock(return_value={"total_edges": 0, "total_clusters": 0})
    db.get_top_clusters = AsyncMock(return_value=[])
    return db


@pytest.fixture
def graph(mock_db):
    return ThreatGraphService(db=mock_db)


@pytest.mark.asyncio
async def test_add_edge(graph, mock_db):
    await graph.add_edge("0xAAA", "0xBBB", 56, "deployed", confidence=0.9)
    mock_db.add_threat_graph_edge.assert_awaited_once()
    args = mock_db.add_threat_graph_edge.call_args
    assert args[1]["source"] == "0xaaa"  # lowercased
    assert args[1]["target"] == "0xbbb"
    assert args[1]["confidence"] == 0.9


@pytest.mark.asyncio
async def test_add_edge_clamps_confidence(graph, mock_db):
    await graph.add_edge("0xA", "0xB", 56, "funded", confidence=1.5)
    args = mock_db.add_threat_graph_edge.call_args
    assert args[1]["confidence"] == 1.0

    await graph.add_edge("0xA", "0xB", 56, "funded", confidence=-0.5)
    args = mock_db.add_threat_graph_edge.call_args
    assert args[1]["confidence"] == 0.0


@pytest.mark.asyncio
async def test_check_address_no_edges(graph, mock_db):
    result = await graph.check_address("0xAAA", chain_id=56)
    assert result["address"] == "0xaaa"
    assert result["connected_to_cluster"] is False
    assert result["edges_found"] == 0
    assert result["nodes_visited"] == 1


@pytest.mark.asyncio
async def test_check_address_with_edges(graph, mock_db):
    mock_db.get_edges_from.return_value = [
        {"source_address": "0xaaa", "target_address": "0xbbb", "relationship": "deployed"},
    ]
    result = await graph.check_address("0xAAA", chain_id=56)
    assert result["edges_found"] >= 1
    assert result["nodes_visited"] >= 2


@pytest.mark.asyncio
async def test_check_address_cluster_hit(graph, mock_db):
    mock_db.get_cluster_for_address.return_value = {
        "cluster_id": "C-12345",
        "address": "0xaaa",
        "chain_id": 56,
        "role": "deployer",
        "confidence": 0.8,
    }
    result = await graph.check_address("0xAAA", chain_id=56)
    assert result["connected_to_cluster"] is True
    assert len(result["clusters"]) == 1
    assert result["clusters"][0]["cluster_id"] == "C-12345"


@pytest.mark.asyncio
async def test_check_address_max_depth_capped(graph, mock_db):
    """Max depth should be capped at 5."""
    result = await graph.check_address("0xAAA", chain_id=56, max_depth=20)
    assert result["max_depth_reached"] == 5


@pytest.mark.asyncio
async def test_check_address_hot_cache(graph, mock_db):
    """Hot cache should short-circuit DB lookups."""
    cached_result = {
        "address": "0xaaa",
        "chain_id": 56,
        "connected_to_cluster": True,
        "from_cache": True,
    }
    graph._hot_cache["0xaaa:56"] = cached_result
    result = await graph.check_address("0xAAA", chain_id=56)
    assert result.get("from_cache") is True
    mock_db.get_edges_from.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_cluster_empty(graph, mock_db):
    result = await graph.get_cluster("C-999")
    assert result["size"] == 0
    assert result["members"] == []


@pytest.mark.asyncio
async def test_get_cluster_with_members(graph, mock_db):
    mock_db.get_cluster_members.return_value = [
        {"address": "0xa", "role": "deployer"},
        {"address": "0xb", "role": "member"},
        {"address": "0xc", "role": "member"},
    ]
    result = await graph.get_cluster("C-123")
    assert result["size"] == 3
    assert result["roles"]["deployer"] == 1
    assert result["roles"]["member"] == 2


@pytest.mark.asyncio
async def test_get_stats(graph, mock_db):
    mock_db.get_graph_stats.return_value = {"total_edges": 100, "total_clusters": 5}
    result = await graph.get_stats()
    assert result["total_edges"] == 100


@pytest.mark.asyncio
async def test_enrich_from_scan_deployer(graph, mock_db):
    scan_result = {"deployer": "0xDeployer", "risk_score": 80}
    await graph.enrich_from_scan("0xToken", 56, scan_result)
    # Should add deployed edge
    assert mock_db.add_threat_graph_edge.await_count >= 1


@pytest.mark.asyncio
async def test_enrich_from_scan_funder(graph, mock_db):
    scan_result = {"deployer": "0xDeployer", "funded_by": "0xFunder"}
    await graph.enrich_from_scan("0xToken", 56, scan_result)
    # Should add deployed + funded edges
    assert mock_db.add_threat_graph_edge.await_count >= 2


@pytest.mark.asyncio
async def test_enrich_from_scan_no_deployer(graph, mock_db):
    scan_result = {"risk_score": 50}
    await graph.enrich_from_scan("0xToken", 56, scan_result)
    mock_db.add_threat_graph_edge.assert_not_awaited()
