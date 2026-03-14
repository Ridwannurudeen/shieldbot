"""Tests for agent.tools — thin service wrappers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.analyzer import AnalysisContext, AnalyzerResult


@pytest.fixture
def mock_container():
    """Build a mock container with the services AgentTools depends on."""
    registry = MagicMock()
    registry.run_all = AsyncMock(return_value=[
        AnalyzerResult(name="structural", weight=0.4, score=30, flags=["Contract not verified"]),
        AnalyzerResult(name="market", weight=0.25, score=10, flags=[]),
        AnalyzerResult(name="behavioral", weight=0.2, score=0, flags=[]),
        AnalyzerResult(name="honeypot", weight=0.15, score=0, flags=[]),
    ])

    risk_engine = MagicMock()
    risk_engine.compute_from_results = MagicMock(return_value={
        "rug_probability": 14.5,
        "risk_level": "LOW",
        "risk_archetype": "legitimate",
        "critical_flags": ["Contract not verified"],
        "confidence_level": 60,
        "category_scores": {"structural": 30, "market": 10, "behavioral": 0, "honeypot": 0},
    })

    db = MagicMock()
    db.get_deployer_risk_summary = AsyncMock(return_value={
        "deployer_address": "0xdead",
        "total_contracts": 5,
        "high_risk_contracts": 3,
    })
    db.get_campaign_graph = AsyncMock(return_value={
        "deployer": "0xdead",
        "contracts": [],
        "funder": "0xbeef",
    })
    db.get_agent_findings = AsyncMock(return_value=[
        {"id": 1, "finding_type": "honeypot", "severity": "HIGH"},
    ])
    db.add_watched_deployer = AsyncMock(return_value=None)
    db.get_contract_score = AsyncMock(return_value={
        "risk_score": 14.5,
        "risk_level": "LOW",
    })

    honeypot_service = MagicMock()
    honeypot_service.fetch_honeypot_data = AsyncMock(return_value={
        "is_honeypot": False,
        "sell_tax": 0,
        "buy_tax": 0,
        "can_sell": True,
    })

    dex_service = MagicMock()
    dex_service.fetch_token_market_data = AsyncMock(return_value={
        "liquidity_usd": 50000,
        "volume_24h": 12000,
    })

    return SimpleNamespace(
        registry=registry,
        risk_engine=risk_engine,
        db=db,
        honeypot_service=honeypot_service,
        dex_service=dex_service,
    )


@pytest.fixture
def tools(mock_container):
    from agent.tools import AgentTools
    return AgentTools(mock_container)


# --- scan_contract ---

@pytest.mark.asyncio
async def test_scan_contract(tools, mock_container):
    result = await tools.scan_contract("0xabc123")

    # Registry should be called with an AnalysisContext
    mock_container.registry.run_all.assert_awaited_once()
    ctx_arg = mock_container.registry.run_all.call_args[0][0]
    assert isinstance(ctx_arg, AnalysisContext)
    assert ctx_arg.address == "0xabc123"
    assert ctx_arg.chain_id == 56

    # Risk engine should be called with the registry results
    mock_container.risk_engine.compute_from_results.assert_called_once()
    assert result["risk_level"] == "LOW"
    assert result["rug_probability"] == 14.5


@pytest.mark.asyncio
async def test_scan_contract_custom_chain(tools, mock_container):
    await tools.scan_contract("0xabc123", chain_id=1)
    ctx_arg = mock_container.registry.run_all.call_args[0][0]
    assert ctx_arg.chain_id == 1


# --- check_deployer ---

@pytest.mark.asyncio
async def test_check_deployer(tools, mock_container):
    result = await tools.check_deployer("0xabc123")
    mock_container.db.get_deployer_risk_summary.assert_awaited_once_with("0xabc123", 56)
    assert result["high_risk_contracts"] == 3


# --- check_honeypot ---

@pytest.mark.asyncio
async def test_check_honeypot(tools, mock_container):
    result = await tools.check_honeypot("0xabc123")
    mock_container.honeypot_service.fetch_honeypot_data.assert_awaited_once_with("0xabc123")
    assert result["is_honeypot"] is False


# --- get_market_data ---

@pytest.mark.asyncio
async def test_get_market_data(tools, mock_container):
    result = await tools.get_market_data("0xabc123")
    mock_container.dex_service.fetch_token_market_data.assert_awaited_once_with("0xabc123")
    assert result["liquidity_usd"] == 50000


# --- query_campaign ---

@pytest.mark.asyncio
async def test_query_campaign(tools, mock_container):
    result = await tools.query_campaign("0xabc123", chain_id=56)
    mock_container.db.get_campaign_graph.assert_awaited_once_with("0xabc123", 56)
    assert result["funder"] == "0xbeef"


# --- get_funder_links ---

@pytest.mark.asyncio
async def test_get_funder_links(tools, mock_container):
    result = await tools.get_funder_links("0xdead")
    mock_container.db.get_campaign_graph.assert_awaited_once_with("0xdead", None)
    assert "funder" in result


# --- get_agent_findings ---

@pytest.mark.asyncio
async def test_get_agent_findings(tools, mock_container):
    result = await tools.get_agent_findings(limit=5, finding_type="honeypot")
    mock_container.db.get_agent_findings.assert_awaited_once_with(5, "honeypot")
    assert len(result) == 1
    assert result[0]["finding_type"] == "honeypot"


# --- auto_watch_deployer ---

@pytest.mark.asyncio
async def test_auto_watch_deployer(tools, mock_container):
    await tools.auto_watch_deployer("0xbad", reason="serial rugger", chain_id=56)
    mock_container.db.add_watched_deployer.assert_awaited_once_with("0xbad", 56, "serial rugger")


# --- get_cached_score ---

@pytest.mark.asyncio
async def test_get_cached_score(tools, mock_container):
    result = await tools.get_cached_score("0xabc123")
    mock_container.db.get_contract_score.assert_awaited_once_with("0xabc123", 56)
    assert result["risk_level"] == "LOW"
