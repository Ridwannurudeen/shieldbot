"""Tests for Composite Trust Scoring (Reputation Service)."""

import time
import pytest
from unittest.mock import AsyncMock, MagicMock

from services.reputation import ReputationService


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.get_reputation_cache = AsyncMock(return_value=None)
    db.upsert_reputation_cache = AsyncMock()
    db.get_reputation_cache_by_registry = AsyncMock(return_value=None)
    db.get_agent_firewall_history = AsyncMock(return_value=[])
    db.get_agent_policy = AsyncMock(return_value=None)
    db.get_reputation_leaderboard = AsyncMock(return_value=[])
    db.invalidate_reputation_cache = AsyncMock()
    return db


@pytest.fixture
def reputation(mock_db):
    return ReputationService(db=mock_db)


@pytest.mark.asyncio
async def test_weights_sum_to_one():
    total = sum(ReputationService.WEIGHTS.values())
    assert abs(total - 1.0) < 0.001


@pytest.mark.asyncio
async def test_new_agent_gets_neutral_score(reputation, mock_db):
    """New agent with no history should get ~50 composite (all sources neutral)."""
    result = await reputation.get_trust_score("new-agent")
    assert result["agent_id"] == "new-agent"
    # All sources return 50.0 (neutral), so composite = 50.0
    assert result["composite_score"] == 50.0
    assert result["breakdown"]["shieldbot"] == 50.0
    assert result["breakdown"]["erc8004"] == 50.0
    assert result["verified"] is False
    mock_db.upsert_reputation_cache.assert_awaited_once()


@pytest.mark.asyncio
async def test_cached_score_returned(reputation, mock_db):
    """Cached score within TTL should be returned directly."""
    cached = {
        "agent_id": "cached-agent",
        "composite_score": 85.0,
        "last_fetched": time.time(),  # Fresh cache
    }
    mock_db.get_reputation_cache.return_value = cached
    result = await reputation.get_trust_score("cached-agent")
    assert result["composite_score"] == 85.0
    # Should NOT recalculate (no upsert call)
    mock_db.upsert_reputation_cache.assert_not_awaited()


@pytest.mark.asyncio
async def test_expired_cache_triggers_recalculation(reputation, mock_db):
    """Expired cache should trigger full recalculation."""
    cached = {
        "agent_id": "stale-agent",
        "composite_score": 60.0,
        "last_fetched": time.time() - 7200,  # 2h ago, past 1h TTL
    }
    mock_db.get_reputation_cache.return_value = cached
    result = await reputation.get_trust_score("stale-agent")
    # Should recalculate and upsert
    mock_db.upsert_reputation_cache.assert_awaited_once()


@pytest.mark.asyncio
async def test_shieldbot_score_all_allowed(reputation, mock_db):
    """Agent with all ALLOW verdicts should get high ShieldBot score."""
    history = [{"verdict": "ALLOW", "created_at": time.time() - i * 60} for i in range(20)]
    mock_db.get_agent_firewall_history.return_value = history
    result = await reputation.get_trust_score("good-agent")
    # 100% allow ratio → base_score=100, block_penalty=0, clean_bonus=10 → capped at 100
    assert result["breakdown"]["shieldbot"] == 100.0


@pytest.mark.asyncio
async def test_shieldbot_score_with_blocks(reputation, mock_db):
    """Agent with some blocks should get penalized."""
    history = [
        {"verdict": "ALLOW", "created_at": time.time() - i * 60} for i in range(15)
    ] + [
        {"verdict": "BLOCK", "created_at": time.time() - i * 60} for i in range(5)
    ]
    mock_db.get_agent_firewall_history.return_value = history
    result = await reputation.get_trust_score("mixed-agent")
    # 75% allow, 25% block → base=75, penalty=12.5, no clean bonus → ~62.5
    assert result["breakdown"]["shieldbot"] < 70
    assert result["breakdown"]["shieldbot"] > 50


@pytest.mark.asyncio
async def test_verdict_summary(reputation, mock_db):
    """Verdict summary should count correctly."""
    history = [
        {"verdict": "ALLOW", "created_at": time.time()},
        {"verdict": "ALLOW", "created_at": time.time()},
        {"verdict": "BLOCK", "created_at": time.time()},
        {"verdict": "WARN", "created_at": time.time()},
    ]
    mock_db.get_agent_firewall_history.return_value = history
    result = await reputation.get_trust_score("test-agent")
    summary = result["verdict_summary"]
    assert summary["total"] == 4
    assert summary["allowed"] == 2
    assert summary["blocked"] == 1
    assert summary["warned"] == 1


@pytest.mark.asyncio
async def test_batch_lookup(reputation, mock_db):
    """Batch lookup should return results for each agent."""
    results = await reputation.batch_lookup(["a1", "a2", "a3"])
    assert len(results) == 3
    assert results[0]["agent_id"] == "a1"
    assert results[2]["agent_id"] == "a3"


@pytest.mark.asyncio
async def test_batch_lookup_max_100(reputation, mock_db):
    """Batch should be capped at 100."""
    ids = [f"agent-{i}" for i in range(150)]
    results = await reputation.batch_lookup(ids)
    assert len(results) == 100


@pytest.mark.asyncio
async def test_get_leaderboard(reputation, mock_db):
    """Leaderboard should delegate to DB."""
    mock_db.get_reputation_leaderboard.return_value = [
        {"agent_id": "top1", "composite_score": 95.0},
    ]
    results = await reputation.get_leaderboard(limit=10)
    assert len(results) == 1
    mock_db.get_reputation_leaderboard.assert_awaited_once_with(10)


@pytest.mark.asyncio
async def test_update_from_verdict_invalidates_cache(reputation, mock_db):
    """Verdict update should invalidate the cache."""
    await reputation.update_from_verdict("agent-1", "ALLOW", 10.0)
    mock_db.invalidate_reputation_cache.assert_awaited_once_with("agent-1")


@pytest.mark.asyncio
async def test_score_history_empty(reputation, mock_db):
    """Empty history should return empty list."""
    result = await reputation.get_score_history("agent-1", days=30)
    assert result == []


@pytest.mark.asyncio
async def test_score_history_groups_by_day(reputation, mock_db):
    """History entries should be grouped by day."""
    now = time.time()
    day_boundary = int(now // 86400) * 86400
    history = [
        {"verdict": "ALLOW", "created_at": day_boundary + 100},
        {"verdict": "ALLOW", "created_at": day_boundary + 200},
        {"verdict": "BLOCK", "created_at": day_boundary + 300},
    ]
    mock_db.get_agent_firewall_history.return_value = history
    result = await reputation.get_score_history("agent-1", days=1)
    assert len(result) == 1
    assert result[0]["verdicts"]["total"] == 3
    assert result[0]["verdicts"]["allowed"] == 2
    assert result[0]["verdicts"]["blocked"] == 1
