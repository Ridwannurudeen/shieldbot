"""Tests for the Redis-backed CacheService."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def mock_redis():
    """Return a mock redis.asyncio.Redis instance."""
    r = AsyncMock()
    r.ping = AsyncMock(return_value=True)
    r.get = AsyncMock(return_value=None)
    r.set = AsyncMock(return_value=True)
    r.incr = AsyncMock(return_value=1)
    r.expire = AsyncMock(return_value=True)
    r.close = AsyncMock()
    return r


@pytest.fixture
def cache_service(mock_redis):
    """CacheService wired to a mock Redis connection."""
    from services.cache import CacheService

    svc = CacheService(redis_url="redis://localhost:6379/0", ttl=300)
    svc._redis = mock_redis
    svc._available = True
    return svc


@pytest.mark.asyncio
async def test_get_verdict_cache_miss(cache_service, mock_redis):
    """Cache miss returns None."""
    mock_redis.get.return_value = None

    result = await cache_service.get_verdict(
        "0xabc123", chain_id=56
    )

    assert result is None
    mock_redis.get.assert_awaited_once_with("verdict:0xabc123:56")


@pytest.mark.asyncio
async def test_get_verdict_cache_hit(cache_service, mock_redis):
    """Cache hit returns the stored dict."""
    verdict = {"risk_score": 85, "risk_level": "HIGH"}
    mock_redis.get.return_value = json.dumps(verdict).encode()

    result = await cache_service.get_verdict(
        "0xabc123", chain_id=56
    )

    assert result == verdict
    mock_redis.get.assert_awaited_once_with("verdict:0xabc123:56")


@pytest.mark.asyncio
async def test_set_verdict(cache_service, mock_redis):
    """set_verdict stores JSON with a TTL."""
    verdict = {"risk_score": 30, "risk_level": "LOW"}

    await cache_service.set_verdict(
        "0xdef456", chain_id=1, verdict=verdict, ttl=120
    )

    expected_key = "verdict:0xdef456:1"
    expected_value = json.dumps(verdict)
    mock_redis.set.assert_awaited_once_with(expected_key, expected_value, ex=120)


@pytest.mark.asyncio
async def test_set_verdict_default_ttl(cache_service, mock_redis):
    """set_verdict uses the instance default TTL when none is provided."""
    verdict = {"risk_score": 50, "risk_level": "MEDIUM"}

    await cache_service.set_verdict("0xdef456", chain_id=56, verdict=verdict)

    expected_key = "verdict:0xdef456:56"
    expected_value = json.dumps(verdict)
    mock_redis.set.assert_awaited_once_with(expected_key, expected_value, ex=300)


@pytest.mark.asyncio
async def test_cache_disabled_returns_none():
    """When Redis is unavailable the cache degrades to no-op."""
    from services.cache import CacheService

    svc = CacheService(redis_url="redis://localhost:6379/0")
    # _available defaults to False (no connect() called)
    assert svc._available is False

    result = await svc.get_verdict("0xabc123", chain_id=56)
    assert result is None

    # set_verdict should also be a silent no-op
    await svc.set_verdict("0xabc123", chain_id=56, verdict={"risk_score": 10})


@pytest.mark.asyncio
async def test_rate_limit_check(cache_service, mock_redis):
    """Increments counter and returns True when under limit."""
    mock_redis.incr.return_value = 1

    allowed = await cache_service.check_rate_limit(
        key="agent:0xabc", limit=10, window=60
    )

    assert allowed is True
    mock_redis.incr.assert_awaited_once_with("ratelimit:agent:0xabc")
    mock_redis.expire.assert_awaited_once_with("ratelimit:agent:0xabc", 60)


@pytest.mark.asyncio
async def test_rate_limit_exceeded(cache_service, mock_redis):
    """Returns False when the counter exceeds the limit."""
    mock_redis.incr.return_value = 11

    allowed = await cache_service.check_rate_limit(
        key="agent:0xabc", limit=10, window=60
    )

    assert allowed is False
