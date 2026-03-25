"""Tests for Premium Tier Service (token gating)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from services.tier_service import (
    TierService, TIER_RATE_LIMITS, TIER_FEATURES, TIER_THRESHOLDS,
)


@pytest.fixture
def tier_service():
    """TierService without RPC (disabled mode)."""
    return TierService(rpc_url="")


@pytest.mark.asyncio
async def test_disabled_without_rpc(tier_service):
    assert tier_service.is_enabled() is False


@pytest.mark.asyncio
async def test_resolve_tier_enterprise_never_overridden(tier_service):
    result = await tier_service.resolve_tier({"tier": "enterprise", "owner": ""})
    assert result == "enterprise"


@pytest.mark.asyncio
async def test_resolve_tier_defaults_to_free(tier_service):
    result = await tier_service.resolve_tier({})
    assert result == "free"


@pytest.mark.asyncio
async def test_resolve_tier_uses_db_tier(tier_service):
    result = await tier_service.resolve_tier({"tier": "pro"})
    assert result == "pro"


@pytest.mark.asyncio
async def test_rate_limit_free(tier_service):
    assert tier_service.get_rate_limit("free") == 30


@pytest.mark.asyncio
async def test_rate_limit_agent(tier_service):
    assert tier_service.get_rate_limit("agent") == 500


@pytest.mark.asyncio
async def test_rate_limit_unknown_defaults_to_free(tier_service):
    assert tier_service.get_rate_limit("unknown") == 30


@pytest.mark.asyncio
async def test_has_feature_free_scan(tier_service):
    assert tier_service.has_feature("free", "scan") is True


@pytest.mark.asyncio
async def test_has_feature_free_no_agent_firewall(tier_service):
    assert tier_service.has_feature("free", "agent_firewall") is False


@pytest.mark.asyncio
async def test_has_feature_agent_tier(tier_service):
    assert tier_service.has_feature("agent", "agent_firewall") is True
    assert tier_service.has_feature("agent", "anomaly_detection") is True
    assert tier_service.has_feature("agent", "sdk_access") is True


@pytest.mark.asyncio
async def test_has_feature_enterprise_all(tier_service):
    assert tier_service.has_feature("enterprise", "anything_at_all") is True


@pytest.mark.asyncio
async def test_has_feature_unknown_tier_defaults_free(tier_service):
    assert tier_service.has_feature("nonexistent", "scan") is True
    assert tier_service.has_feature("nonexistent", "agent_firewall") is False


@pytest.mark.asyncio
async def test_get_token_balance_disabled(tier_service):
    balance = await tier_service.get_token_balance("0x1234567890abcdef1234567890abcdef12345678")
    assert balance == 0


@pytest.mark.asyncio
async def test_get_token_balance_invalid_address(tier_service):
    balance = await tier_service.get_token_balance("not-an-address")
    assert balance == 0


@pytest.mark.asyncio
async def test_thresholds_pro_less_than_agent():
    assert TIER_THRESHOLDS["pro"] < TIER_THRESHOLDS["agent"]


@pytest.mark.asyncio
async def test_rate_limits_increase_with_tier():
    assert TIER_RATE_LIMITS["free"] < TIER_RATE_LIMITS["pro"]
    assert TIER_RATE_LIMITS["pro"] < TIER_RATE_LIMITS["agent"]
    assert TIER_RATE_LIMITS["agent"] < TIER_RATE_LIMITS["enterprise"]
