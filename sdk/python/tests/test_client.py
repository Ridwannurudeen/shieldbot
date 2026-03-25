"""Tests for the ShieldBot Python SDK client."""

import pytest
import json
import httpx
from unittest.mock import AsyncMock, patch, MagicMock
from shieldbot.client import ShieldBot, ShieldBotError
from shieldbot.models import Verdict


@pytest.fixture
def sb():
    return ShieldBot(api_key="sb_test", agent_id="agent:1", base_url="http://localhost:8000")


@pytest.mark.asyncio
async def test_check_returns_verdict(sb):
    """check() returns a Verdict object."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "verdict": "ALLOW", "score": 12, "flags": [],
        "policy_check": {"passed": True, "checks": {}, "failed": [], "needs_owner_approval": False},
        "cached": False, "latency_ms": 100,
    }
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        verdict = await sb.check({
            "from": "0xAgent", "to": "0xTarget", "chain_id": 56,
        })
    assert isinstance(verdict, Verdict)
    assert verdict.allowed is True
    assert verdict.score == 12
    assert verdict.verdict == "ALLOW"


@pytest.mark.asyncio
async def test_check_block_verdict(sb):
    """BLOCK verdict sets allowed=False."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "verdict": "BLOCK", "score": 91, "flags": ["honeypot"],
        "policy_check": {"passed": False, "checks": {}, "failed": ["risk_threshold"], "needs_owner_approval": False},
        "cached": False, "latency_ms": 380,
    }
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        verdict = await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert verdict.allowed is False
    assert verdict.blocked is True
    assert "honeypot" in verdict.flags


@pytest.mark.asyncio
async def test_local_cache_hit(sb):
    """Second check for same address uses local cache."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "verdict": "ALLOW", "score": 5, "flags": [],
        "policy_check": {"passed": True, "checks": {}, "failed": [], "needs_owner_approval": False},
        "cached": False, "latency_ms": 100,
    }
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp) as mock_post:
        await sb.check({"from": "0xA", "to": "0xSame", "chain_id": 56})
        v2 = await sb.check({"from": "0xA", "to": "0xSame", "chain_id": 56})
    # Only 1 HTTP call — second was cached
    assert mock_post.call_count == 1
    assert v2.score == 5


def test_verdict_properties():
    """Verdict model properties work correctly."""
    v = Verdict(verdict="ALLOW", score=12, flags=[], evidence=None,
                policy_check={}, cached=False, latency_ms=100)
    assert v.allowed is True
    assert v.blocked is False

    v2 = Verdict(verdict="BLOCK", score=91, flags=["honeypot"], evidence="scam",
                 policy_check={}, cached=False, latency_ms=380)
    assert v2.allowed is False
    assert v2.blocked is True


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,label", [
    (401, "unauthorized"),
    (403, "forbidden"),
    (404, "not found"),
    (429, "rate limited"),
])
async def test_4xx_raises_shieldbot_error(sb, status_code, label):
    """4xx errors raise ShieldBotError instead of returning a fail-mode verdict."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = label
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        with pytest.raises(ShieldBotError) as exc_info:
            await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert exc_info.value.status_code == status_code
    assert label in exc_info.value.message


@pytest.mark.asyncio
async def test_500_uses_fail_mode(sb):
    """5xx server errors use fail-mode (ALLOW for default cached/open) instead of raising."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        verdict = await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert isinstance(verdict, Verdict)
    assert verdict.verdict == "ALLOW"
    assert "api_unavailable" in verdict.flags


@pytest.mark.asyncio
async def test_500_fail_closed():
    """5xx with fail_mode='closed' returns BLOCK verdict."""
    client = ShieldBot(api_key="sb_test", agent_id="agent:1",
                       base_url="http://localhost:8000", fail_mode="closed")
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_resp.text = "Bad Gateway"
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        verdict = await client.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert verdict.verdict == "BLOCK"
    assert "api_unavailable" in verdict.flags


@pytest.mark.asyncio
async def test_network_error_uses_fail_mode(sb):
    """Network errors (connection refused, DNS failure) use fail-mode."""
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock,
               side_effect=httpx.ConnectError("Connection refused")):
        verdict = await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert isinstance(verdict, Verdict)
    assert verdict.verdict == "ALLOW"
    assert "api_unavailable" in verdict.flags


@pytest.mark.asyncio
async def test_shieldbot_error_exported():
    """ShieldBotError is importable from the top-level package."""
    from shieldbot import ShieldBotError as SBE
    err = SBE(401, "bad key")
    assert err.status_code == 401
    assert "bad key" in str(err)
