"""Offline coverage and unavailable-analysis regressions for the Python SDK."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from shieldbot.client import ShieldBot
from shieldbot.models import Verdict


@pytest.mark.asyncio
@pytest.mark.parametrize("reason,fraction", [("Provider unavailable", 0), ("Simulation failed", 0.8)])
async def test_incomplete_verdict_preserves_metadata_in_cache(reason, fraction):
    client = ShieldBot(api_key="test", agent_id="agent:1")
    payload = {
        "verdict": "ALLOW", "score": 0, "risk_level": "UNKNOWN",
        "status": "unknown", "coverage": {"honeypot": fraction},
        "coverage_reasons": {"honeypot": reason}, "category_scores": {"honeypot": None},
        "risk_display": "Unknown (incomplete provider coverage)", "confidence": 20,
    }
    response = MagicMock(status_code=200)
    response.json.return_value = payload
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response) as post:
        fresh = await client.check({"to": "0xtarget"})
        cached = await client.check({"to": "0xtarget"})
    assert post.await_count == 1
    for verdict in [fresh, cached]:
        assert not verdict.allowed
        assert verdict.verdict != "ALLOW"
        assert verdict.status == "unknown"
        assert verdict.coverage == payload["coverage"]
        assert verdict.coverage_reasons == payload["coverage_reasons"]
        assert verdict.category_scores == {"honeypot": None}
        assert verdict.risk_level == "UNKNOWN"
        assert verdict.confidence == 20
        assert "Unknown" in verdict.risk_display
        assert verdict.analysis_unavailable is False
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_mode,allowed", [("open", True), ("cached", True), ("closed", False)])
async def test_unavailable_decision_is_explicit(fail_mode, allowed):
    client = ShieldBot(api_key="test", agent_id="agent:1", fail_mode=fail_mode)
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=httpx.ConnectError("offline")):
        result = await client.check({"to": "0xtarget"})
    assert result.allowed is allowed
    assert result.analysis_unavailable is True
    assert result.status == "unknown"
    assert result.risk_display == "Unknown (analysis unavailable)"
    await client.close()


def test_unknown_model_never_allows_without_explicit_fail_open():
    result = Verdict(verdict="ALLOW", score=0, status="unknown", risk_level="UNKNOWN", category_scores={"honeypot": None})
    assert result.verdict != "ALLOW"
    assert not result.allowed
    assert result.risk_display == "Unknown (incomplete provider coverage)"


def test_complete_model_still_allows():
    result = Verdict(verdict="ALLOW", score=5, status="ok", coverage={"honeypot": 1})
    assert result.allowed
    assert result.risk_display == "5%"


def test_explicit_unknown_overrides_ok_status():
    result = Verdict(verdict="ALLOW", score=0, status="ok", coverage={"honeypot": 1}, risk_level="UNKNOWN")
    assert result.verdict != "ALLOW"
    assert result.status == "unknown"
    assert "Unknown" in result.risk_display


@pytest.mark.asyncio
async def test_server_cannot_mark_incomplete_allow_as_unavailable_analysis():
    client = ShieldBot(api_key="test", agent_id="agent:1")
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "verdict": "ALLOW", "score": 0, "status": "unknown", "coverage": {"honeypot": 0},
        "analysis_unavailable": True,
    }
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response):
        result = await client.check({"to": "0xtarget"})
    assert not result.allowed
    assert result.analysis_unavailable is False
    await client.close()
