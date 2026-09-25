"""X-Policy-Mode: STRICT skips the score cache only for a caller with a valid API key. Anyone else is
answered from the cached facts in STRICT mode, which blocks on a failed required check, as a fresh scan
does, and on any Unknown in a row that does not name them."""

import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from core import verdicts
from core.analyzer import AnalyzerResult
from core.policy import PolicyEngine
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine
from utils.scam_db import ScamDatabase

UNKNOWN_ROW = {
    "risk_score": 20,
    "risk_level": "MEDIUM",
    "flags": ["Sellability unknown: honeypot.is timed out"],
    "archetype": "unknown",
    "confidence": 40,
    "scan_count": 3,
    "last_scanned_at": time.time(),
    "category_scores": {
        "honeypot": None,
        "_scan_metadata": {
            "status": "unknown",
            "coverage": {"honeypot": 0, "structural": 1},
            "coverage_reasons": {"honeypot": "honeypot.is timed out"},
            "risk_display": "Unknown (incomplete provider coverage)",
        },
    },
}
COMPLETE_ROW = {
    **UNKNOWN_ROW,
    "risk_level": "LOW",
    "flags": [],
    "category_scores": {
        "honeypot": 0,
        "_scan_metadata": {
            "status": "ok",
            "coverage": {"honeypot": 1, "structural": 1},
            "coverage_reasons": {},
            "risk_display": "20%",
        },
    },
}


@pytest.fixture
def strict_api(monkeypatch, mock_web3_client):
    import api

    mock_web3_client.is_token_contract = AsyncMock(return_value=True)
    services = SimpleNamespace(
        web3_client=mock_web3_client,
        db=SimpleNamespace(
            get_contract_score=AsyncMock(return_value=UNKNOWN_ROW),
            get_deployer_risk_summary=AsyncMock(return_value=None),
            upsert_contract_score=AsyncMock(),
        ),
        registry=SimpleNamespace(run_all=AsyncMock(return_value=[])),
        policy_engine=PolicyEngine(),
        indexer=None,
        counterparty_service=None,
    )
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", mock_web3_client)
    monkeypatch.setattr(api, "scam_db", ScamDatabase())
    monkeypatch.setattr(
        api,
        "calldata_decoder",
        SimpleNamespace(
            decode=lambda _: {"selector": None},
            is_whitelisted_target=lambda *args, **kwargs: None,
        ),
    )
    risk_engine = MagicMock()
    risk_engine.compute_from_results.return_value = {
        "rug_probability": 20,
        "risk_level": "LOW",
        "status": "ok",
        "coverage": {"honeypot": 1, "structural": 1},
        "coverage_reasons": {},
    }
    monkeypatch.setattr(api, "risk_engine", risk_engine)
    monkeypatch.setattr(api, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    monkeypatch.setattr(api, "greenfield_service", None)
    monkeypatch.setattr(api, "ai_analyzer", SimpleNamespace(is_available=lambda: False))
    return api, services


def _request(key_info=None):
    return SimpleNamespace(
        headers={"X-Policy-Mode": "STRICT"},
        state=SimpleNamespace(**({"api_key_info": key_info} if key_info else {})),
    )


async def _firewall(api, request):
    return await api.firewall(
        api.FirewallRequest(to="0x" + "a" * 40, sender="0x" + "b" * 40), request
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("server_mode, header", [("BALANCED", "STRICT"), ("STRICT", None)])
async def test_unauthenticated_strict_is_answered_from_the_cache_and_still_blocks_an_unknown(
    strict_api,
    server_mode,
    header,
):
    api, services = strict_api
    services.policy_engine = PolicyEngine(server_mode)
    request = _request()
    request.headers = {"X-Policy-Mode": header} if header else {}

    response = await _firewall(api, request)

    services.registry.run_all.assert_not_awaited()
    assert response["cached"] is True
    assert response["policy_mode"] == "STRICT"
    assert response["classification"] == "BLOCK_RECOMMENDED"
    assert response["risk_score"] >= 80
    assert response["status"] == "unknown"
    assert response["danger_signals"][0].startswith("Policy override")


@pytest.mark.asyncio
async def test_unauthenticated_strict_keeps_a_complete_cached_verdict(strict_api):
    api, services = strict_api
    services.db.get_contract_score.return_value = COMPLETE_ROW

    response = await _firewall(api, _request())

    services.registry.run_all.assert_not_awaited()
    assert (response["cached"], response["classification"], response["risk_score"]) == (
        True,
        "SAFE",
        20,
    )


@pytest.mark.asyncio
async def test_authenticated_strict_bypasses_the_cache(strict_api):
    api, services = strict_api

    response = await _firewall(api, _request({"key_id": "k1", "tier": "free"}))

    services.registry.run_all.assert_awaited_once()
    assert "cached" not in response


# Fully covered analyzer data; a test makes one field unknown.
COVERED = {
    "structural": {
        "is_contract": True,
        "is_verified": True,
        "contract_age_days": 400,
        "scam_matches": [],
        "coverage": {"is_verified": True, "contract_age_days": True, "scam_database": True},
    },
    "market": {"liquidity_usd": 50_000, "pair_age_hours": 100, "coverage": {"liquidity_usd": True, "pair_age_hours": True}},
    "behavioral": {"reputation_score": 50},
    "honeypot": {
        "is_honeypot": False,
        "can_sell": True,
        "buy_tax": 0,
        "sell_tax": 0,
        "coverage": {"is_honeypot": True, "can_sell": True, "buy_tax": True, "sell_tax": True},
    },
}
WEIGHTS = {"structural": 0.40, "market": 0.25, "behavioral": 0.20, "honeypot": 0.15}


def _registry(gap):
    """The four target analyzers, fully covered except the (analyzer, field) `gap`."""
    registry = AnalyzerRegistry()
    for name, weight in WEIGHTS.items():
        data = {**COVERED[name], "status": "ok"}
        if name == gap[0]:
            data = {**data, "coverage": {**data["coverage"], gap[1]: False}, "status": "unknown", gap[1]: None}
        analyzer = MagicMock()
        analyzer.name = name
        analyzer.weight = weight

        async def analyze(ctx, result=AnalyzerResult(name, weight, 0, data=data)):
            return result

        analyzer.analyze = analyze
        registry.register(analyzer)
    return registry


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "gap, blocked",
    [(("market", "pair_age_hours"), False), (("honeypot", "can_sell"), True)],
    ids=["informational-gap", "required-gap"],
)
async def test_strict_gives_a_cached_scan_the_answer_it_gave_the_fresh_one(strict_api, monkeypatch, gap, blocked):
    api, services = strict_api
    monkeypatch.setattr(api, "risk_engine", RiskEngine())
    services.registry = _registry(gap)
    services.db.get_contract_score.return_value = None

    fresh = await _firewall(api, _request())
    # The row the fresh scan wrote, as the database returns it.
    stored = services.db.upsert_contract_score.await_args.kwargs
    services.db.get_contract_score.return_value = {
        "risk_score": stored["risk_score"],
        "risk_level": stored["risk_level"],
        "flags": stored["flags"],
        "archetype": stored["archetype"],
        "confidence": stored["confidence"],
        "scan_count": 1,
        "last_scanned_at": time.time(),
        "category_scores": json.loads(json.dumps(stored["category_scores"])),
    }
    cached = await _firewall(api, _request())

    assert "cached" not in fresh and cached["cached"] is True
    assert fresh["status"] == cached["status"] == "unknown"
    for response in (fresh, cached):
        overridden = any(signal.startswith("Policy override") for signal in response["danger_signals"])
        assert (response["classification"] == verdicts.BLOCK_RECOMMENDED, overridden) == (blocked, blocked)
    assert fresh["classification"] == cached["classification"]
    assert fresh["risk_score"] == cached["risk_score"]
