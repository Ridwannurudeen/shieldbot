"""On /api/firewall and the router-swap path, a community report never turns into a BLOCK: not with a
routine simulation revert, and not with the deployer campaign boost."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from analyzers.structural import StructuralAnalyzer
from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine


COMMUNITY = {
    "type": "community_reports",
    "reason": "Reported by 3 users",
    "source": "ShieldBot",
    "severity": "medium",
    "reports": 3,
}
GOPLUS_HIGH = {
    "type": "GoPlus Security",
    "reason": "Honeypot (GoPlus)",
    "source": "gopluslabs.io",
    "severity": "high",
}
CONTRACT = {
    "is_contract": True,
    "is_verified": True,
    "contract_age_days": 400,
    "ownership_renounced": None,
}
WEIGHTS = {
    "structural": 0.32,
    "market": 0.20,
    "behavioral": 0.16,
    "honeypot": 0.12,
    "intent": 0.12,
    "signature": 0.08,
}
REVERT = {"success": False, "revert_reason": "PancakeRouter: EXPIRED"}
TOKEN = "0x" + "c" * 40


def _results(scam_matches, market=0, behavioral=0, honeypot=0, renounced=None, liquidity=50000):
    contract = {**CONTRACT, "ownership_renounced": renounced, "scam_matches": scam_matches}
    structural, flags = StructuralAnalyzer(None)._compute(contract, {})
    return [
        AnalyzerResult("structural", WEIGHTS["structural"], structural, flags=flags, data=contract),
        AnalyzerResult(
            "market", WEIGHTS["market"], market, data={"liquidity_usd": liquidity, "pair_age_hours": 100}
        ),
        AnalyzerResult("behavioral", WEIGHTS["behavioral"], behavioral, data={"reputation_score": 80}),
        AnalyzerResult(
            "honeypot",
            WEIGHTS["honeypot"],
            honeypot,
            data={
                "is_honeypot": False,
                "can_buy": True,
                "can_sell": True,
                "buy_tax": 0,
                "sell_tax": 0,
            },
        ),
        AnalyzerResult("intent", WEIGHTS["intent"], 0, data={"status": "ok"}),
        AnalyzerResult("signature", WEIGHTS["signature"], 0, data={"has_typed_data": False}),
    ]


@pytest.fixture
def firewall(monkeypatch, mock_web3_client):
    import api

    mock_web3_client.is_token_contract = AsyncMock(return_value=True)
    mock_web3_client.is_verified_contract.return_value = (True, None)
    db = SimpleNamespace(
        get_contract_score=AsyncMock(return_value=None),
        get_deployer_risk_summary=AsyncMock(return_value=None),
        upsert_contract_score=AsyncMock(),
        is_watched_deployer=AsyncMock(return_value=True),
    )
    services = SimpleNamespace(
        web3_client=mock_web3_client,
        db=db,
        registry=SimpleNamespace(run_all=AsyncMock()),
        policy_engine=None,
        indexer=None,
        counterparty_service=None,
        settings=SimpleNamespace(policy_mode="BALANCED", reporter_hash_secret=""),
    )
    simulator = SimpleNamespace(
        is_enabled=lambda: True, simulate_transaction=AsyncMock(return_value=REVERT)
    )
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", mock_web3_client)
    monkeypatch.setattr(
        api,
        "calldata_decoder",
        SimpleNamespace(
            decode=lambda _: {"selector": None},
            is_whitelisted_target=lambda *args, **kwargs: None,
        ),
    )
    monkeypatch.setattr(api, "risk_engine", RiskEngine())
    monkeypatch.setattr(api, "tenderly_simulator", simulator)
    monkeypatch.setattr(api, "greenfield_service", None)
    monkeypatch.setattr(api, "ai_analyzer", SimpleNamespace(is_available=lambda: False))
    return api, services, simulator


async def _call(api, surface):
    req = api.FirewallRequest(to="0x" + "a" * 40, sender="0x" + "b" * 40)
    if surface == "firewall":
        return await api.firewall(req, SimpleNamespace(headers={}))
    return await api._analyze_router_swap(
        req, req.to, req.sender, {"params": {"path": [TOKEN]}}, "Router", 0
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["firewall", "swap"])
async def test_a_routine_revert_does_not_turn_a_community_report_into_a_block(firewall, surface):
    api, services, _ = firewall
    services.registry.run_all.return_value = _results([COMMUNITY])
    response = await _call(api, surface)
    assert response["risk_score"] == 40
    assert response["classification"] != "BLOCK_RECOMMENDED"
    assert "Simulation reverted: PancakeRouter: EXPIRED" in response["danger_signals"]
    assert "Reported by 3 users" in response["danger_signals"]


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["firewall", "swap"])
@pytest.mark.parametrize("matches", [[GOPLUS_HIGH], [GOPLUS_HIGH, COMMUNITY]])
async def test_a_revert_still_blocks_a_scam_database_match(firewall, surface, matches):
    api, services, _ = firewall
    services.registry.run_all.return_value = _results(matches)
    response = await _call(api, surface)
    assert response["risk_score"] == 70
    assert response["classification"] == "BLOCK_RECOMMENDED"


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["firewall", "swap"])
@pytest.mark.parametrize("matches", [[], [COMMUNITY]])
async def test_a_community_report_does_not_mask_a_revert_on_a_risky_target(firewall, surface, matches):
    api, services, _ = firewall
    # The target scores 35 on its own: 20 market, 3 behavioral and 12 honeypot points.
    services.registry.run_all.return_value = _results(matches, market=100, behavioral=18.75, honeypot=100)
    response = await _call(api, surface)
    assert response["risk_score"] == (40 if matches else 35)
    assert response["classification"] == "BLOCK_RECOMMENDED"


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["firewall", "swap"])
async def test_a_community_report_does_not_cause_a_revert_block_by_withholding_the_discount(firewall, surface):
    api, services, _ = firewall
    # 32 points on their own, less the 20-point discount for renounced ownership and deep liquidity: 12.
    services.registry.run_all.return_value = _results(
        [COMMUNITY], market=100, honeypot=100, renounced=True, liquidity=5_000_000
    )
    response = await _call(api, surface)
    assert response["risk_score"] == 40
    assert response["classification"] != "BLOCK_RECOMMENDED"


@pytest.mark.asyncio
async def test_a_campaign_boost_on_a_community_report_is_high_risk_not_block(firewall):
    api, services, simulator = firewall
    simulator.simulate_transaction.return_value = {"success": True}
    services.registry.run_all.return_value = _results([COMMUNITY])
    services.db.get_deployer_risk_summary.return_value = {
        "deployer_address": "0x" + "d" * 40,
        "total_contracts": 6,
        "high_risk_contracts": 4,
    }
    response = await _call(api, "firewall")
    assert response["risk_score"] == 65
    assert response["classification"] == "HIGH_RISK"
