"""An unknown ownership lookup must never be labelled a rug pull."""

import pytest

from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine


MARKET = {"liquidity_usd": 50000, "pair_age_hours": 100, "fdv": 200000, "volume_24h": 2000}
HONEYPOT = {"is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0}
ETHOS = {"reputation_score": 80}


def _risk(entrypoint, ownership_renounced):
    contract = {
        "is_contract": True,
        "is_verified": True,
        "contract_age_days": 400,
        "has_mint": True,
        "has_proxy": True,
        "ownership_renounced": ownership_renounced,
    }
    # Mirrors analyzers/structural.py: mint 15 + proxy 15, plus 5 for a confirmed owner.
    structural = 35 if ownership_renounced is False else 30
    engine = RiskEngine()
    if entrypoint == "direct":
        return engine.compute_composite_risk(contract, HONEYPOT, MARKET, ETHOS)
    return engine.compute_from_results(
        [
            AnalyzerResult("structural", 0.4, structural, data=contract),
            AnalyzerResult("market", 0.25, 0, data=MARKET),
            AnalyzerResult("behavioral", 0.2, 0, data=ETHOS),
            AnalyzerResult("honeypot", 0.15, 0, data=HONEYPOT),
        ]
    )


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
def test_confirmed_unrenounced_ownership_is_still_a_rug_pull(entrypoint):
    risk = _risk(entrypoint, False)
    assert risk["risk_archetype"] == "rug_pull"
    assert risk["rug_probability"] == 85
    assert risk["status"] == "ok"


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
def test_unknown_ownership_is_neither_a_rug_pull_nor_legitimate(entrypoint):
    risk = _risk(entrypoint, None)
    assert risk["risk_archetype"] not in ("rug_pull", "legitimate")
    assert risk["rug_probability"] == 12


def test_unknown_ownership_keeps_high_risk_contract_when_the_score_is_high():
    contract = {
        "is_contract": True,
        "is_verified": True,
        "contract_age_days": 400,
        "has_mint": True,
        "has_proxy": True,
        "ownership_renounced": None,
    }
    risk = RiskEngine().compute_from_results(
        [
            AnalyzerResult("structural", 0.4, 100, data=contract),
            AnalyzerResult("market", 0.25, 100, data=MARKET),
            AnalyzerResult("behavioral", 0.2, 100, data=ETHOS),
            AnalyzerResult("honeypot", 0.15, 0, data=HONEYPOT),
        ]
    )
    assert risk["rug_probability"] == 85
    assert risk["risk_archetype"] == "high_risk_contract"


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
def test_renounced_ownership_is_not_a_rug_pull(entrypoint):
    risk = _risk(entrypoint, True)
    assert risk["risk_archetype"] != "rug_pull"
    assert risk["rug_probability"] == 12
    assert risk["status"] == "ok"
