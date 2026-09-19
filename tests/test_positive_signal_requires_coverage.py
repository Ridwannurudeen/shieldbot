"""The renounced-ownership discount needs a covered scam database lookup."""

import pytest

from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine


MARKET = {"liquidity_usd": 200000, "pair_age_hours": 100, "fdv": 200000, "volume_24h": 2000}
HONEYPOT = {"is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0}
ETHOS = {"reputation_score": 80}
# Unverified 25 + mint 15 + proxy 15 + blacklist 10, renounced owner: 65 * 0.4 = 26.
STRUCTURAL = 65


def _contract(coverage):
    contract = {
        "is_contract": True,
        "is_verified": False,
        "contract_age_days": 400,
        "has_mint": True,
        "has_proxy": True,
        "has_blacklist": True,
        "ownership_renounced": True,
        "scam_matches": [],
    }
    if coverage is not None:
        contract["coverage"] = coverage
        if not all(coverage.values()):
            contract["status"] = "unknown"
            contract["reason"] = "Scam database unavailable: GoPlus HTTP 429"
    return contract


def _risk(entrypoint, coverage):
    contract = _contract(coverage)
    engine = RiskEngine()
    if entrypoint == "direct":
        return engine.compute_composite_risk(contract, HONEYPOT, MARKET, ETHOS)
    return engine.compute_from_results(
        [
            AnalyzerResult("structural", 0.4, STRUCTURAL, data=contract),
            AnalyzerResult("market", 0.25, 0, data=MARKET),
            AnalyzerResult("behavioral", 0.2, 0, data=ETHOS),
            AnalyzerResult("honeypot", 0.15, 0, data=HONEYPOT),
        ]
    )


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
@pytest.mark.parametrize(
    "coverage",
    [
        None,
        {"is_verified": True, "contract_age_days": True},
        {"scam_database": True, "is_verified": True, "contract_age_days": True},
    ],
)
def test_covered_clean_lookup_keeps_the_discount(entrypoint, coverage):
    risk = _risk(entrypoint, coverage)
    assert risk["rug_probability"] == 6
    assert risk["status"] == "ok"
    assert risk["risk_level"] == "LOW"


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
def test_failed_scam_lookup_loses_the_discount(entrypoint):
    risk = _risk(
        entrypoint, {"scam_database": False, "is_verified": True, "contract_age_days": True}
    )
    assert risk["rug_probability"] == 26
    assert risk["status"] == "unknown"
    assert risk["risk_level"] != "LOW"


def _bytecode_risk(entrypoint, bytecode_covered):
    # A failed bytecode read leaves every pattern flag False (services/contract_service.py),
    # so only the unverified 25 remains: 25 * 0.4 = 10.
    contract = {
        "is_contract": True,
        "is_verified": False,
        "contract_age_days": 400,
        "has_mint": False,
        "has_proxy": False,
        "has_blacklist": False,
        "ownership_renounced": True,
        "scam_matches": [],
    }
    if not bytecode_covered:
        contract["coverage"] = {"bytecode": False, "is_verified": True, "contract_age_days": True}
        contract["status"] = "unknown"
        contract["reason"] = "Bytecode scan unavailable"
    engine = RiskEngine()
    if entrypoint == "direct":
        return engine.compute_composite_risk(contract, HONEYPOT, MARKET, ETHOS)
    return engine.compute_from_results(
        [
            AnalyzerResult("structural", 0.4, 25, data=contract),
            AnalyzerResult("market", 0.25, 0, data=MARKET),
            AnalyzerResult("behavioral", 0.2, 0, data=ETHOS),
            AnalyzerResult("honeypot", 0.15, 0, data=HONEYPOT),
        ]
    )


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
def test_successful_bytecode_read_keeps_the_discount(entrypoint):
    risk = _bytecode_risk(entrypoint, True)
    assert risk["rug_probability"] == 0
    assert risk["status"] == "ok"


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
def test_failed_bytecode_scan_loses_the_discount(entrypoint):
    risk = _bytecode_risk(entrypoint, False)
    assert risk["rug_probability"] == 10
    assert risk["status"] == "unknown"
    assert risk["risk_level"] != "LOW"
