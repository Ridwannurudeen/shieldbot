"""Risk engine weighting, the clean-token discount and hard floors, with production weights."""

import pytest

from core.analyzer import AnalyzerResult
from core.calibration import CalibrationConfig
from core.risk_engine import RiskEngine

# The weights the registry normalises the container's six analyzers to.
WEIGHTS = {
    "structural": 0.32,
    "market": 0.20,
    "behavioral": 0.16,
    "honeypot": 0.12,
    "intent": 0.12,
    "signature": 0.08,
}
SKIPPED = {"skipped": True, "reason": "non-token contract"}
CONTRACT = {
    "is_contract": True,
    "is_verified": True,
    "contract_age_days": 400,
    "ownership_renounced": None,
}
MARKET = {"liquidity_usd": 50000, "pair_age_hours": 100}
HONEYPOT = {"is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0}
ETHOS = {"reputation_score": 80}


def _results(
    structural=0,
    contract=CONTRACT,
    market=MARKET,
    honeypot=HONEYPOT,
    intent=0,
    intent_data=None,
    signature=0,
    signature_data=None,
):
    return [
        AnalyzerResult("structural", WEIGHTS["structural"], structural, data=contract),
        AnalyzerResult("market", WEIGHTS["market"], 0, data=market),
        AnalyzerResult("behavioral", WEIGHTS["behavioral"], 0, data=ETHOS),
        AnalyzerResult("honeypot", WEIGHTS["honeypot"], 0, data=honeypot),
        AnalyzerResult("intent", WEIGHTS["intent"], intent, data=intent_data or {"status": "ok"}),
        AnalyzerResult(
            "signature",
            WEIGHTS["signature"],
            signature,
            data=signature_data or {"has_typed_data": False},
        ),
    ]


@pytest.mark.parametrize("structural, expected, level", [(100, 47.1, "MEDIUM"), (25, 11.8, "LOW")])
def test_skipped_analyzers_leave_the_weighted_mean(structural, expected, level):
    risk = RiskEngine().compute_from_results(
        _results(structural, market=SKIPPED, honeypot=SKIPPED), is_token=False
    )
    # structural * .32 / .68: market and honeypot do not apply to a non-token.
    assert risk["rug_probability"] == expected
    assert risk["risk_level"] == level
    assert risk["category_scores"]["market"] == 0.0
    assert risk["category_scores"]["honeypot"] == 0.0
    assert risk["coverage"]["market"] == risk["coverage"]["honeypot"] == 1
    assert risk["status"] == "ok"


def test_unknown_market_on_a_token_is_not_made_safer():
    unknown = {"status": "unknown", "reason": "DexScreener HTTP 500"}
    risk = RiskEngine().compute_from_results(_results(50, market=unknown))
    # Unknown market data is excluded exactly as before: 50 * .32 / .80.
    assert risk["rug_probability"] == 20
    assert risk["category_scores"]["market"] is None
    assert risk["coverage"]["market"] == 0
    assert risk["status"] == "unknown"
    assert risk["risk_level"] == "MEDIUM"


CLEAN_TOKEN = {**CONTRACT, "ownership_renounced": True}
DEEP_MARKET = {"liquidity_usd": 5_000_000, "pair_age_hours": 1000}


@pytest.mark.parametrize("intent, expected", [(35, 4.2), (70, 8.4)])
def test_clean_token_discount_keeps_the_transaction_share(intent, expected):
    risk = RiskEngine().compute_from_results(
        _results(0, contract=CLEAN_TOKEN, market=DEEP_MARKET, intent=intent)
    )
    # The renounced, liquid token earns its discount on its own components only: intent * .12.
    assert risk["rug_probability"] == expected
    assert risk["category_scores"]["intent"] == intent


def test_clean_token_discount_without_transaction_risk_is_unchanged():
    risk = RiskEngine().compute_from_results(
        _results(100, contract=CLEAN_TOKEN, market=DEEP_MARKET)
    )
    # 100 * .32 - 20, as before.
    assert risk["rug_probability"] == 12


RAISED = CalibrationConfig(high_threshold=90.0, medium_threshold=80.0)
WALLET_FLAG = "Approval to a wallet address, not a contract (drainer pattern)"
FRESH_UNVERIFIED = ["Contract not verified", "Contract age: 2 days", "Mint function detected"]


def _floored(floor, error=None):
    results = _results(60, contract=CLEAN_TOKEN, market=DEEP_MARKET)
    results[0].flags = list(FRESH_UNVERIFIED)
    results[4] = AnalyzerResult(
        "intent",
        WEIGHTS["intent"],
        35,
        flags=[WALLET_FLAG],
        data={"status": "ok", "floor": floor},
        error=error,
    )
    return results


@pytest.mark.parametrize("floor", [100, 85])
def test_floor_holds_over_the_mean_and_forces_high_under_calibration(floor):
    risk = RiskEngine(calibration=RAISED).compute_from_results(_floored(floor))
    assert risk["rug_probability"] == floor
    # 85 is below the calibrated 90, but a fired floor at or above 71 is always HIGH.
    assert risk["risk_level"] == "HIGH"
    assert risk["transaction_floor"] == floor
    assert risk["critical_flags"][0] == WALLET_FLAG
    assert risk["critical_flags"][1:4] == FRESH_UNVERIFIED


def test_floor_below_the_block_boundary_is_never_low():
    risk = RiskEngine(calibration=RAISED).compute_from_results(_floored(60))
    assert risk["rug_probability"] == 60
    # Calibration maps 60 to LOW (medium threshold 80); a fired floor is never LOW.
    assert risk["risk_level"] == "MEDIUM"
    assert risk["transaction_floor"] == 60


def test_floor_on_an_errored_result_is_ignored():
    risk = RiskEngine().compute_from_results(_floored(100, error="intent analysis unavailable"))
    assert risk["rug_probability"] < 71
    assert risk["transaction_floor"] is None
    assert risk["critical_flags"][0] == FRESH_UNVERIFIED[0]


def test_no_floor_reports_none():
    risk = RiskEngine().compute_from_results(_results(30))
    assert risk["transaction_floor"] is None
    assert risk["rug_probability"] == 9.6


AIRDROP_SCAM = {
    "type": "GoPlus Security",
    "reason": "Airdrop scam token",
    "source": "gopluslabs.io",
    "severity": "block",
}
HONEYPOT_MATCH = {
    "type": "GoPlus Security",
    "reason": "Honeypot (GoPlus)",
    "source": "gopluslabs.io",
    "severity": "high",
}


def _scam_risk(entrypoint, is_token, match):
    contract = {**CONTRACT, "scam_matches": [match]}
    engine = RiskEngine(calibration=RAISED)
    if entrypoint == "direct":
        return engine.compute_composite_risk(contract, HONEYPOT, MARKET, ETHOS, is_token=is_token)
    return engine.compute_from_results(
        _results(
            30,
            contract=contract,
            market=MARKET if is_token else SKIPPED,
            honeypot=HONEYPOT if is_token else SKIPPED,
        ),
        is_token=is_token,
    )


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
@pytest.mark.parametrize("is_token", [True, False])
def test_block_severity_scam_match_floors_at_90_on_both_entry_points(entrypoint, is_token):
    risk = _scam_risk(entrypoint, is_token, AIRDROP_SCAM)
    assert risk["rug_probability"] == 90
    assert risk["risk_level"] == "HIGH"


@pytest.mark.parametrize(
    "entrypoint, is_token", [("direct", True), ("registry", True), ("registry", False)]
)
def test_high_severity_scam_match_keeps_the_70_floor(entrypoint, is_token):
    risk = _scam_risk(entrypoint, is_token, HONEYPOT_MATCH)
    assert risk["rug_probability"] == 70
    assert risk["risk_level"] == "MEDIUM"
