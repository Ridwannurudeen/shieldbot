"""A scam database match must never map to LOW, whatever the calibration."""

import pytest

from core.analyzer import AnalyzerResult
from core.calibration import CalibrationConfig, default_calibration, propose_thresholds
from core.risk_engine import RiskEngine


SCAM_MATCH = {"type": "Local Blacklist", "reason": "Known scam address", "source": "ShieldBot"}
CONTRACT = {
    "is_contract": True,
    "is_verified": True,
    "contract_age_days": 400,
    "ownership_renounced": None,
}
HONEYPOT = {"is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0}
MARKET = {"liquidity_usd": 50000, "pair_age_hours": 100}
ETHOS = {"reputation_score": 80}
RAISED = CalibrationConfig(high_threshold=90.0, medium_threshold=80.0)


def _risk(calibration, entrypoint, is_token, scam_matches):
    contract = {**CONTRACT, "scam_matches": scam_matches}
    engine = RiskEngine(calibration=calibration)
    if entrypoint == "direct":
        return engine.compute_composite_risk(contract, HONEYPOT, MARKET, ETHOS, is_token=is_token)
    skipped = {"skipped": True, "reason": "non-token contract"}
    return engine.compute_from_results(
        [
            AnalyzerResult("structural", 0.4, 30 if scam_matches else 0, data=contract),
            AnalyzerResult("market", 0.25, 0, data=MARKET if is_token else skipped),
            AnalyzerResult("behavioral", 0.2, 0, data=ETHOS),
            AnalyzerResult("honeypot", 0.15, 0, data=HONEYPOT if is_token else skipped),
        ],
        is_token=is_token,
    )


@pytest.mark.parametrize(
    "entrypoint, is_token, rug_probability",
    [
        ("direct", True, 70),
        ("registry", True, 70),
        ("registry", False, 70),
        # The direct entry point has no non-token floor: 30 structural points * 0.4.
        ("direct", False, 12),
    ],
)
def test_raised_medium_threshold_never_maps_scam_match_to_low(
    entrypoint, is_token, rug_probability
):
    risk = _risk(RAISED, entrypoint, is_token, [SCAM_MATCH])
    assert risk["status"] == "ok"
    assert risk["rug_probability"] == rug_probability
    assert risk["risk_level"] == "MEDIUM"


@pytest.mark.parametrize(
    "entrypoint, is_token",
    [
        ("direct", True),
        ("registry", True),
        ("registry", False),
        ("direct", False),
    ],
)
def test_calibration_still_applies_without_scam_matches(entrypoint, is_token):
    uncalibrated = _risk(None, entrypoint, is_token, [])
    calibrated = _risk(RAISED, entrypoint, is_token, [])
    assert calibrated == uncalibrated
    assert calibrated["risk_level"] == "LOW"


@pytest.mark.parametrize(
    "entrypoint, is_token, expected",
    [
        ("direct", True, (70, "MEDIUM")),
        ("registry", True, (70, "MEDIUM")),
        ("registry", False, (70, "MEDIUM")),
    ],
)
def test_uncalibrated_scam_floor_numbers_are_unchanged(entrypoint, is_token, expected):
    risk = _risk(None, entrypoint, is_token, [SCAM_MATCH])
    assert (risk["rug_probability"], risk["risk_level"]) == expected


def test_proposed_calibration_can_raise_medium_above_the_scam_floor():
    labels = [(95.0, "scam")] * 10 + [(85.0, "scam")] * 10
    calibration = propose_thresholds(labels, default_calibration())
    assert (calibration.high_threshold, calibration.medium_threshold) == (90.0, 80.0)
    for entrypoint, is_token in (("direct", True), ("registry", True), ("registry", False)):
        risk = _risk(calibration, entrypoint, is_token, [SCAM_MATCH])
        assert risk["rug_probability"] == 70
        assert risk["risk_level"] != "LOW"
