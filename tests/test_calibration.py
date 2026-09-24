"""Tests for confidence calibration."""

import json
from core.calibration import CalibrationConfig, default_calibration, load_calibration, propose_thresholds
from core.risk_engine import RiskEngine


def test_default_calibration_matches_current():
    """Default calibration should match the hardcoded thresholds."""
    config = default_calibration()
    assert config.high_threshold == 71.0
    assert config.medium_threshold == 31.0
    assert config.confidence_boost == 0.0


def test_load_calibration_from_json(tmp_path):
    """Loading from a JSON file should produce the correct config."""
    config_path = tmp_path / "cal.json"
    config_path.write_text(json.dumps({
        "high_threshold": 65.0,
        "medium_threshold": 25.0,
        "confidence_boost": 5.0,
    }))

    config = load_calibration(str(config_path))
    assert config.high_threshold == 65.0
    assert config.medium_threshold == 25.0
    assert config.confidence_boost == 5.0


def test_load_calibration_missing_file():
    """Missing file should fall back to defaults."""
    config = load_calibration("/nonexistent/path.json")
    assert config.high_threshold == 71.0


def test_custom_config_changes_classification():
    """Custom thresholds should change risk level classification."""
    # With default thresholds, score 65 is MEDIUM
    engine_default = RiskEngine()
    result_default = engine_default.compute_composite_risk(
        contract_data={'is_verified': False},
        honeypot_data={},
        dex_data={'low_liquidity_flag': True},
        ethos_data={},
    )

    # With lowered high threshold, same inputs might classify as HIGH
    custom = CalibrationConfig(high_threshold=50.0, medium_threshold=20.0)
    engine_custom = RiskEngine(calibration=custom)
    result_custom = engine_custom.compute_composite_risk(
        contract_data={'is_verified': False},
        honeypot_data={},
        dex_data={'low_liquidity_flag': True},
        ethos_data={},
    )

    # Both should produce valid risk levels
    assert result_default['risk_level'] in ('LOW', 'MEDIUM', 'HIGH')
    assert result_custom['risk_level'] in ('LOW', 'MEDIUM', 'HIGH')

    # Custom should be at least as severe (lower threshold = more HIGH)
    level_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}
    assert level_order[result_custom['risk_level']] >= level_order[result_default['risk_level']]


def test_propose_thresholds_insufficient_data():
    """With fewer than 20 labels there is no proposal."""
    assert propose_thresholds([(80.0, "scam")] * 5, default_calibration()) is None


def test_propose_thresholds_with_data():
    """With enough well-separated labels, the proposal is a valid pair of thresholds."""
    labels = [(85.0 + (i % 10), "scam") for i in range(15)] + [(10.0 + (i % 15), "safe") for i in range(15)]
    config = propose_thresholds(labels, default_calibration())
    assert 20 <= config.high_threshold <= 95
    assert 10 <= config.medium_threshold <= config.high_threshold


def test_propose_thresholds_without_a_separating_threshold():
    """When no threshold has 80% scam labels at or above it, there is no proposal."""
    labels = [(95.0, "safe")] * 20 + [(95.0, "scam")] * 4
    assert propose_thresholds(labels, default_calibration()) is None
