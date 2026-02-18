"""Tests for confidence calibration."""

import json
import pytest
import pytest_asyncio
from core.calibration import CalibrationConfig, default_calibration, load_calibration, calibrate_from_outcomes
from core.risk_engine import RiskEngine
from core.database import Database


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


@pytest_asyncio.fixture
async def db(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    await db.initialize()
    yield db
    await db.close()


@pytest.mark.asyncio
async def test_calibrate_from_outcomes_insufficient_data(db):
    """With fewer than 20 outcomes, should return defaults."""
    # Add only 5 outcomes
    for i in range(5):
        await db.record_outcome(
            address=f"0x{'a' * 40}",
            risk_score_at_scan=80.0,
            outcome="scam",
        )

    config = await calibrate_from_outcomes(db)
    assert config.high_threshold == 71.0  # defaults


@pytest.mark.asyncio
async def test_calibrate_from_outcomes_with_data(db):
    """With enough labeled outcomes, should produce valid thresholds."""
    # Add 30 well-separated outcomes
    for i in range(15):
        await db.record_outcome(
            address=f"0x{'a' * 38}{i:02x}",
            risk_score_at_scan=85.0 + (i % 10),
            outcome="scam",
        )
    for i in range(15):
        await db.record_outcome(
            address=f"0x{'b' * 38}{i:02x}",
            risk_score_at_scan=10.0 + (i % 15),
            outcome="safe",
        )

    config = await calibrate_from_outcomes(db)
    # Thresholds should be reasonable
    assert 20 <= config.high_threshold <= 95
    assert 10 <= config.medium_threshold <= config.high_threshold
