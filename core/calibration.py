"""Confidence calibration — data-driven thresholds and weight tuning."""

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class CalibrationConfig:
    """Risk classification thresholds and weight overrides."""
    high_threshold: float = 71.0
    medium_threshold: float = 31.0
    weight_overrides: Dict[str, float] = field(default_factory=dict)
    confidence_boost: float = 0.0  # Added to confidence when historical accuracy is high


def default_calibration() -> CalibrationConfig:
    """Return the default calibration matching current hardcoded values."""
    return CalibrationConfig(
        high_threshold=71.0,
        medium_threshold=31.0,
    )


def load_calibration(path: str) -> CalibrationConfig:
    """Load calibration config from a JSON file."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return CalibrationConfig(
            high_threshold=data.get('high_threshold', 71.0),
            medium_threshold=data.get('medium_threshold', 31.0),
            weight_overrides=data.get('weight_overrides', {}),
            confidence_boost=data.get('confidence_boost', 0.0),
        )
    except FileNotFoundError:
        logger.warning(f"Calibration file not found: {path}, using defaults")
        return default_calibration()
    except Exception as e:
        logger.error(f"Error loading calibration: {e}")
        return default_calibration()


async def calibrate_from_outcomes(db) -> CalibrationConfig:
    """Analyze outcome_events to find optimal thresholds via binning.

    Queries the database for outcome events where we know the ground truth
    (outcome = "safe" or "scam"), bins by risk score, and finds the threshold
    that maximizes separation between safe and scam.

    Returns a CalibrationConfig with updated thresholds.
    """
    config = default_calibration()

    try:
        # Get all outcomes with known labels
        cursor = await db._db.execute("""
            SELECT risk_score_at_scan, outcome
            FROM outcome_events
            WHERE outcome IN ('safe', 'scam')
              AND risk_score_at_scan IS NOT NULL
        """)
        rows = await cursor.fetchall()

        if len(rows) < 20:
            logger.info(f"Only {len(rows)} labeled outcomes — need 20+ for calibration")
            return config

        # Bin scores into 10-point ranges and count safe/scam per bin
        bins = {}  # bin_start -> {'safe': count, 'scam': count}
        for score, outcome in rows:
            bin_start = int(score // 10) * 10
            if bin_start not in bins:
                bins[bin_start] = {'safe': 0, 'scam': 0}
            bins[bin_start][outcome] += 1

        # Find HIGH threshold: lowest bin where scam > 80% of entries
        best_high = 71.0
        for threshold in range(90, 20, -10):
            scam_above = sum(bins.get(b, {}).get('scam', 0) for b in range(threshold, 110, 10))
            safe_above = sum(bins.get(b, {}).get('safe', 0) for b in range(threshold, 110, 10))
            total_above = scam_above + safe_above
            if total_above > 0 and scam_above / total_above >= 0.8:
                best_high = float(threshold)
                break

        # Find MEDIUM threshold: lowest bin where scam > 40% of entries
        best_medium = 31.0
        for threshold in range(int(best_high) - 10, 10, -10):
            scam_above = sum(bins.get(b, {}).get('scam', 0) for b in range(threshold, int(best_high), 10))
            safe_above = sum(bins.get(b, {}).get('safe', 0) for b in range(threshold, int(best_high), 10))
            total_above = scam_above + safe_above
            if total_above > 0 and scam_above / total_above >= 0.4:
                best_medium = float(threshold)
                break

        config.high_threshold = best_high
        config.medium_threshold = best_medium

        # Calculate confidence boost from historical accuracy
        correct = sum(1 for s, o in rows if (s >= best_high and o == 'scam') or (s < best_medium and o == 'safe'))
        accuracy = correct / len(rows) if rows else 0
        if accuracy > 0.8:
            config.confidence_boost = min((accuracy - 0.8) * 50, 10.0)

        logger.info(
            f"Calibration: HIGH>={best_high}, MEDIUM>={best_medium}, "
            f"accuracy={accuracy:.1%}, boost={config.confidence_boost:.1f}"
        )

    except Exception as e:
        logger.error(f"Calibration error: {e}")

    return config
