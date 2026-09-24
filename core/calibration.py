"""Confidence calibration — data-driven thresholds and weight tuning.

The live thresholds come from a config file read at startup. scripts/calibrate.py proposes new ones
from trusted labels with propose_thresholds(); the owner reviews the proposal and edits the file by
hand. Nothing applies a proposal on its own.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

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


# Fewer trusted labels than this give no proposal.
MIN_LABELS = 20


def score_bins(labels: List[Tuple[float, str]]) -> Dict[int, Dict[str, int]]:
    """Safe and scam label counts per 10-point score bin, keyed by the bin's lowest score (0 to 100)."""
    bins = {start: {'safe': 0, 'scam': 0} for start in range(0, 110, 10)}
    for score, label in labels:
        bins[int(score // 10) * 10][label] += 1
    return bins


def propose_thresholds(labels: List[Tuple[float, str]], current: CalibrationConfig) -> Optional[CalibrationConfig]:
    """Thresholds learned from (score, 'safe' | 'scam') labels, or None when there are fewer than
    MIN_LABELS or no HIGH threshold separates them.

    Pass trusted labels only. HIGH is the highest 10-point threshold at or above which at least 80% of
    the labels are scam. MEDIUM is the highest threshold below HIGH whose band up to HIGH is at least
    40% scam, else the current MEDIUM, kept below HIGH. The confidence boost grows with the share of
    labels the pair classifies correctly above 80%.
    """
    if len(labels) < MIN_LABELS:
        return None
    bins = score_bins(labels)

    def share_scam(start, end):
        scam = sum(bins[b]['scam'] for b in range(start, end, 10))
        total = scam + sum(bins[b]['safe'] for b in range(start, end, 10))
        return scam / total if total else None

    high = next(
        (threshold for threshold in range(90, 20, -10) if (share_scam(threshold, 110) or 0) >= 0.8), None
    )
    if high is None:
        return None
    medium = next(
        (threshold for threshold in range(high - 10, 10, -10) if (share_scam(threshold, high) or 0) >= 0.4),
        min(current.medium_threshold, high - 10),
    )

    correct = sum(
        1 for score, label in labels
        if (score >= high and label == 'scam') or (score < medium and label == 'safe')
    )
    accuracy = correct / len(labels)
    return CalibrationConfig(
        high_threshold=float(high),
        medium_threshold=float(medium),
        weight_overrides=dict(current.weight_overrides),
        confidence_boost=min((accuracy - 0.8) * 50, 10.0) if accuracy > 0.8 else 0.0,
    )
