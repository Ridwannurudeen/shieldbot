"""Benchmark runner — measures precision, recall, and F1 score."""

import logging
from dataclasses import dataclass, field
from typing import Dict, List

from eval.dataset import BenchmarkEntry

logger = logging.getLogger(__name__)

# Threshold for classifying a score as "flagged" (malicious)
DEFAULT_FLAG_THRESHOLD = 50.0


@dataclass
class BenchmarkResult:
    """Aggregated benchmark metrics."""
    total: int = 0
    true_positives: int = 0   # malicious correctly flagged
    false_positives: int = 0  # safe incorrectly flagged
    true_negatives: int = 0   # safe correctly passed
    false_negatives: int = 0  # malicious incorrectly passed
    errors: int = 0
    details: List[Dict] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0


def run_benchmark(
    entries: List[BenchmarkEntry],
    scores: Dict[str, float],
    threshold: float = DEFAULT_FLAG_THRESHOLD,
) -> BenchmarkResult:
    """Run benchmark evaluation against pre-computed scores.

    Args:
        entries: Labeled benchmark entries.
        scores: Map of address (lowercased) -> risk score (0-100).
        threshold: Score at or above which an address is flagged as malicious.

    Returns:
        BenchmarkResult with precision, recall, F1, and per-entry details.
    """
    result = BenchmarkResult(total=len(entries))

    for entry in entries:
        addr = entry.address.lower()
        score = scores.get(addr)

        if score is None:
            result.errors += 1
            result.details.append({
                'address': entry.address,
                'chain_id': entry.chain_id,
                'label': entry.label,
                'score': None,
                'predicted': None,
                'correct': None,
                'error': 'No score available',
            })
            continue

        predicted = 'malicious' if score >= threshold else 'safe'
        correct = predicted == entry.label

        if entry.label == 'malicious' and predicted == 'malicious':
            result.true_positives += 1
        elif entry.label == 'safe' and predicted == 'malicious':
            result.false_positives += 1
        elif entry.label == 'safe' and predicted == 'safe':
            result.true_negatives += 1
        elif entry.label == 'malicious' and predicted == 'safe':
            result.false_negatives += 1

        result.details.append({
            'address': entry.address,
            'chain_id': entry.chain_id,
            'label': entry.label,
            'category': entry.category,
            'score': score,
            'predicted': predicted,
            'correct': correct,
        })

    return result
