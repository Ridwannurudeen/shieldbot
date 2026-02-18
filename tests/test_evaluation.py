"""Tests for the evaluation pipeline."""

import pytest
from eval.dataset import load_dataset, BenchmarkEntry
from eval.benchmark import run_benchmark, BenchmarkResult


def test_load_dataset():
    """Load the seed benchmark dataset."""
    entries = load_dataset("eval/data/benchmark_v1.json")
    assert len(entries) >= 20
    # Should have both safe and malicious
    labels = {e.label for e in entries}
    assert "safe" in labels
    assert "malicious" in labels


def test_precision_recall_math():
    """Verify precision/recall calculation with known values."""
    entries = [
        BenchmarkEntry(address="0x1", chain_id=56, label="malicious"),
        BenchmarkEntry(address="0x2", chain_id=56, label="malicious"),
        BenchmarkEntry(address="0x3", chain_id=56, label="safe"),
        BenchmarkEntry(address="0x4", chain_id=56, label="safe"),
    ]
    # Scores: 0x1=80 (TP), 0x2=30 (FN), 0x3=60 (FP), 0x4=20 (TN)
    scores = {"0x1": 80, "0x2": 30, "0x3": 60, "0x4": 20}

    result = run_benchmark(entries, scores, threshold=50)

    assert result.true_positives == 1
    assert result.false_negatives == 1
    assert result.false_positives == 1
    assert result.true_negatives == 1
    # Precision = 1 / (1+1) = 0.5
    assert abs(result.precision - 0.5) < 1e-9
    # Recall = 1 / (1+1) = 0.5
    assert abs(result.recall - 0.5) < 1e-9
    # F1 = 2 * 0.5 * 0.5 / (0.5 + 0.5) = 0.5
    assert abs(result.f1 - 0.5) < 1e-9


def test_perfect_scores():
    """Perfect classification should give precision=recall=F1=1.0."""
    entries = [
        BenchmarkEntry(address="0x1", chain_id=56, label="malicious"),
        BenchmarkEntry(address="0x2", chain_id=56, label="safe"),
    ]
    scores = {"0x1": 90, "0x2": 10}
    result = run_benchmark(entries, scores, threshold=50)

    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1 == 1.0
    assert result.false_positive_rate == 0.0


def test_missing_scores_counted_as_errors():
    """Entries without scores should be counted as errors."""
    entries = [
        BenchmarkEntry(address="0x1", chain_id=56, label="malicious"),
    ]
    scores = {}  # No scores
    result = run_benchmark(entries, scores, threshold=50)
    assert result.errors == 1
    assert result.true_positives == 0
