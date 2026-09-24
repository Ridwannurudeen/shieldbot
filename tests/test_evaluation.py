"""Tests for the evaluation pipeline."""

from eval.dataset import load_dataset, BenchmarkEntry
from eval.benchmark import benchmark_results

V1_STALE = {"0x25d887ce7a35172c62febfd67a1856f20faebb00", "0xb08504d245713ca9692c8fa605e76a0a11ed4955"}


def ok(score):
    return {"status": "ok", "score": score}


def records(scores):
    return {(56, address): record for address, record in scores.items()}


def test_load_dataset():
    """Load the seed benchmark dataset; entries marked stale are left out."""
    entries = load_dataset("eval/data/benchmark_v1.json")
    assert len(entries) == 32
    # Should have both safe and malicious
    labels = {e.label for e in entries}
    assert "safe" in labels
    assert "malicious" in labels
    assert not V1_STALE & {e.address.lower() for e in entries}


def test_precision_recall_math():
    """Verify precision/recall calculation with known values."""
    entries = [
        BenchmarkEntry(address="0x1", chain_id=56, label="malicious", category="honeypot"),
        BenchmarkEntry(address="0x2", chain_id=56, label="malicious", category="honeypot"),
        BenchmarkEntry(address="0x3", chain_id=56, label="safe"),
        BenchmarkEntry(address="0x4", chain_id=56, label="safe"),
    ]
    # Scores: 0x1=80 (TP), 0x2=30 (FN), 0x3=60 (FP), 0x4=20 (TN)
    result = benchmark_results(
        entries, records({"0x1": ok(80), "0x2": ok(30), "0x3": ok(60), "0x4": ok(20)}), threshold=50
    )

    honeypot = result["classes"]["honeypot"]
    assert (honeypot["decided"], honeypot["flagged"]) == (2, 1)
    # Recall = 1 / 2; precision = 1 / (1 + 1 flagged safe)
    assert honeypot["recall"] == 0.5
    assert honeypot["precision"] == 0.5
    assert result["classes"]["safe"]["false_positive_rate"] == 0.5
    assert result["overall"] == {
        "entries": 4, "unknown_rate": 0.0, "recall": 0.5, "precision": 0.5, "false_positive_rate": 0.5,
    }


def test_perfect_scores():
    """Perfect classification should give precision=recall=1.0 and no false positives."""
    entries = [
        BenchmarkEntry(address="0x1", chain_id=56, label="malicious", category="honeypot"),
        BenchmarkEntry(address="0x2", chain_id=56, label="safe"),
    ]
    result = benchmark_results(entries, records({"0x1": ok(90), "0x2": ok(10)}), threshold=50)

    assert result["overall"]["precision"] == 1.0
    assert result["overall"]["recall"] == 1.0
    assert result["overall"]["false_positive_rate"] == 0.0


def test_missing_scores_are_unknown():
    """An entry without a recorded score is unknown: neither flagged nor passed."""
    entries = [
        BenchmarkEntry(address="0x1", chain_id=56, label="malicious", category="honeypot"),
    ]
    result = benchmark_results(entries, {}, threshold=50)
    honeypot = result["classes"]["honeypot"]
    assert (honeypot["unknown"], honeypot["decided"], honeypot["flagged"]) == (1, 0, 0)
    assert honeypot["recall"] is None
    assert result["details"][0]["status"] == "missing"
