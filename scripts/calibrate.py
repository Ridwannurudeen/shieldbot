#!/usr/bin/env python3
"""Propose risk thresholds from trusted labels. It never changes the live configuration.

Trusted labels are:
  - benchmark entries with the scores eval.live_scorer recorded for them (--dataset, --scores). Only
    completed scans count; a safe entry is 'safe' and every malicious class is 'scam'.
  - outcome events sent with an API key (source 'key:<key_id>') whose outcome is 'safe' or 'scam' and
    that carry the score of the scan. Rows sent without a key ('client') are never read.

The proposal file gives the proposed HIGH and MEDIUM thresholds (none when the labels are too few),
the labels in each 10-point score bin, the precision and recall of the current and proposed thresholds,
the current thresholds, and where the labels came from, with the outcome rows counted per API key. The
owner reviews it and edits core/calibration_config.json by hand (docs/TECHNICAL.md).

Usage:
    python scripts/calibrate.py --db /opt/shieldbot/shieldbot.db --out calibration-proposal.json
    python scripts/calibrate.py --db shieldbot.db --scores eval/data/live_scores.json --out proposal.json
"""

import argparse
import datetime
import json
import os
import sqlite3
import sys
from collections import Counter
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.calibration import MIN_LABELS, load_calibration, propose_thresholds, score_bins
from eval.benchmark import json_sha256, load_scores
from eval.dataset import load_dataset

FORMAT_PROPOSAL = "shieldbot-calibration-proposal/1"
LIVE_CONFIG = str(Path(__file__).resolve().parent.parent / "core" / "calibration_config.json")


def benchmark_labels(dataset_path: str, scores_path: str) -> list:
    """(score, label) for each benchmark entry whose recorded scan completed.

    Raises ValueError when the scores were recorded against a different dataset file.
    """
    entries = load_dataset(dataset_path)
    scores = load_scores(scores_path)
    if scores["dataset_sha256"] != json_sha256(dataset_path):
        raise ValueError(
            f"{scores_path} was recorded against a different dataset than {dataset_path}"
        )
    labels = []
    for entry in entries:
        record = scores["records"].get((entry.chain_id, entry.address.lower()))
        if record is not None and record["status"] == "ok":
            labels.append((record["score"], "safe" if entry.label == "safe" else "scam"))
    return labels


def outcome_labels(db_path: str) -> list:
    """(score, label, source) for each outcome event sent with an API key, read without writing."""
    connection = sqlite3.connect(f"{Path(db_path).resolve().as_uri()}?mode=ro", uri=True)
    try:
        return connection.execute("""
            SELECT risk_score_at_scan, outcome, source
            FROM outcome_events
            WHERE source LIKE 'key:%'
              AND outcome IN ('safe', 'scam')
              AND risk_score_at_scan IS NOT NULL
        """).fetchall()
    finally:
        connection.close()


def _ratio(numerator: int, denominator: int):
    return round(numerator / denominator, 4) if denominator else None


def threshold_metrics(labels: list, high: float, medium: float) -> dict:
    """Precision and recall for scam of a score at or above each threshold."""
    scams = sum(1 for _, label in labels if label == "scam")
    metrics = {}
    for name, threshold in (("high", high), ("medium", medium)):
        flagged = [label for score, label in labels if score >= threshold]
        caught = flagged.count("scam")
        metrics[name] = {
            "threshold": threshold,
            "flagged": len(flagged),
            "precision": _ratio(caught, len(flagged)),
            "recall": _ratio(caught, scams),
        }
    return metrics


def build_proposal(
    db_path: str, config_path: str, dataset_path: str = None, scores_path: str = None
) -> dict:
    current = load_calibration(config_path)
    outcomes = outcome_labels(db_path)
    benchmark = benchmark_labels(dataset_path, scores_path) if scores_path else []
    labels = benchmark + [(score, label) for score, label, _ in outcomes]
    proposed = propose_thresholds(labels, current)

    if proposed is not None:
        reason = None
    elif len(labels) < MIN_LABELS:
        reason = f"{len(labels)} trusted labels; at least {MIN_LABELS} are needed"
    else:
        reason = "No threshold has at least 80% scam labels at or above it"

    counts = Counter(label for _, label in labels)
    return {
        "format": FORMAT_PROPOSAL,
        "created_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "current": {
            "path": Path(config_path).as_posix(),
            "high_threshold": current.high_threshold,
            "medium_threshold": current.medium_threshold,
            "confidence_boost": current.confidence_boost,
        },
        "proposed": None
        if proposed is None
        else {
            "high_threshold": proposed.high_threshold,
            "medium_threshold": proposed.medium_threshold,
            "confidence_boost": proposed.confidence_boost,
        },
        "reason": reason,
        "labels": {
            "total": len(labels),
            "safe": counts["safe"],
            "scam": counts["scam"],
            "benchmark": {
                "dataset": Path(dataset_path).as_posix() if scores_path else None,
                "scores": Path(scores_path).as_posix() if scores_path else None,
                "rows": len(benchmark),
            },
            "outcomes": {
                "db": Path(db_path).as_posix(),
                "rows": len(outcomes),
                "by_source": dict(sorted(Counter(source for _, _, source in outcomes).items())),
            },
        },
        "bins": {str(start): counts for start, counts in score_bins(labels).items()},
        "metrics": {
            "current": threshold_metrics(labels, current.high_threshold, current.medium_threshold),
            "proposed": None
            if proposed is None
            else threshold_metrics(
                labels,
                proposed.high_threshold,
                proposed.medium_threshold,
            ),
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Propose risk thresholds from trusted labels")
    parser.add_argument("--db", required=True, help="The ShieldBot SQLite database, read only")
    parser.add_argument("--out", required=True, help="Where to write the proposal (JSON)")
    parser.add_argument(
        "--config",
        default=LIVE_CONFIG,
        help=f"The live calibration config, read only (default {LIVE_CONFIG})",
    )
    parser.add_argument(
        "--dataset",
        default="eval/data/benchmark_v2.json",
        help="Benchmark dataset the scores were recorded for",
    )
    parser.add_argument("--scores", help="Scores eval.live_scorer recorded for the dataset")
    args = parser.parse_args(argv)
    if Path(args.out).resolve() == Path(args.config).resolve():
        parser.error("--out must not be the live config; the owner applies a proposal by hand")

    proposal = build_proposal(args.db, args.config, args.dataset, args.scores)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(proposal, f, indent=2)
        f.write("\n")

    print(
        f"{proposal['labels']['total']} trusted labels "
        f"({proposal['labels']['benchmark']['rows']} benchmark, {proposal['labels']['outcomes']['rows']} API key outcomes)"
    )
    if proposal["proposed"] is None:
        print(f"No proposal: {proposal['reason']}")
    else:
        print(
            f"Proposed HIGH {proposal['proposed']['high_threshold']:g}, MEDIUM {proposal['proposed']['medium_threshold']:g} "
            f"(current {proposal['current']['high_threshold']:g}, {proposal['current']['medium_threshold']:g})"
        )
    print(f"Proposal written to {args.out}; the live config is unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
