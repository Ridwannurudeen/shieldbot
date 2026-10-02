"""Offline scorer from recorded analyzer inputs.

Usage:
    python -m eval.replay --inputs eval/data/live_inputs.json --output eval/data/replay_scores.json
"""

import argparse
import datetime
import json
import math
import re
import sys

from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine
from eval.benchmark import FORMAT_INPUTS, FORMAT_SCORES, json_sha256
from eval.live_scorer import current_revision

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_REVISION = re.compile(r"[0-9a-f]{40}")


def load_inputs(path):
    """Read recorded analyzer inputs and reject records that cannot rebuild AnalyzerResult objects."""
    with open(path, encoding="utf-8") as f:
        document = json.load(f)
    if not isinstance(document, dict) or document.get("format") != FORMAT_INPUTS:
        raise ValueError(f"{path} is not a {FORMAT_INPUTS} file")
    if not isinstance(document.get("revision"), str) or not _REVISION.fullmatch(
        document["revision"]
    ):
        raise ValueError(f"{path} is not pinned to a 40-character git revision")
    if (
        "dirty" not in document
        or type(document["dirty"]) not in (bool, type(None))
        or not isinstance(document.get("scored_at"), str)
        or not isinstance(document.get("dataset"), str)
        or not isinstance(document.get("dataset_sha256"), str)
    ):
        raise ValueError(f"{path} does not carry complete scan provenance")
    for index, record in enumerate(document.get("records", [])):
        if not (
            isinstance(record, dict)
            and type(record.get("chain_id")) is int
            and isinstance(record.get("address"), str)
            and _ADDRESS.fullmatch(record["address"])
            and isinstance(record.get("results"), list)
        ):
            raise ValueError(f"{path}: malformed record {index}")
        for result in record["results"]:
            if not (
                isinstance(result, dict)
                and isinstance(result.get("name"), str)
                and type(result.get("weight")) in (int, float)
                and math.isfinite(result["weight"])
                and type(result.get("score")) in (int, float)
                and math.isfinite(result["score"])
                and isinstance(result.get("flags"), list)
                and all(isinstance(flag, str) for flag in result["flags"])
                and isinstance(result.get("data"), dict)
                and (
                    result.get("error") is None or isinstance(result.get("error"), str)
                )
            ):
                raise ValueError(f"{path}: malformed analyzer result {index}")
    return document


def rebuild_results(record):
    """Rebuild the AnalyzerResult list saved for one benchmark entry."""
    return [
        AnalyzerResult(
            name=result["name"],
            weight=result["weight"],
            score=result["score"],
            flags=result["flags"],
            data=result["data"],
            error=result["error"],
        )
        for result in record["results"]
    ]


def normalize_weights(results):
    """Normalize recorded raw weights exactly as AnalyzerRegistry.run_all does."""
    total = sum(result.weight for result in results)
    if total > 0 and abs(total - 1.0) > 1e-9:
        for result in results:
            result.weight = result.weight / total
    return results


def replay_records(records):
    """Score recorded analyzer inputs with the current RiskEngine revision."""
    engine = RiskEngine()
    scores = []
    for input_record in records:
        results = normalize_weights(rebuild_results(input_record))
        risk_output = engine.compute_from_results(results)
        score = risk_output.get("rug_probability")
        record = {
            "chain_id": input_record["chain_id"],
            "address": input_record["address"].lower(),
            "status": "error",
            "score": score,
            "risk_level": risk_output.get("risk_level"),
            "reason": None,
        }
        if risk_output.get("status") == "ok" and score is not None:
            record["status"] = "ok"
        else:
            record["status"] = "unknown"
            record["reason"] = (
                "; ".join(
                    f"{name}: {reason}"
                    for name, reason in (
                        risk_output.get("coverage_reasons") or {}
                    ).items()
                )
                or "Incomplete scan"
            )
        scores.append(record)
    return scores


def replay(inputs_path, output_path, revision, dirty):
    """Write current-revision scores from one immutable analyzer-input recording."""
    inputs = load_inputs(inputs_path)
    document = {
        "format": FORMAT_SCORES,
        "revision": revision,
        "dirty": dirty,
        "scored_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "dataset": inputs["dataset"],
        "dataset_sha256": inputs["dataset_sha256"],
        "inputs_sha256": json_sha256(inputs_path),
        "records": replay_records(inputs["records"]),
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2)
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="ShieldBot offline analyzer-input replay"
    )
    parser.add_argument(
        "--inputs", required=True, help="Analyzer inputs recorded by eval.live_scorer"
    )
    parser.add_argument(
        "--output", required=True, help="Path to save the replayed scores"
    )
    args = parser.parse_args(argv)
    revision, dirty = current_revision()
    replay(args.inputs, args.output, revision, dirty)
    print(f"Scores saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
