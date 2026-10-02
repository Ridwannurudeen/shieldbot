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
from core.config import Settings
from core.container import ServiceContainer
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
        or not isinstance(document.get("recorded_at"), str)
        or not isinstance(document.get("dataset"), str)
        or not isinstance(document.get("dataset_sha256"), str)
        or not isinstance(document.get("analyzers"), list)
    ):
        raise ValueError(f"{path} does not carry complete scan provenance")
    recorded_weights = {}
    for analyzer in document["analyzers"]:
        if not (
            isinstance(analyzer, dict)
            and isinstance(analyzer.get("name"), str)
            and type(analyzer.get("weight")) in (int, float)
            and math.isfinite(analyzer["weight"])
            and analyzer["name"] not in recorded_weights
        ):
            raise ValueError(f"{path}: malformed analyzer manifest")
        recorded_weights[analyzer["name"]] = analyzer["weight"]
    for index, record in enumerate(document.get("records", [])):
        if not (
            isinstance(record, dict)
            and type(record.get("chain_id")) is int
            and isinstance(record.get("address"), str)
            and _ADDRESS.fullmatch(record["address"])
            and record.get("status") in ("ok", "error")
            and (record.get("reason") is None or isinstance(record.get("reason"), str))
            and isinstance(record.get("results"), list)
        ):
            raise ValueError(f"{path}: malformed record {index}")
        if record["status"] == "error" and (record["results"] or not record["reason"]):
            raise ValueError(f"{path}: malformed errored record {index}")
        result_names = []
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
            result_names.append(result["name"])
            if (
                result["name"] not in recorded_weights
                or result["weight"] != recorded_weights[result["name"]]
            ):
                raise ValueError(
                    f"{path}: analyzer weight changed within record {index}"
                )
        if record["status"] == "ok" and (
            set(result_names) != set(recorded_weights)
            or len(result_names) != len(recorded_weights)
        ):
            raise ValueError(f"{path}: analyzer set changed within record {index}")
    return document


def current_engine_and_weights():
    """Build the production engine and registry used by the current revision."""
    container = ServiceContainer(Settings())
    return container.risk_engine, {
        analyzer.name: analyzer.weight for analyzer in container.registry.get_all()
    }


def verify_analyzer_set(recorded_weights, current_weights):
    """Reject provider data from a different analyzer set before scoring it."""
    added = sorted(set(current_weights) - set(recorded_weights))
    removed = sorted(set(recorded_weights) - set(current_weights))
    if added or removed:
        parts = []
        if added:
            parts.append("added: " + ", ".join(added))
        if removed:
            parts.append("removed: " + ", ".join(removed))
        raise ValueError(
            "analyzer set differs from recorded inputs (" + "; ".join(parts) + ")"
        )
    return [
        {
            "name": name,
            "recorded_weight": recorded_weights[name],
            "current_weight": current_weights[name],
        }
        for name in sorted(current_weights)
        if recorded_weights[name] != current_weights[name]
    ]


def rebuild_results(record, current_weights):
    """Rebuild results with raw weights from the current production registry."""
    return [
        AnalyzerResult(
            name=result["name"],
            weight=current_weights[result["name"]],
            score=result["score"],
            flags=result["flags"],
            data=result["data"],
            error=result["error"],
        )
        for result in record["results"]
    ]


def normalize_weights(results):
    """Normalize current raw weights exactly as AnalyzerRegistry.run_all does."""
    total = sum(result.weight for result in results)
    if total > 0 and abs(total - 1.0) > 1e-9:
        for result in results:
            result.weight = result.weight / total
    return results


def replay_records(records, engine, current_weights):
    """Score recorded analyzer inputs with the current RiskEngine revision."""
    scores = []
    for input_record in records:
        if input_record["status"] == "error":
            scores.append(
                {
                    "chain_id": input_record["chain_id"],
                    "address": input_record["address"].lower(),
                    "status": "error",
                    "score": None,
                    "risk_level": None,
                    "reason": input_record["reason"],
                }
            )
            continue
        results = normalize_weights(rebuild_results(input_record, current_weights))
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
    engine, current_weights = current_engine_and_weights()
    recorded_weights = {
        analyzer["name"]: analyzer["weight"] for analyzer in inputs["analyzers"]
    }
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
        "inputs_revision": inputs["revision"],
        "inputs_dirty": inputs["dirty"],
        "inputs_recorded_at": inputs["recorded_at"],
        "weight_changes": verify_analyzer_set(recorded_weights, current_weights),
        "records": replay_records(inputs["records"], engine, current_weights),
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
