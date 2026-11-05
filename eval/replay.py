"""Offline scorer from recorded analyzer inputs.

Usage:
    python -m eval.replay --inputs eval/data/live_inputs.json --output eval/data/replay_scores.json
    python -m eval.replay --inputs eval/data/live_inputs.json --output eval/data/replay_scores.json \
        --rerun intent,signature,behavioral
"""

import argparse
import asyncio
import datetime
import json
import math
import re
import sys

from analyzers.behavioral import BehavioralAnalyzer
from analyzers.intent import IntentMismatchAnalyzer
from analyzers.signature import SignaturePermitAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.config import Settings
from core.container import ServiceContainer
from eval.benchmark import FORMAT_INPUTS, FORMAT_SCORES, json_sha256
from eval.live_scorer import current_revision
from services.ethos_service import neutral_reputation

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_REVISION = re.compile(r"[0-9a-f]{40}")
# The transaction-only analyzers, which can be run again at the replaying revision without a provider.
RERUNNABLE = ("intent", "signature", "behavioral")
# Every field EthosService.fetch_wallet_reputation returns; it adds status and reason when the data is unknown.
_ETHOS_RESPONSE = tuple(neutral_reputation())


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


class _Offline:
    """A service for a rerun analyzer: any use of it refuses the replay rather than reach a provider."""

    def __init__(self, analyzer):
        self._analyzer = analyzer

    def __getattr__(self, attribute):
        raise ValueError(
            f"{self._analyzer} would make a network lookup ({attribute}) at this revision; "
            "it cannot be rerun offline"
        )


class _RecordedEthos(_Offline):
    """Answers behavioral's Ethos lookup of the recorded address with the recorded response, and nothing else."""

    def __init__(self, address, response):
        super().__init__("behavioral")
        self._address = address
        self._response = response

    async def fetch_wallet_reputation(self, address):
        if address.lower() != self._address:
            raise ValueError(
                f"behavioral looked up {address}, not the recorded {self._address}; "
                "it cannot be rerun offline"
            )
        return dict(self._response)


def recorded_ethos_response(result):
    """The Ethos response a recorded behavioral result was computed from, or None if it cannot be rebuilt.

    The live run's behavioral data is that response plus the address it named in ``counterparty``.
    """
    data = result.data
    if (
        result.error is not None
        or not isinstance(data.get("counterparty"), str)
        or any(key not in data for key in _ETHOS_RESPONSE)
    ):
        return None
    keys = _ETHOS_RESPONSE + tuple(key for key in ("status", "reason") if key in data)
    return data["counterparty"].lower(), {key: data[key] for key in keys}


def rerun_behavioral(recorded):
    """The current behavioral analyzer answered by the entry's recorded Ethos response, or None."""
    response = recorded_ethos_response(recorded)
    if response is None:
        return None
    return BehavioralAnalyzer(_RecordedEthos(*response))


def rerun_analyzers(names):
    """For each analyzer to run again, a builder that takes the entry's recorded result and returns the
    current revision's analyzer wired to offline services, or None when the recording cannot answer it."""
    unknown = sorted(set(names) - set(RERUNNABLE))
    if unknown:
        raise ValueError(
            "only "
            + ", ".join(RERUNNABLE)
            + " can be rerun offline, not "
            + ", ".join(unknown)
        )
    build = {
        "intent": lambda recorded: IntentMismatchAnalyzer(
            _Offline("intent"), _Offline("intent")
        ),
        "signature": lambda recorded: SignaturePermitAnalyzer(_Offline("signature")),
        "behavioral": rerun_behavioral,
    }
    return {name: build[name] for name in names}


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


def rerun_results(record, results, analyzers, current_weights, unavailable):
    """Replace the recorded results of the rerun analyzers with what they return at this revision.

    A result the recording cannot answer is kept as recorded and counted in ``unavailable``.
    """
    ctx = AnalysisContext(address=record["address"], chain_id=record["chain_id"])
    rerun = []
    for result in results:
        if result.name in analyzers:
            analyzer = analyzers[result.name](result)
            if analyzer is None:
                unavailable[result.name] += 1
            else:
                result = asyncio.run(analyzer.analyze(ctx))
                result.weight = current_weights[result.name]
        rerun.append(result)
    return rerun


def replay_records(records, engine, current_weights, analyzers, unavailable):
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
        results = normalize_weights(
            rerun_results(
                input_record,
                rebuild_results(input_record, current_weights),
                analyzers,
                current_weights,
                unavailable,
            )
        )
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


def replay(inputs_path, output_path, revision, dirty, rerun=()):
    """Write current-revision scores from one immutable analyzer-input recording.

    The analyzers named in ``rerun`` are run again at this revision instead of read from the recording,
    except where the recording cannot answer them; those are counted in ``rerun_unavailable``.
    """
    inputs = load_inputs(inputs_path)
    analyzers = rerun_analyzers(rerun)
    engine, current_weights = current_engine_and_weights()
    recorded_weights = {
        analyzer["name"]: analyzer["weight"] for analyzer in inputs["analyzers"]
    }
    weight_changes = verify_analyzer_set(recorded_weights, current_weights)
    unavailable = {name: 0 for name in sorted(analyzers)}
    records = replay_records(
        inputs["records"], engine, current_weights, analyzers, unavailable
    )
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
        "weight_changes": weight_changes,
        "rerun": sorted(analyzers),
        "rerun_unavailable": unavailable,
        "records": records,
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
    parser.add_argument(
        "--rerun",
        default="",
        help="Comma-separated analyzers to run again at this revision: "
        + ", ".join(RERUNNABLE),
    )
    args = parser.parse_args(argv)
    revision, dirty = current_revision()
    replay(
        args.inputs,
        args.output,
        revision,
        dirty,
        [name for name in args.rerun.split(",") if name],
    )
    print(f"Scores saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
