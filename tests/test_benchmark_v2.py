"""Benchmark v2: class-stratified labels with independent sources, recorded scores and offline results.

The recorded scores here are written by the tests for the tests; they are not measurements.
"""

import asyncio
import json
from unittest.mock import AsyncMock
from pathlib import Path
from types import SimpleNamespace

import pytest

import eval.cli as cli
import eval.live_scorer as live_scorer
import eval.replay as replay
from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine
from eval.benchmark import (
    FORMAT_INPUTS,
    FORMAT_RESULTS,
    FORMAT_SCORES,
    build_results,
    json_sha256,
    load_scores,
)
from eval.dataset import CLASSES, FORMAT_V2, LABEL_PROVIDERS, load_dataset

V2 = "eval/data/benchmark_v2.json"
REVISION = "0123456789abcdef0123456789abcdef01234567"
IMPOSTORS = {
    "0x1c2a482970ae6b6e5052a7a184c8aef19e0840be",
    "0xf01ab9476afcaa0e0058c83cef2b4c30867abeeb",
    "0x982732a974738b771b07a2588f1b38a968a11e18",
}
# The fewest entries each class of the committed file may hold (eval/README.md, "Size").
MINIMUMS = {
    "honeypot": 0,
    "rug_pull": 0,
    "drainer_contract": 100,
    "approval_drainer_spender": 100,
    "address_poisoning": 50,
    "impostor_token": 90,
    "fake_claim": 0,
    "safe": 250,
}
DRAINER = "0x" + "d0" * 20
SAFE = "0x" + "5a" * 20
SOURCE = {
    "provider": "scamsniffer",
    "url": "https://github.com/scamsniffer/scam-database",
    "retrieved": "2026-09-24",
    "evidence": "listed",
}


def entry(**changes):
    item = {
        "class": "drainer_contract",
        "chain_id": 1,
        "address": DRAINER,
        "labeled": "2026-09-24",
        "sources": [SOURCE],
    }
    return {**item, **changes}


def write_dataset(tmp_path, entries):
    path = tmp_path / "dataset.json"
    path.write_text(
        json.dumps({"format": FORMAT_V2, "entries": entries}), encoding="utf-8"
    )
    return str(path)


def write_scores(tmp_path, dataset, records, **changes):
    path = tmp_path / "scores.json"
    document = {
        "format": FORMAT_SCORES,
        "revision": REVISION,
        "dirty": False,
        "scored_at": "2026-09-24T12:00:00Z",
        "dataset": dataset,
        "dataset_sha256": json_sha256(dataset),
        "inputs_sha256": "inputs-hash",
        "inputs_revision": REVISION,
        "inputs_dirty": False,
        "inputs_recorded_at": "2026-09-24T12:00:00Z",
        "weight_changes": [],
        "records": records,
        **changes,
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def record(address, status="ok", score=None, chain_id=1):
    return {"chain_id": chain_id, "address": address, "status": status, "score": score}


def write_inputs(tmp_path, dataset, records, **changes):
    path = tmp_path / "inputs.json"
    document = {
        "format": FORMAT_INPUTS,
        "revision": REVISION,
        "dirty": False,
        "recorded_at": "2026-09-24T12:00:00Z",
        "dataset": dataset,
        "dataset_sha256": json_sha256(dataset),
        "analyzers": [
            {"name": result["name"], "weight": result["weight"]}
            for record in records
            if record.get("status", "ok") == "ok"
            for result in record["results"]
        ],
        "records": records,
        **changes,
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def analyzer_input(name, weight, score, data, flags=None, error=None):
    return {
        "name": name,
        "weight": weight,
        "score": score,
        "flags": flags or [],
        "data": data,
        "error": error,
    }


def complete_analyzer_inputs(weights=(4, 2.5, 2, 1.5, 1.5, 1)):
    return [
        analyzer_input(
            "structural",
            weights[0],
            100,
            {
                "status": "ok",
                "is_contract": True,
                "is_verified": True,
                "contract_age_days": 100,
                "coverage": {"scam_database": True, "bytecode": True},
                "scam_matches": [{"severity": "medium", "reason": "Community report"}],
                "observed_at": 1_700_000_000,
                "notes": ["Top holders checked"],
            },
        ),
        analyzer_input(
            "market",
            weights[1],
            80,
            {
                "status": "ok",
                "liquidity_usd": 200000,
                "observed_at": 1_700_000_001,
                "notes": ["Market observed"],
            },
        ),
        analyzer_input(
            "behavioral", weights[2], 50, {"status": "ok", "reputation_score": 80}
        ),
        analyzer_input(
            "honeypot",
            weights[3],
            0,
            {
                "status": "ok",
                "is_honeypot": False,
                "can_sell": True,
                "buy_tax": 0,
                "sell_tax": 0,
            },
        ),
        analyzer_input(
            "intent",
            weights[4],
            60,
            {"status": "ok", "floor": 70, "observed_at": 1_700_000_002},
        ),
        analyzer_input(
            "signature", weights[5], 0, {"status": "ok", "observed_at": 1_700_000_003}
        ),
    ]


# ---------------------------------------------------------------------------
# The committed v2 dataset
# ---------------------------------------------------------------------------


def test_the_dataset_holds_every_class_minimum_with_about_40_percent_safe():
    data = json.loads(Path(V2).read_text(encoding="utf-8"))
    entries = load_dataset(V2)
    # A stale entry stays in the file and is left out when it loads.
    assert 500 <= len(entries) <= len(data["entries"])
    counts = {name: sum(1 for e in entries if e.category == name) for name in CLASSES}
    assert all(counts[name] >= minimum for name, minimum in MINIMUMS.items()), counts
    assert 0.35 <= counts["safe"] / len(entries) <= 0.45
    described = ", ".join(f"{counts[name]} {name}" for name in CLASSES if counts[name])
    assert f"{len(entries)} entries ({described})" in data["description"]


def test_every_label_is_sourced_by_accepted_providers():
    entries = load_dataset(V2)
    for item in entries:
        assert item.sources and item.labeled, (item.chain_id, item.address)
        for source in item.sources:
            assert source["provider"] in LABEL_PROVIDERS
            assert (
                source["url"].startswith("https://")
                and source["retrieved"] >= item.labeled
            )
    assert IMPOSTORS <= {e.address for e in entries if e.category == "impostor_token"}


def test_no_address_is_listed_twice_on_a_chain():
    data = json.loads(Path(V2).read_text(encoding="utf-8"))
    keys = [(item["chain_id"], item["address"].lower()) for item in data["entries"]]
    assert len(keys) == len(set(keys))


def test_the_v1_safes_are_kept():
    v1_safes = {
        (e.chain_id, e.address)
        for e in load_dataset("eval/data/benchmark_v1.json")
        if e.label == "safe"
    }
    v2_safes = {(e.chain_id, e.address) for e in load_dataset(V2) if e.label == "safe"}
    assert len(v1_safes) == 20 and v1_safes <= v2_safes


# ---------------------------------------------------------------------------
# Format rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "item,message",
    [
        (entry(**{"class": "scam"}), "class must be one of"),
        (entry(address="0x1234"), "20-byte hex address"),
        (entry(chain_id="1"), "chain_id"),
        (entry(labeled="24 September 2026"), "labeled"),
        (entry(sources=[]), "at least one source"),
        (
            entry(sources=[{**SOURCE, "provider": "GoPlus"}]),
            "not an accepted label provider",
        ),
        (
            entry(sources=[SOURCE, {**SOURCE, "provider": "honeypot.is"}]),
            "not an accepted label provider",
        ),
        (
            entry(sources=[{**SOURCE, "provider": "chainabuse"}]),
            "not an accepted label provider",
        ),
        (
            entry(sources=[{**SOURCE, "provider": None}]),
            "every source needs a provider",
        ),
        (
            entry(**{"class": "safe"}, sources=[{**SOURCE, "provider": "goplus"}]),
            "not an accepted label provider",
        ),
        (entry(sources=[{**SOURCE, "retrieved": None}]), "retrieved date"),
        (entry(sources=[{**SOURCE, "url": "http://example.com"}]), "https url"),
        (entry(sources=[{**SOURCE, "evidence": ""}]), "evidence"),
        (entry(**{"class": "address_poisoning"}), "counterpart"),
        (entry(stale={"reason": "no date"}), "stale"),
    ],
)
def test_a_dataset_that_breaks_the_rules_is_refused(tmp_path, item, message):
    with pytest.raises(ValueError, match=message):
        load_dataset(write_dataset(tmp_path, [item]))


def test_label_providers_are_accepted_in_any_case(tmp_path):
    entries = load_dataset(
        write_dataset(
            tmp_path, [entry(sources=[{**SOURCE, "provider": "ScamSniffer"}])]
        )
    )
    assert [e.sources[0]["provider"] for e in entries] == ["ScamSniffer"]


def test_an_address_listed_twice_on_one_chain_is_refused(tmp_path):
    with pytest.raises(ValueError, match="listed twice"):
        load_dataset(
            write_dataset(
                tmp_path, [entry(), entry(address=DRAINER.upper().replace("0X", "0x"))]
            )
        )


def test_a_safe_label_needs_no_source_and_stale_entries_are_left_out(tmp_path):
    entries = load_dataset(
        write_dataset(
            tmp_path,
            [
                entry(**{"class": "safe"}, address=SAFE, sources=[]),
                entry(stale={"date": "2026-09-24", "reason": "no longer listed"}),
                entry(
                    **{"class": "address_poisoning"},
                    address="0x" + "a1" * 20,
                    counterpart="0x" + "a2" * 20,
                ),
            ],
        )
    )
    assert [(e.address, e.label, e.category) for e in entries] == [
        (SAFE, "safe", "safe"),
        ("0x" + "a1" * 20, "malicious", "address_poisoning"),
    ]
    assert entries[1].counterpart == "0x" + "a2" * 20


# ---------------------------------------------------------------------------
# Results from recorded scores, offline
# ---------------------------------------------------------------------------


def test_results_are_per_class_pinned_to_the_revision_and_never_count_unknown_as_passed(
    tmp_path,
):
    dataset = write_dataset(
        tmp_path,
        [
            entry(address="0x" + "d1" * 20),
            entry(address="0x" + "d2" * 20),
            entry(address="0x" + "d3" * 20),
            entry(address="0x" + "d4" * 20),
            entry(
                **{"class": "impostor_token"}, chain_id=4663, address="0x" + "e1" * 20
            ),
            entry(**{"class": "safe"}, address="0x" + "51" * 20, sources=[]),
            entry(**{"class": "safe"}, address="0x" + "52" * 20, sources=[]),
            entry(**{"class": "safe"}, address="0x" + "53" * 20, sources=[]),
        ],
    )
    scores = write_scores(
        tmp_path,
        dataset,
        [
            record("0x" + "d1" * 20, score=85),
            record("0x" + "d2" * 20, score=20),
            record("0x" + "d3" * 20, status="unknown", score=5),
            # 0xd4... has no record at all.
            record("0x" + "e1" * 20, status="error", chain_id=4663),
            record("0x" + "51" * 20, score=10),
            record("0x" + "52" * 20, score=50),
            record("0x" + "53" * 20, status="unknown", score=0),
        ],
    )

    results = build_results(dataset, scores, threshold=50)

    assert results["format"] == FORMAT_RESULTS
    assert (results["revision"], results["dirty"], results["scored_at"]) == (
        REVISION,
        False,
        "2026-09-24T12:00:00Z",
    )
    assert results["dataset"] == {
        "path": dataset.replace("\\", "/"),
        "sha256": json_sha256(dataset),
    }
    assert results["threshold"] == 50
    assert list(results["classes"]) == list(CLASSES)
    assert results["classes"]["drainer_contract"] == {
        "entries": 4,
        "decided": 2,
        "unknown": 2,
        "unknown_rate": 0.5,
        "flagged": 1,
        "recall": 0.5,
        "precision": 0.5,
    }
    assert results["classes"]["impostor_token"] == {
        "entries": 1,
        "decided": 0,
        "unknown": 1,
        "unknown_rate": 1.0,
        "flagged": 0,
        "recall": None,
        "precision": None,
    }
    assert results["classes"]["safe"] == {
        "entries": 3,
        "decided": 2,
        "unknown": 1,
        "unknown_rate": 0.3333,
        "flagged": 1,
        "false_positive_rate": 0.5,
    }
    assert results["classes"]["honeypot"] == {
        "entries": 0,
        "decided": 0,
        "unknown": 0,
        "unknown_rate": None,
        "flagged": 0,
        "recall": None,
        "precision": None,
    }
    assert results["overall"] == {
        "entries": 8,
        "unknown_rate": 0.5,
        "recall": 0.5,
        "precision": 0.5,
        "false_positive_rate": 0.5,
    }
    statuses = {
        row["address"]: (row["status"], row["flagged"]) for row in results["details"]
    }
    assert statuses["0x" + "d3" * 20] == ("unknown", None)
    assert statuses["0x" + "d4" * 20] == ("missing", None)
    assert statuses["0x" + "53" * 20] == ("unknown", None)
    assert build_results(dataset, scores, threshold=50) == results


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"format": "scores"}, "is not a shieldbot-scores/2 file"),
        ({"revision": None}, "git revision"),
        ({"revision": "abc1234"}, "git revision"),
        ({"dirty": "no"}, "local changes"),
        ({"scored_at": None}, "local changes"),
        ({"dataset_sha256": None}, "complete inputs provenance"),
        ({"inputs_sha256": None}, "complete inputs provenance"),
        ({"records": [record(DRAINER, score=None)]}, "malformed record"),
        ({"records": [record(DRAINER, status="clean", score=10)]}, "malformed record"),
        ({"records": [record(DRAINER, score=float("nan"))]}, "malformed record"),
        ({"records": [record(DRAINER, score=float("inf"))]}, "malformed record"),
        (
            {"records": [record(DRAINER, status="unknown", score=float("-inf"))]},
            "malformed record",
        ),
        ({"records": [record(DRAINER, score=True)]}, "malformed record"),
        (
            {"records": [{**record(DRAINER, score=90), "chain_id": "1"}]},
            "malformed record",
        ),
        ({"records": [{"status": "ok", "score": 90}]}, "malformed record"),
        (
            {
                "records": [
                    record(DRAINER, score=90),
                    record(DRAINER.upper().replace("0X", "0x"), score=10),
                ]
            },
            "recorded twice",
        ),
    ],
)
def test_scores_that_are_not_pinned_or_well_formed_are_refused(
    tmp_path, changes, message
):
    dataset = write_dataset(tmp_path, [entry()])
    changes = dict(changes)
    records = changes.pop("records", [record(DRAINER, score=90)])
    with pytest.raises(ValueError, match=message):
        load_scores(write_scores(tmp_path, dataset, records, **changes))


def test_scores_recorded_against_another_dataset_are_refused(tmp_path):
    dataset = write_dataset(tmp_path, [entry()])
    scores = write_scores(
        tmp_path, dataset, [record(DRAINER, score=90)], dataset_sha256="0" * 64
    )
    with pytest.raises(ValueError, match="different dataset"):
        build_results(dataset, scores)


def test_the_cli_never_makes_up_scores(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--dataset", V2])
    assert exit_info.value.code == 2
    error = capsys.readouterr().err
    assert "--scores is required" in error and "never makes up scores" in error


def test_the_cli_writes_the_results_file(tmp_path, capsys):
    dataset = write_dataset(
        tmp_path, [entry(), entry(**{"class": "safe"}, address=SAFE, sources=[])]
    )
    scores = write_scores(
        tmp_path,
        dataset,
        [record(DRAINER, score=90), record(SAFE, score=10)],
        dirty=None,
    )
    out = tmp_path / "results.json"
    assert cli.main(["--dataset", dataset, "--scores", scores, "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8")) == build_results(dataset, scores)
    printed = capsys.readouterr().out
    assert REVISION in printed and "local changes not checked" in printed


# ---------------------------------------------------------------------------
# Analyzer-input recording and offline replay
# ---------------------------------------------------------------------------


def test_the_live_scorer_records_raw_analyzer_inputs(tmp_path, monkeypatch):
    real_sleep = asyncio.sleep
    monkeypatch.setattr(live_scorer.asyncio, "sleep", lambda seconds: real_sleep(0))
    token_types = []
    normalized = [
        AnalyzerResult(
            "structural",
            0.4,
            70,
            flags=["Structural flag"],
            data={"source": "provider"},
        ),
        AnalyzerResult("market", 0.6, 20, error="market analysis unavailable"),
    ]

    contexts = []

    async def run_all(ctx):
        contexts.append(ctx)
        return normalized

    container = SimpleNamespace(
        web3_client=SimpleNamespace(is_token_contract=AsyncMock(return_value=False)),
        registry=SimpleNamespace(
            get_all=lambda: [
                SimpleNamespace(name="structural", weight=4),
                SimpleNamespace(name="market", weight=6),
            ],
            run_all=run_all,
        ),
        risk_engine=SimpleNamespace(
            compute_from_results=lambda results, is_token: (
                token_types.append(is_token)
                or {
                    "status": "ok",
                    "rug_probability": 50,
                    "risk_level": "MEDIUM",
                }
            )
        ),
    )
    inputs_path = tmp_path / "inputs.json"
    with live_scorer.InputRecorder(
        inputs_path,
        {
            "format": FORMAT_INPUTS,
            "revision": REVISION,
            "dirty": False,
            "recorded_at": "2026-09-24T12:00:00Z",
            "dataset": "fixture.json",
            "dataset_sha256": "dataset-hash",
            "analyzers": [
                {"name": "structural", "weight": 4},
                {"name": "market", "weight": 6},
            ],
        },
    ) as recorder:
        records = asyncio.run(
            live_scorer.score_entries(
                [
                    SimpleNamespace(
                        address=DRAINER,
                        chain_id=1,
                        category="drainer_contract",
                        label="malicious",
                    )
                ],
                container,
                recorder,
            )
        )
    inputs = replay.load_inputs(inputs_path)["records"]

    assert records[0]["score"] == 50
    assert contexts[0].is_token is False
    assert token_types == [False]
    assert inputs == [
        {
            "chain_id": 1,
            "address": DRAINER,
            "is_token": False,
            "status": "ok",
            "reason": None,
            "results": [
                {
                    "name": "structural",
                    "weight": 4,
                    "score": 70,
                    "flags": ["Structural flag"],
                    "data": {"source": "provider"},
                    "error": None,
                },
                {
                    "name": "market",
                    "weight": 6,
                    "score": 20,
                    "flags": [],
                    "data": {},
                    "error": "market analysis unavailable",
                },
            ],
        }
    ]


def test_replay_preserves_token_status_and_uses_none_for_older_inputs(tmp_path, monkeypatch):
    dataset = write_dataset(tmp_path, [entry(), entry(address=SAFE)])
    records = [
        {
            "chain_id": 1,
            "address": DRAINER,
            "is_token": False,
            "status": "ok",
            "reason": None,
            "results": complete_analyzer_inputs(),
        },
        {
            "chain_id": 1,
            "address": SAFE,
            "status": "ok",
            "reason": None,
            "results": complete_analyzer_inputs(),
        },
    ]
    weights = {
        result["name"]: result["weight"] for result in complete_analyzer_inputs()
    }
    inputs = write_inputs(
        tmp_path,
        dataset,
        records,
        analyzers=[{"name": name, "weight": weight} for name, weight in weights.items()],
    )
    seen = []

    class CapturingEngine(RiskEngine):
        def compute_from_results(self, results, is_token=True):
            seen.append(is_token)
            return super().compute_from_results(results, is_token=is_token)

    monkeypatch.setattr(
        replay, "current_engine_and_weights", lambda: (CapturingEngine(), weights)
    )

    replay.replay(inputs, tmp_path / "scores.json", REVISION, False)

    assert seen == [False, None]


def test_replay_scores_with_current_weights_not_recorded_weights(tmp_path, monkeypatch):
    dataset = write_dataset(tmp_path, [entry()])
    inputs = write_inputs(
        tmp_path,
        dataset,
        [
            {
                "chain_id": 1,
                "address": DRAINER,
                "status": "ok",
                "reason": None,
                "results": complete_analyzer_inputs(),
            }
        ],
    )
    output = tmp_path / "scores.json"
    current_weights = {
        result["name"]: result["weight"] for result in complete_analyzer_inputs()
    }
    current_weights["structural"] = 8
    engine = RiskEngine()
    current_results = [
        AnalyzerResult(
            "structural",
            8,
            100,
            data={
                "status": "ok",
                "is_contract": True,
                "is_verified": True,
                "contract_age_days": 100,
                "coverage": {"scam_database": True, "bytecode": True},
                "scam_matches": [
                    {"severity": "medium", "reason": "Community report"}
                ],
                "observed_at": 1_700_000_000,
                "notes": ["Top holders checked"],
            },
        ),
        AnalyzerResult(
            "market",
            2.5,
            80,
            data={
                "status": "ok",
                "liquidity_usd": 200000,
                "observed_at": 1_700_000_001,
                "notes": ["Market observed"],
            },
        ),
        AnalyzerResult(
            "behavioral", 2, 50, data={"status": "ok", "reputation_score": 80}
        ),
        AnalyzerResult(
            "honeypot",
            1.5,
            0,
            data={
                "status": "ok",
                "is_honeypot": False,
                "can_sell": True,
                "buy_tax": 0,
                "sell_tax": 0,
            },
        ),
        AnalyzerResult(
            "intent",
            1.5,
            60,
            data={"status": "ok", "floor": 70, "observed_at": 1_700_000_002},
        ),
        AnalyzerResult(
            "signature", 1, 0, data={"status": "ok", "observed_at": 1_700_000_003}
        ),
    ]
    recorded_results = [
        AnalyzerResult(
            result.name,
            4 if result.name == "structural" else result.weight,
            result.score,
            flags=result.flags,
            data=result.data,
            error=result.error,
        )
        for result in current_results
    ]
    current_score = engine.compute_from_results(replay.normalize_weights(current_results))
    recorded_score = engine.compute_from_results(
        replay.normalize_weights(recorded_results)
    )
    monkeypatch.setattr(
        replay, "current_engine_and_weights", lambda: (engine, current_weights)
    )

    document = replay.replay(inputs, output, REVISION, False)

    assert document["inputs_sha256"] == json_sha256(inputs)
    assert document["dataset_sha256"] == json_sha256(dataset)
    assert document["weight_changes"] == [
        {"name": "structural", "recorded_weight": 4, "current_weight": 8}
    ]
    assert document["records"][0]["score"] == current_score["rug_probability"]
    assert document["records"][0]["score"] != recorded_score["rug_probability"]
    assert document["records"][0]["risk_level"] == current_score["risk_level"]
    assert load_scores(output)["records"][(1, DRAINER)] == document["records"][0]


@pytest.mark.parametrize(
    ("current_weights", "message"),
    [
        (
            {
                "added": 1,
                **{
                    result["name"]: result["weight"]
                    for result in complete_analyzer_inputs()
                },
            },
            "added: added",
        ),
        (
            {
                result["name"]: result["weight"]
                for result in complete_analyzer_inputs()[1:]
            },
            "removed: structural",
        ),
    ],
)
def test_replay_refuses_an_added_or_removed_analyzer(
    tmp_path, monkeypatch, current_weights, message
):
    dataset = write_dataset(tmp_path, [entry()])
    inputs = write_inputs(
        tmp_path,
        dataset,
        [
            {
                "chain_id": 1,
                "address": DRAINER,
                "status": "ok",
                "reason": None,
                "results": complete_analyzer_inputs(),
            }
        ],
    )
    monkeypatch.setattr(
        replay, "current_engine_and_weights", lambda: (RiskEngine(), current_weights)
    )

    with pytest.raises(ValueError, match=message):
        replay.replay(inputs, tmp_path / "scores.json", REVISION, False)


def test_an_errored_live_entry_replays_to_the_same_error_record(tmp_path, monkeypatch):
    async def run_all(ctx):
        raise TimeoutError()

    container = SimpleNamespace(
        web3_client=SimpleNamespace(is_token_contract=AsyncMock(return_value=True)),
        registry=SimpleNamespace(get_all=lambda: [], run_all=run_all),
        risk_engine=SimpleNamespace(compute_from_results=lambda results, is_token: None),
    )
    inputs_path = tmp_path / "inputs.json"
    with live_scorer.InputRecorder(
        inputs_path,
        {
            "format": FORMAT_INPUTS,
            "revision": REVISION,
            "dirty": False,
            "recorded_at": "2026-09-24T12:00:00Z",
            "dataset": "fixture.json",
            "dataset_sha256": "dataset-hash",
            "analyzers": [],
        },
    ) as recorder:
        live_records = asyncio.run(
            live_scorer.score_entries(
                [
                    SimpleNamespace(
                        address=DRAINER,
                        chain_id=1,
                        category="drainer_contract",
                        label="malicious",
                    )
                ],
                container,
                recorder,
            )
        )
    monkeypatch.setattr(
        replay, "current_engine_and_weights", lambda: (RiskEngine(), {})
    )
    replayed = replay.replay(inputs_path, tmp_path / "scores.json", REVISION, False)

    assert replay.load_inputs(inputs_path)["records"] == [
        {
            "chain_id": 1,
            "address": DRAINER,
            "is_token": True,
            "status": "error",
            "reason": "TimeoutError",
            "results": [],
        }
    ]
    assert replayed["records"] == live_records


def test_rebuild_results_preserves_nested_engine_data_through_json(tmp_path):
    dataset = write_dataset(tmp_path, [entry()])
    inputs = write_inputs(
        tmp_path,
        dataset,
        [
            {
                "chain_id": 1,
                "address": DRAINER,
                "status": "ok",
                "reason": None,
                "results": complete_analyzer_inputs(),
            }
        ],
    )
    weights = {
        result["name"]: result["weight"] for result in complete_analyzer_inputs()
    }
    rebuilt = replay.normalize_weights(
        replay.rebuild_results(replay.load_inputs(inputs)["records"][0], weights)
    )
    structural = next(result for result in rebuilt if result.name == "structural")
    intent = next(result for result in rebuilt if result.name == "intent")

    assert structural.data["coverage"] == {"scam_database": True, "bytecode": True}
    assert structural.data["scam_matches"] == [
        {"severity": "medium", "reason": "Community report"}
    ]
    assert structural.data["observed_at"] == 1_700_000_000
    assert structural.data["notes"] == ["Top holders checked"]
    assert intent.data["floor"] == 70

    with_floor = RiskEngine().compute_from_results(rebuilt)
    intent.data.pop("floor")
    without_floor = RiskEngine().compute_from_results(rebuilt)
    assert with_floor["rug_probability"] > without_floor["rug_probability"]


def test_replay_and_results_carry_inputs_provenance(tmp_path, monkeypatch):
    dataset = write_dataset(tmp_path, [entry()])
    inputs = write_inputs(
        tmp_path,
        dataset,
        [
            {
                "chain_id": 1,
                "address": DRAINER,
                "status": "ok",
                "reason": None,
                "results": complete_analyzer_inputs(),
            }
        ],
    )
    weights = {
        result["name"]: result["weight"] for result in complete_analyzer_inputs()
    }
    monkeypatch.setattr(
        replay, "current_engine_and_weights", lambda: (RiskEngine(), weights)
    )
    scores_path = tmp_path / "scores.json"
    scores = replay.replay(inputs, scores_path, REVISION, False)
    results = build_results(dataset, scores_path)

    expected = {
        "inputs_sha256": json_sha256(inputs),
        "inputs_revision": REVISION,
        "inputs_dirty": False,
        "inputs_recorded_at": "2026-09-24T12:00:00Z",
    }
    assert {key: scores[key] for key in expected} == expected
    assert {key: results[key] for key in expected} == expected


def one_complete_input(tmp_path):
    dataset = write_dataset(tmp_path, [entry()])
    inputs = write_inputs(
        tmp_path,
        dataset,
        [
            {
                "chain_id": 1,
                "address": DRAINER,
                "status": "ok",
                "reason": None,
                "results": complete_analyzer_inputs(),
            }
        ],
    )
    weights = {
        result["name"]: result["weight"] for result in complete_analyzer_inputs()
    }
    return dataset, inputs, weights


def test_replay_reruns_the_named_analyzers_and_reads_the_rest_from_the_recording(
    tmp_path, monkeypatch
):
    dataset, inputs, weights = one_complete_input(tmp_path)
    seen = []

    rerun_data = {
        "intent": (100, {"status": "ok", "floor": 90}),
        "signature": (0, {"skipped": True}),
    }

    class Rerun:
        def __init__(self, name):
            self.name = name

        async def analyze(self, ctx):
            seen.append((self.name, ctx.address, ctx.chain_id, ctx.extra))
            score, data = rerun_data[self.name]
            return AnalyzerResult(self.name, 99, score, data=dict(data))

    monkeypatch.setattr(
        replay,
        "rerun_analyzers",
        lambda names: {name: lambda recorded, name=name: Rerun(name) for name in names},
    )
    engine = RiskEngine()
    monkeypatch.setattr(
        replay, "current_engine_and_weights", lambda: (engine, weights)
    )
    expected_results = [
        AnalyzerResult(
            "structural",
            4,
            100,
            data={
                "status": "ok",
                "is_contract": True,
                "is_verified": True,
                "contract_age_days": 100,
                "coverage": {"scam_database": True, "bytecode": True},
                "scam_matches": [
                    {"severity": "medium", "reason": "Community report"}
                ],
                "observed_at": 1_700_000_000,
                "notes": ["Top holders checked"],
            },
        ),
        AnalyzerResult(
            "market",
            2.5,
            80,
            data={
                "status": "ok",
                "liquidity_usd": 200000,
                "observed_at": 1_700_000_001,
                "notes": ["Market observed"],
            },
        ),
        AnalyzerResult(
            "behavioral", 2, 50, data={"status": "ok", "reputation_score": 80}
        ),
        AnalyzerResult(
            "honeypot",
            1.5,
            0,
            data={
                "status": "ok",
                "is_honeypot": False,
                "can_sell": True,
                "buy_tax": 0,
                "sell_tax": 0,
            },
        ),
        AnalyzerResult("intent", 1.5, 100, data={"status": "ok", "floor": 90}),
        AnalyzerResult("signature", 1, 0, data={"skipped": True}),
    ]
    for result in expected_results:
        result.weight = result.weight / 12.5
    expected = engine.compute_from_results(expected_results)
    scores_path = tmp_path / "scores.json"

    recorded = replay.replay(inputs, tmp_path / "recorded.json", REVISION, False)
    document = replay.replay(
        inputs, scores_path, REVISION, False, ["intent", "signature"]
    )

    assert sorted(seen) == [
        ("intent", DRAINER, 1, {}),
        ("signature", DRAINER, 1, {}),
    ]
    assert document["rerun"] == ["intent", "signature"]
    assert document["rerun_unavailable"] == {"intent": 0, "signature": 0}
    assert recorded["rerun"] == []
    assert recorded["rerun_unavailable"] == {}
    assert document["records"][0]["score"] == expected["rug_probability"]
    assert document["records"][0]["risk_level"] == expected["risk_level"]
    assert document["records"][0]["score"] != recorded["records"][0]["score"]
    results = build_results(dataset, scores_path)
    assert results["rerun"] == ["intent", "signature"]
    assert results["rerun_unavailable"] == {"intent": 0, "signature": 0}


def test_a_rerun_analyzer_that_reaches_for_a_provider_refuses_the_replay(
    tmp_path, monkeypatch
):
    _, inputs, weights = one_complete_input(tmp_path)

    class LooksUp:
        name = "behavioral"

        def __init__(self, service):
            self._service = service

        async def analyze(self, ctx):
            await self._service.fetch_wallet_reputation(ctx.address)

    monkeypatch.setattr(
        replay,
        "rerun_analyzers",
        lambda names: {"behavioral": lambda recorded: LooksUp(replay._Offline("behavioral"))},
    )
    monkeypatch.setattr(
        replay, "current_engine_and_weights", lambda: (RiskEngine(), weights)
    )
    output = tmp_path / "scores.json"

    with pytest.raises(
        ValueError,
        match="behavioral would make a network lookup [(]fetch_wallet_reputation[)]",
    ):
        replay.replay(inputs, output, REVISION, False, ["behavioral"])
    assert not output.exists()


def test_the_current_analyzers_rerun_offline(tmp_path, monkeypatch):
    dataset = write_dataset(tmp_path, [entry()])
    inputs = write_inputs(
        tmp_path, dataset, [behavioral_record({**ethos_response(), "counterparty": DRAINER}, score=0)]
    )
    weights = {
        result["name"]: result["weight"] for result in complete_analyzer_inputs()
    }
    monkeypatch.setattr(
        replay, "current_engine_and_weights", lambda: (RiskEngine(), weights)
    )

    document = replay.replay(
        inputs, tmp_path / "scores.json", REVISION, False, list(replay.RERUNNABLE)
    )

    assert document["records"][0]["status"] in ("ok", "unknown")
    assert document["rerun_unavailable"] == {
        "behavioral": 0,
        "intent": 0,
        "signature": 0,
    }


def ethos_response(**changes):
    """An EthosService.fetch_wallet_reputation response for an address with no Ethos profile."""
    response = {
        "observed_at": 1_700_000_004,
        "reputation_score": 50,
        "ethos_raw_score": None,
        "trust_level": "unknown",
        "scam_flags": [],
        "linked_wallets": [],
        "vouch_count": 0,
        "review_stats": {},
        "low_reputation_flag": False,
        "severe_reputation_flag": False,
    }
    return {**response, **changes}


def behavioral_record(data, score, flags=None, error=None):
    results = [
        analyzer_input("behavioral", result["weight"], score, data, flags, error)
        if result["name"] == "behavioral"
        else result
        for result in complete_analyzer_inputs()
    ]
    return {
        "chain_id": 1,
        "address": DRAINER,
        "status": "ok",
        "reason": None,
        "results": results,
    }


def replay_behavioral(tmp_path, monkeypatch, record):
    """Replay one recorded entry with behavioral rerun; the behavioral result the engine scored, and the scores."""
    dataset = write_dataset(tmp_path, [entry()])
    inputs = write_inputs(tmp_path, dataset, [record])
    weights = {
        result["name"]: result["weight"] for result in complete_analyzer_inputs()
    }
    scored = []

    class Capturing(RiskEngine):
        def compute_from_results(self, results, is_token=True):
            scored.extend(results)
            return super().compute_from_results(results, is_token=is_token)

    monkeypatch.setattr(
        replay, "current_engine_and_weights", lambda: (Capturing(), weights)
    )
    document = replay.replay(
        inputs, tmp_path / "scores.json", REVISION, False, ["behavioral"]
    )
    return next(result for result in scored if result.name == "behavioral"), document


def test_a_behavioral_rerun_scores_the_recorded_ethos_profile_with_the_current_logic(
    tmp_path, monkeypatch
):
    response = ethos_response(
        reputation_score=7.1,
        ethos_raw_score=200,
        trust_level="very_low",
        scam_flags=["Profile slashed on Ethos"],
        vouch_count=1,
        review_stats={"negative": 1},
        low_reputation_flag=True,
        severe_reputation_flag=True,
    )
    # Scored 0 with no flags, as a revision that ignored the profile would have recorded it.
    record = behavioral_record({**response, "counterparty": DRAINER}, score=0)

    behavioral, document = replay_behavioral(tmp_path, monkeypatch, record)

    assert behavioral.score == 90
    assert behavioral.flags == ["Severe reputation warning", "Ethos scam flags present"]
    assert behavioral.data == {**response, "counterparty": DRAINER}
    assert behavioral.error is None
    assert document["rerun_unavailable"] == {"behavioral": 0}


def test_a_behavioral_rerun_with_no_ethos_profile_uses_the_recorded_neutral_response(
    tmp_path, monkeypatch
):
    response = ethos_response()
    record = behavioral_record(
        {**response, "counterparty": DRAINER}, score=50, flags=["Recorded flag"]
    )

    behavioral, document = replay_behavioral(tmp_path, monkeypatch, record)

    assert behavioral.score == 0
    assert behavioral.flags == []
    assert behavioral.data == {"skipped": True, "reason": "no reputation profile"}
    assert document["rerun_unavailable"] == {"behavioral": 0}
    assert document["records"][0]["score"] == 70


def test_a_behavioral_rerun_keeps_an_unknown_ethos_response_unknown(
    tmp_path, monkeypatch
):
    response = ethos_response(status="unknown", reason="Ethos HTTP 503")
    record = behavioral_record({**response, "counterparty": DRAINER}, score=0)

    behavioral, document = replay_behavioral(tmp_path, monkeypatch, record)

    assert behavioral.flags == ["Behavioral data unknown: Ethos HTTP 503"]
    assert behavioral.data == {**response, "counterparty": DRAINER}
    assert document["rerun_unavailable"] == {"behavioral": 0}


@pytest.mark.parametrize(
    ("data", "error"),
    [
        ({}, "behavioral analysis unavailable (TimeoutError)"),
        ({"status": "ok", "reputation_score": 80}, None),
        (ethos_response(), None),
    ],
    ids=["errored", "partial-response", "no-counterparty"],
)
def test_a_behavioral_result_the_recording_cannot_answer_is_kept_and_counted(
    tmp_path, monkeypatch, data, error
):
    record = behavioral_record(
        data, score=50, flags=["behavioral analysis unavailable"], error=error
    )

    behavioral, document = replay_behavioral(tmp_path, monkeypatch, record)

    assert behavioral.score == 50
    assert behavioral.flags == ["behavioral analysis unavailable"]
    assert behavioral.data == data
    assert behavioral.error == error
    assert document["rerun_unavailable"] == {"behavioral": 1}
    assert build_results(
        write_dataset(tmp_path, [entry()]), tmp_path / "scores.json"
    )["rerun_unavailable"] == {"behavioral": 1}


def test_the_recorded_ethos_stand_in_answers_only_the_recorded_lookup():
    stand_in = replay._RecordedEthos(DRAINER, ethos_response())

    assert asyncio.run(stand_in.fetch_wallet_reputation("0x" + DRAINER[2:].upper())) == ethos_response()
    with pytest.raises(ValueError, match="not the recorded"):
        asyncio.run(stand_in.fetch_wallet_reputation(SAFE))
    with pytest.raises(ValueError, match="behavioral would make a network lookup"):
        stand_in.fetch_token_reputation


def test_only_the_transaction_analyzers_can_be_rerun(tmp_path, monkeypatch):
    _, inputs, weights = one_complete_input(tmp_path)
    monkeypatch.setattr(
        replay, "current_engine_and_weights", lambda: (RiskEngine(), weights)
    )

    with pytest.raises(ValueError, match="not honeypot"):
        replay.replay(
            inputs, tmp_path / "scores.json", REVISION, False, ["intent", "honeypot"]
        )


def test_the_replay_command_passes_the_rerun_list(monkeypatch):
    calls = []
    monkeypatch.setattr(replay, "current_revision", lambda: (REVISION, False))
    monkeypatch.setattr(replay, "replay", lambda *args: calls.append(args))

    replay.main(["--inputs", "in.json", "--output", "out.json"])
    replay.main(
        ["--inputs", "in.json", "--output", "out.json", "--rerun", "intent,behavioral"]
    )

    assert calls == [
        ("in.json", "out.json", REVISION, False, []),
        ("in.json", "out.json", REVISION, False, ["intent", "behavioral"]),
    ]


def test_input_recording_keeps_earlier_records_when_a_later_one_cannot_serialize(
    tmp_path, monkeypatch
):
    async def run_all(ctx):
        data = {} if ctx.address == DRAINER else {"unserializable": object()}
        return [AnalyzerResult("structural", 1, 0, data=data)]

    container = SimpleNamespace(
        web3_client=SimpleNamespace(is_token_contract=AsyncMock(return_value=True)),
        registry=SimpleNamespace(
            get_all=lambda: [SimpleNamespace(name="structural", weight=1)],
            run_all=run_all,
        ),
        risk_engine=SimpleNamespace(
            compute_from_results=lambda results, is_token: {
                "status": "ok",
                "rug_probability": 0,
                "risk_level": "LOW",
            }
        ),
    )
    real_sleep = asyncio.sleep
    monkeypatch.setattr(live_scorer.asyncio, "sleep", lambda seconds: real_sleep(0))
    inputs_path = tmp_path / "inputs.json"
    with (
        live_scorer.InputRecorder(
            inputs_path,
            {
                "format": FORMAT_INPUTS,
                "revision": REVISION,
                "dirty": False,
                "recorded_at": "2026-09-24T12:00:00Z",
                "dataset": "fixture.json",
                "dataset_sha256": "dataset-hash",
                "analyzers": [{"name": "structural", "weight": 1}],
            },
        ) as recorder,
        pytest.raises(TypeError),
    ):
        asyncio.run(
            live_scorer.score_entries(
                [
                    SimpleNamespace(
                        address=DRAINER,
                        chain_id=1,
                        category="drainer_contract",
                        label="malicious",
                    ),
                    SimpleNamespace(
                        address=SAFE,
                        chain_id=1,
                        category="drainer_contract",
                        label="malicious",
                    ),
                ],
                container,
                recorder,
            )
        )
    assert json.loads(inputs_path.read_text(encoding="utf-8"))["records"] == [
        {
            "chain_id": 1,
            "address": DRAINER,
            "is_token": True,
            "status": "ok",
            "reason": None,
            "results": [
                {
                    "name": "structural",
                    "weight": 1,
                    "score": 0,
                    "flags": [],
                    "data": {},
                    "error": None,
                }
            ],
        }
    ]


# ---------------------------------------------------------------------------
# The live scorer records what the scan said, and nothing else
# ---------------------------------------------------------------------------


def test_the_revision_ignores_untracked_files(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(
            stdout=REVISION + "\n" if command[1] == "rev-parse" else ""
        )

    monkeypatch.setattr(live_scorer.subprocess, "run", run)
    assert live_scorer.current_revision() == (REVISION, False)
    assert calls[1] == ["git", "status", "--porcelain", "--untracked-files=no"]


def test_the_live_scorer_records_unknown_and_failed_scans_without_inventing_scores(
    monkeypatch, caplog, capsys
):
    real_sleep = asyncio.sleep
    monkeypatch.setattr(live_scorer.asyncio, "sleep", lambda seconds: real_sleep(0))
    outputs = {
        "0x" + "01" * 20: {
            "status": "ok",
            "rug_probability": 72.5,
            "risk_level": "HIGH",
        },
        "0x" + "02" * 20: {
            "status": "unknown",
            "rug_probability": 12.0,
            "risk_level": "LOW",
            "coverage_reasons": {"honeypot": "Sell simulation unavailable"},
        },
        "0x" + "03" * 20: {"status": "ok", "risk_level": "LOW"},
    }

    async def run_all(ctx):
        if ctx.address == "0x" + "04" * 20:
            raise TimeoutError("scan deadline SECRET-PROVIDER-TEXT")
        return ctx.address

    container = SimpleNamespace(
        web3_client=SimpleNamespace(is_token_contract=AsyncMock(return_value=True)),
        registry=SimpleNamespace(run_all=run_all),
        risk_engine=SimpleNamespace(
            compute_from_results=lambda address, is_token=True: outputs[address]
        ),
    )
    entries = [
        SimpleNamespace(
            address="0x" + f"{index:02d}" * 20,
            chain_id=1,
            category="drainer_contract",
            label="malicious",
        )
        for index in range(1, 5)
    ]

    records = asyncio.run(live_scorer.score_entries(entries, container))

    assert [
        (r["status"], r["score"], r["risk_level"], r["reason"]) for r in records
    ] == [
        ("ok", 72.5, "HIGH", None),
        ("unknown", 12.0, "LOW", "honeypot: Sell simulation unavailable"),
        ("unknown", None, "LOW", "Incomplete scan"),
        ("error", None, None, "TimeoutError"),
    ]
    # A failed scan is reported by exception class only, never by its text.
    assert "SECRET-PROVIDER-TEXT" not in caplog.text
    assert "SECRET-PROVIDER-TEXT" not in capsys.readouterr().out
