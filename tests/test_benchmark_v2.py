"""Benchmark v2: class-stratified labels with independent sources, recorded scores and offline results.

The recorded scores here are written by the tests for the tests; they are not measurements.
"""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import eval.cli as cli
import eval.live_scorer as live_scorer
import eval.replay as replay
from core.analyzer import AnalyzerResult
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine
from eval.benchmark import FORMAT_INPUTS, FORMAT_RESULTS, FORMAT_SCORES, build_results, json_sha256, load_scores
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
    path.write_text(json.dumps({"format": FORMAT_V2, "entries": entries}), encoding="utf-8")
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
        "scored_at": "2026-09-24T12:00:00Z",
        "dataset": dataset,
        "dataset_sha256": json_sha256(dataset),
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


def complete_analyzer_inputs(weights=(4, 2.5, 2, 1.5)):
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
            },
        ),
        analyzer_input(
            "market", weights[1], 80, {"status": "ok", "liquidity_usd": 200000}
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
            assert source["url"].startswith("https://") and source["retrieved"] >= item.labeled
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
        (entry(sources=[{**SOURCE, "provider": "GoPlus"}]), "not an accepted label provider"),
        (
            entry(sources=[SOURCE, {**SOURCE, "provider": "honeypot.is"}]),
            "not an accepted label provider",
        ),
        (entry(sources=[{**SOURCE, "provider": "chainabuse"}]), "not an accepted label provider"),
        (entry(sources=[{**SOURCE, "provider": None}]), "every source needs a provider"),
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
        write_dataset(tmp_path, [entry(sources=[{**SOURCE, "provider": "ScamSniffer"}])])
    )
    assert [e.sources[0]["provider"] for e in entries] == ["ScamSniffer"]


def test_an_address_listed_twice_on_one_chain_is_refused(tmp_path):
    with pytest.raises(ValueError, match="listed twice"):
        load_dataset(
            write_dataset(tmp_path, [entry(), entry(address=DRAINER.upper().replace("0X", "0x"))])
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


def test_results_are_per_class_pinned_to_the_revision_and_never_count_unknown_as_passed(tmp_path):
    dataset = write_dataset(
        tmp_path,
        [
            entry(address="0x" + "d1" * 20),
            entry(address="0x" + "d2" * 20),
            entry(address="0x" + "d3" * 20),
            entry(address="0x" + "d4" * 20),
            entry(**{"class": "impostor_token"}, chain_id=4663, address="0x" + "e1" * 20),
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
    statuses = {row["address"]: (row["status"], row["flagged"]) for row in results["details"]}
    assert statuses["0x" + "d3" * 20] == ("unknown", None)
    assert statuses["0x" + "d4" * 20] == ("missing", None)
    assert statuses["0x" + "53" * 20] == ("unknown", None)
    assert build_results(dataset, scores, threshold=50) == results


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"format": "scores"}, "is not a shieldbot-scores/1 file"),
        ({"revision": None}, "git revision"),
        ({"revision": "abc1234"}, "git revision"),
        ({"dirty": "no"}, "local changes"),
        ({"scored_at": None}, "local changes"),
        ({"dataset_sha256": None}, "does not name the dataset"),
        ({"records": [record(DRAINER, score=None)]}, "malformed record"),
        ({"records": [record(DRAINER, status="clean", score=10)]}, "malformed record"),
        ({"records": [record(DRAINER, score=float("nan"))]}, "malformed record"),
        ({"records": [record(DRAINER, score=float("inf"))]}, "malformed record"),
        ({"records": [record(DRAINER, status="unknown", score=float("-inf"))]}, "malformed record"),
        ({"records": [record(DRAINER, score=True)]}, "malformed record"),
        ({"records": [{**record(DRAINER, score=90), "chain_id": "1"}]}, "malformed record"),
        ({"records": [{"status": "ok", "score": 90}]}, "malformed record"),
        (
            {"records": [record(DRAINER, score=90), record(DRAINER.upper().replace("0X", "0x"), score=10)]},
            "recorded twice",
        ),
    ],
)
def test_scores_that_are_not_pinned_or_well_formed_are_refused(tmp_path, changes, message):
    dataset = write_dataset(tmp_path, [entry()])
    changes = dict(changes)
    records = changes.pop("records", [record(DRAINER, score=90)])
    with pytest.raises(ValueError, match=message):
        load_scores(write_scores(tmp_path, dataset, records, **changes))


def test_scores_recorded_against_another_dataset_are_refused(tmp_path):
    dataset = write_dataset(tmp_path, [entry()])
    scores = write_scores(tmp_path, dataset, [record(DRAINER, score=90)], dataset_sha256="0" * 64)
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
        tmp_path, dataset, [record(DRAINER, score=90), record(SAFE, score=10)], dirty=None
    )
    out = tmp_path / "results.json"
    assert cli.main(["--dataset", dataset, "--scores", scores, "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8")) == build_results(dataset, scores)
    printed = capsys.readouterr().out
    assert REVISION in printed and "local changes not checked" in printed


# ---------------------------------------------------------------------------
# Analyzer-input recording and offline replay
# ---------------------------------------------------------------------------


def test_the_live_scorer_records_raw_analyzer_inputs(monkeypatch):
    real_sleep = asyncio.sleep
    monkeypatch.setattr(live_scorer.asyncio, "sleep", lambda seconds: real_sleep(0))
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

    async def run_all(ctx):
        return normalized

    container = SimpleNamespace(
        registry=SimpleNamespace(
            get_all=lambda: [SimpleNamespace(weight=4), SimpleNamespace(weight=6)],
            run_all=run_all,
        ),
        risk_engine=SimpleNamespace(
            compute_from_results=lambda results: {
                "status": "ok",
                "rug_probability": 50,
                "risk_level": "MEDIUM",
            }
        ),
    )
    inputs = []
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
            inputs,
        )
    )

    assert records[0]["score"] == 50
    assert inputs == [
        {
            "chain_id": 1,
            "address": DRAINER,
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


def test_replay_matches_the_current_engine_and_produces_cli_scores(tmp_path, capsys):
    dataset = write_dataset(tmp_path, [entry()])
    inputs = write_inputs(
        tmp_path,
        dataset,
        [
            {
                "chain_id": 1,
                "address": DRAINER,
                "results": complete_analyzer_inputs(),
            }
        ],
    )
    output = tmp_path / "scores.json"
    direct_results = [
        AnalyzerResult(
            result["name"],
            result["weight"] / 10,
            result["score"],
            result["flags"],
            result["data"],
        )
        for result in complete_analyzer_inputs()
    ]
    expected = RiskEngine().compute_from_results(direct_results)

    document = replay.replay(inputs, output, REVISION, False)

    assert document["inputs_sha256"] == json_sha256(inputs)
    assert document["dataset_sha256"] == json_sha256(dataset)
    assert document["records"][0]["score"] == expected["rug_probability"]
    assert document["records"][0]["risk_level"] == expected["risk_level"]
    assert load_scores(output)["records"][(1, DRAINER)] == document["records"][0]
    assert cli.main(["--dataset", dataset, "--scores", str(output)]) == 0
    assert REVISION in capsys.readouterr().out


def test_replay_normalizes_raw_weights_like_the_registry_and_leaves_normalized_weights_alone():
    raw = replay.normalize_weights(
        replay.rebuild_results({"results": complete_analyzer_inputs()})
    )
    normalized = replay.normalize_weights(
        replay.rebuild_results(
            {
                "results": complete_analyzer_inputs((0.4, 0.25, 0.2, 0.15)),
            }
        )
    )

    class FakeAnalyzer:
        def __init__(self, result):
            self.name = result.name
            self.weight = result.weight * 10

        async def analyze(self, ctx):
            return AnalyzerResult(self.name, self.weight, 0)

    registry = AnalyzerRegistry()
    for result in normalized:
        registry.register(FakeAnalyzer(result))
    registry_weights = [
        result.weight
        for result in asyncio.run(registry.run_all(SimpleNamespace(address=DRAINER)))
    ]

    assert [result.weight for result in raw] == [0.4, 0.25, 0.2, 0.15]
    assert sum(result.weight for result in raw) == 1.0
    assert [result.weight for result in normalized] == [0.4, 0.25, 0.2, 0.15]
    assert registry_weights == [result.weight for result in raw]


def test_replay_preserves_errored_results_for_fail_closed_coverage(tmp_path):
    dataset = write_dataset(tmp_path, [entry()])
    results = complete_analyzer_inputs()
    results[0] = analyzer_input(
        "structural",
        4,
        100,
        {"status": "ok"},
        error="structural analysis unavailable (TimeoutError)",
    )
    inputs = write_inputs(
        tmp_path, dataset, [{"chain_id": 1, "address": DRAINER, "results": results}]
    )

    rebuilt = replay.normalize_weights(
        replay.rebuild_results(replay.load_inputs(inputs)["records"][0])
    )
    risk = RiskEngine().compute_from_results(rebuilt)

    assert rebuilt[0].error == "structural analysis unavailable (TimeoutError)"
    assert risk["category_scores"]["structural"] is None
    assert risk["coverage_reasons"]["structural"] == rebuilt[0].error
    assert (
        replay.replay_records(replay.load_inputs(inputs)["records"])[0]["status"]
        == "unknown"
    )


# ---------------------------------------------------------------------------
# The live scorer records what the scan said, and nothing else
# ---------------------------------------------------------------------------


def test_the_revision_ignores_untracked_files(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(stdout=REVISION + "\n" if command[1] == "rev-parse" else "")

    monkeypatch.setattr(live_scorer.subprocess, "run", run)
    assert live_scorer.current_revision() == (REVISION, False)
    assert calls[1] == ["git", "status", "--porcelain", "--untracked-files=no"]


def test_the_live_scorer_records_unknown_and_failed_scans_without_inventing_scores(
    monkeypatch, caplog, capsys
):
    real_sleep = asyncio.sleep
    monkeypatch.setattr(live_scorer.asyncio, "sleep", lambda seconds: real_sleep(0))
    outputs = {
        "0x" + "01" * 20: {"status": "ok", "rug_probability": 72.5, "risk_level": "HIGH"},
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
        registry=SimpleNamespace(run_all=run_all),
        risk_engine=SimpleNamespace(compute_from_results=lambda address: outputs[address]),
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

    assert [(r["status"], r["score"], r["risk_level"], r["reason"]) for r in records] == [
        ("ok", 72.5, "HIGH", None),
        ("unknown", 12.0, "LOW", "honeypot: Sell simulation unavailable"),
        ("unknown", None, "LOW", "Incomplete scan"),
        ("error", None, None, "TimeoutError"),
    ]
    # A failed scan is reported by exception class only, never by its text.
    assert "SECRET-PROVIDER-TEXT" not in caplog.text
    assert "SECRET-PROVIDER-TEXT" not in capsys.readouterr().out
