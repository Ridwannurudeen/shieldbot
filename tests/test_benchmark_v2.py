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
from eval.benchmark import FORMAT_RESULTS, FORMAT_SCORES, build_results, json_sha256, load_scores
from eval.dataset import CLASSES, FORMAT_V2, LABEL_PROVIDERS, load_dataset

V2 = "eval/data/benchmark_v2.json"
REVISION = "0123456789abcdef0123456789abcdef01234567"
IMPOSTORS = {
    "0x1c2a482970ae6b6e5052a7a184c8aef19e0840be",
    "0xf01ab9476afcaa0e0058c83cef2b4c30867abeeb",
    "0x982732a974738b771b07a2588f1b38a968a11e18",
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


# ---------------------------------------------------------------------------
# The committed v2 dataset
# ---------------------------------------------------------------------------


def test_the_seed_holds_only_independently_sourced_malicious_labels():
    data = json.loads(Path(V2).read_text(encoding="utf-8"))
    entries = load_dataset(V2)
    assert len(entries) == len(data["entries"]) == 38
    counts = {name: sum(1 for e in entries if e.category == name) for name in CLASSES}
    assert counts == {
        "honeypot": 0,
        "rug_pull": 0,
        "drainer_contract": 15,
        "approval_drainer_spender": 0,
        "address_poisoning": 0,
        "impostor_token": 3,
        "fake_claim": 0,
        "safe": 20,
    }
    for item in entries:
        if item.label == "safe":
            continue
        assert item.sources and item.labeled
        for source in item.sources:
            assert source["provider"] in LABEL_PROVIDERS
            assert source["url"].startswith("https://") and source["retrieved"] >= item.labeled
    assert {e.address for e in entries if e.category == "impostor_token"} == IMPOSTORS


def test_the_seed_safes_are_the_v1_safes():
    v1_safes = {
        (e.chain_id, e.address)
        for e in load_dataset("eval/data/benchmark_v1.json")
        if e.label == "safe"
    }
    v2_safes = {(e.chain_id, e.address) for e in load_dataset(V2) if e.label == "safe"}
    assert v2_safes == v1_safes and len(v2_safes) == 20


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
