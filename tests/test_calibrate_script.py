"""scripts/calibrate.py proposes thresholds from trusted labels only and never touches the live config."""

import json
from pathlib import Path

import pytest
import pytest_asyncio

from core.database import Database
from eval.benchmark import FORMAT_SCORES, json_sha256
from scripts import calibrate


ROOT = Path(__file__).resolve().parent.parent
LIVE_CONFIG = ROOT / "core" / "calibration_config.json"


@pytest_asyncio.fixture
async def db_path(tmp_path):
    path = (tmp_path / "outcomes.sqlite").as_posix()
    database = Database(path)
    await database.initialize()
    yield path, database
    await database.close()


async def _record(database, score, outcome, source, count):
    for index in range(count):
        await database.record_outcome(
            address=f"0x{index:040x}",
            risk_score_at_scan=score,
            user_decision="block",
            outcome=outcome,
            source=source,
        )


def _run(tmp_path, db, *extra):
    out = tmp_path / "proposal.json"
    assert calibrate.main(["--db", db, "--out", str(out), *extra]) == 0
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.mark.asyncio
async def test_client_rows_are_ignored(tmp_path, db_path):
    path, database = db_path
    # Enough client rows to move any threshold, all pointing the wrong way.
    await _record(database, 5.0, "scam", "client", 50)
    await _record(database, 95.0, "safe", "client", 50)
    proposal = _run(tmp_path, path)
    assert proposal["proposed"] is None
    assert proposal["labels"]["total"] == 0
    assert proposal["labels"]["outcomes"]["by_source"] == {}


@pytest.mark.asyncio
async def test_api_key_rows_are_read_and_attributed(tmp_path, db_path):
    path, database = db_path
    await _record(database, 5.0, "scam", "client", 50)
    await _record(database, 95.0, "scam", "key:sb_partner", 12)
    await _record(database, 15.0, "safe", "key:sb_partner", 6)
    await _record(database, 15.0, "safe", "key:sb_other", 6)
    await _record(database, 60.0, "unknown", "key:sb_other", 5)
    proposal = _run(tmp_path, path)
    assert proposal["labels"]["total"] == 24
    assert proposal["labels"]["outcomes"]["by_source"] == {"key:sb_other": 6, "key:sb_partner": 18}
    assert proposal["bins"]["0"] == {"safe": 0, "scam": 0}
    assert proposal["bins"]["10"] == {"safe": 12, "scam": 0}
    assert proposal["bins"]["90"] == {"safe": 0, "scam": 12}
    assert proposal["proposed"]["high_threshold"] == 90.0
    high = proposal["metrics"]["proposed"]["high"]
    assert (high["precision"], high["recall"]) == (1.0, 1.0)
    assert proposal["current"]["high_threshold"] == 71.0


@pytest.mark.asyncio
async def test_too_few_trusted_rows_gives_no_proposal(tmp_path, db_path):
    path, database = db_path
    await _record(database, 95.0, "scam", "key:sb_partner", 19)
    proposal = _run(tmp_path, path)
    assert proposal["proposed"] is None
    assert proposal["reason"] == "19 trusted labels; at least 20 are needed"
    assert proposal["labels"]["total"] == 19
    assert proposal["current"]["high_threshold"] == 71.0


@pytest.mark.asyncio
async def test_the_live_config_is_untouched(tmp_path, db_path):
    path, database = db_path
    await _record(database, 95.0, "scam", "key:sb_partner", 15)
    await _record(database, 10.0, "safe", "key:sb_partner", 15)
    before = LIVE_CONFIG.read_bytes()
    proposal = _run(tmp_path, path)
    assert proposal["proposed"] is not None
    assert LIVE_CONFIG.read_bytes() == before
    with pytest.raises(SystemExit):
        calibrate.main(["--db", path, "--out", str(LIVE_CONFIG)])
    assert LIVE_CONFIG.read_bytes() == before


def _benchmark(tmp_path, records):
    entries = [
        {"class": "safe", "chain_id": 56, "address": "0x" + "a" * 40, "labeled": "2026-09-24"},
        {
            "class": "drainer_contract",
            "chain_id": 1,
            "address": "0x" + "b" * 40,
            "labeled": "2026-09-24",
            "sources": [
                {
                    "provider": "scamsniffer",
                    "url": "https://example.com/list",
                    "retrieved": "2026-09-24",
                    "evidence": "listed",
                }
            ],
        },
        {"class": "safe", "chain_id": 56, "address": "0x" + "c" * 40, "labeled": "2026-09-24"},
    ]
    dataset = tmp_path / "benchmark.json"
    dataset.write_text(
        json.dumps({"format": "shieldbot-benchmark/2", "entries": entries}), encoding="utf-8"
    )
    scores = tmp_path / "scores.json"
    scores.write_text(
        json.dumps(
            {
                "format": FORMAT_SCORES,
                "revision": "0" * 40,
                "dirty": False,
                "scored_at": "2026-09-24T00:00:00Z",
                "dataset": str(dataset),
                "dataset_sha256": json_sha256(str(dataset)),
                "records": records,
            }
        ),
        encoding="utf-8",
    )
    return str(dataset), str(scores)


@pytest.mark.asyncio
async def test_benchmark_scores_are_trusted_labels_and_unknown_scans_are_left_out(
    tmp_path, db_path
):
    path, _ = db_path
    dataset, scores = _benchmark(
        tmp_path,
        [
            {"chain_id": 56, "address": "0x" + "a" * 40, "status": "ok", "score": 12.0},
            {"chain_id": 1, "address": "0x" + "b" * 40, "status": "ok", "score": 88.0},
            {"chain_id": 56, "address": "0x" + "c" * 40, "status": "unknown", "score": 40.0},
        ],
    )
    proposal = _run(tmp_path, path, "--dataset", dataset, "--scores", scores)
    assert proposal["labels"]["benchmark"]["rows"] == 2
    assert (proposal["labels"]["safe"], proposal["labels"]["scam"]) == (1, 1)
    assert proposal["bins"]["10"] == {"safe": 1, "scam": 0}
    assert proposal["bins"]["80"] == {"safe": 0, "scam": 1}
    assert proposal["bins"]["40"] == {"safe": 0, "scam": 0}


def test_scores_recorded_against_another_dataset_are_refused(tmp_path):
    dataset, scores = _benchmark(tmp_path, [])
    Path(dataset).write_text(
        json.dumps({"format": "shieldbot-benchmark/2", "entries": []}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="different dataset"):
        calibrate.benchmark_labels(dataset, scores)
