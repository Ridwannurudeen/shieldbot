"""Benchmark results: per-class recall, precision and unknown rate of recorded scores against a labeled dataset."""

import hashlib
import json
import logging
import math
import re
from pathlib import Path
from typing import Dict, List, Optional

from eval.dataset import CLASSES, BenchmarkEntry, load_dataset

logger = logging.getLogger(__name__)

# Threshold for classifying a score as "flagged" (malicious)
DEFAULT_FLAG_THRESHOLD = 50.0
FORMAT_SCORES = "shieldbot-scores/1"
FORMAT_RESULTS = "shieldbot-benchmark-results/1"
# ok: the scan completed and its score decides; unknown: the scan reported incomplete coverage;
# error: the scan failed. Only ok records are decided.
RECORD_STATUSES = ("ok", "unknown", "error")
_REVISION = re.compile(r"[0-9a-f]{40}")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")


def json_sha256(path: str) -> str:
    """sha256 of a JSON file's canonical form (sorted keys, no whitespace), the same on every platform."""
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def load_scores(path: str) -> dict:
    """Read recorded scores (FORMAT_SCORES, as eval.live_scorer writes them), keyed by (chain_id, address).

    Raises ValueError for a file that is not pinned to a git revision and a dataset, or that holds a
    malformed record, so results are never computed from scores of unknown origin.
    """
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict) or data.get('format') != FORMAT_SCORES:
        raise ValueError(f"{path} is not a {FORMAT_SCORES} file")
    if not isinstance(data.get('revision'), str) or not _REVISION.fullmatch(data['revision']):
        raise ValueError(f"{path} is not pinned to a 40-character git revision")
    # dirty is null when the revision was given by hand and local changes could not be checked.
    if 'dirty' not in data or type(data['dirty']) not in (bool, type(None)) or not isinstance(data.get('scored_at'), str):
        raise ValueError(f"{path} does not say when it was scored and whether the revision had local changes")
    if not isinstance(data.get('dataset_sha256'), str):
        raise ValueError(f"{path} does not name the dataset it scored")
    records = {}
    for index, record in enumerate(data.get('records', [])):
        if not (
            isinstance(record, dict)
            and type(record.get('chain_id')) is int
            and isinstance(record.get('address'), str) and _ADDRESS.fullmatch(record['address'])
            and record.get('status') in RECORD_STATUSES
            and _valid_score(record.get('score'), record['status'])
        ):
            raise ValueError(f"{path}: malformed record {index}")
        key = (record['chain_id'], record['address'].lower())
        if key in records:
            raise ValueError(f"{path}: {record['address']} on chain {record['chain_id']} is recorded twice")
        records[key] = record
    return {**data, 'records': records}


def _valid_score(score, status: str) -> bool:
    """A finite number, or absent where the scan did not complete."""
    if score is None:
        return status != 'ok'
    return type(score) in (int, float) and math.isfinite(score)


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, 4) if denominator else None


def _tally(rows: List[Dict]) -> Dict:
    decided = [row for row in rows if row['flagged'] is not None]
    flagged = sum(1 for row in decided if row['flagged'])
    return {
        'entries': len(rows),
        'decided': len(decided),
        'unknown': len(rows) - len(decided),
        'unknown_rate': _ratio(len(rows) - len(decided), len(rows)),
        'flagged': flagged,
    }


def benchmark_results(entries: List[BenchmarkEntry], records: Dict, threshold: float) -> Dict:
    """Per-class results of recorded scores against labeled entries.

    An entry is decided when its record's status is "ok": flagged at or above `threshold`, passed below
    it. An unknown or failed scan, or an entry with no record, is unknown: never counted as passed or
    flagged, and reported as its class's unknown rate. For a malicious class, recall is flagged / decided
    and precision is flagged / (flagged + flagged safe entries), the precision the flag would have on that
    class and the safe entries alone. For the safe class, false_positive_rate is flagged / decided.
    """
    details = []
    for entry in entries:
        record = records.get((entry.chain_id, entry.address.lower()))
        decided = record is not None and record['status'] == 'ok'
        details.append({
            'chain_id': entry.chain_id,
            'address': entry.address,
            'class': 'safe' if entry.label == 'safe' else entry.category or 'malicious',
            'status': record['status'] if record is not None else 'missing',
            'score': record.get('score') if record is not None else None,
            'flagged': record['score'] >= threshold if decided else None,
        })
    names = list(CLASSES) + sorted({row['class'] for row in details} - set(CLASSES))
    safe = _tally([row for row in details if row['class'] == 'safe'])
    safe['false_positive_rate'] = _ratio(safe['flagged'], safe['decided'])
    classes = {'safe': safe}
    for name in names:
        if name == 'safe':
            continue
        tally = _tally([row for row in details if row['class'] == name])
        tally['recall'] = _ratio(tally['flagged'], tally['decided'])
        tally['precision'] = (
            _ratio(tally['flagged'], tally['flagged'] + safe['flagged']) if tally['decided'] else None
        )
        classes[name] = tally
    malicious = _tally([row for row in details if row['class'] != 'safe'])
    overall = {
        'entries': len(details),
        'unknown_rate': _ratio(malicious['unknown'] + safe['unknown'], len(details)),
        'recall': _ratio(malicious['flagged'], malicious['decided']),
        'precision': (
            _ratio(malicious['flagged'], malicious['flagged'] + safe['flagged']) if malicious['decided'] else None
        ),
        'false_positive_rate': safe['false_positive_rate'],
    }
    return {'overall': overall, 'classes': {name: classes[name] for name in names}, 'details': details}


def build_results(dataset_path: str, scores_path: str, threshold: float = DEFAULT_FLAG_THRESHOLD) -> Dict:
    """The results file (FORMAT_RESULTS) for recorded scores, computed offline.

    It is dated by when the scores were recorded and pinned to the revision that recorded them, so the
    same inputs always give the same file. Raises ValueError when the scores were recorded against a
    different dataset file.
    """
    entries = load_dataset(dataset_path)
    scores = load_scores(scores_path)
    dataset_sha256 = json_sha256(dataset_path)
    if scores['dataset_sha256'] != dataset_sha256:
        raise ValueError(f"{scores_path} was recorded against a different dataset than {dataset_path}")
    return {
        'format': FORMAT_RESULTS,
        'scored_at': scores['scored_at'],
        'revision': scores['revision'],
        'dirty': scores['dirty'],
        'dataset': {'path': Path(dataset_path).as_posix(), 'sha256': dataset_sha256},
        'scores_sha256': json_sha256(scores_path),
        'threshold': threshold,
        **benchmark_results(entries, scores['records'], threshold),
    }
