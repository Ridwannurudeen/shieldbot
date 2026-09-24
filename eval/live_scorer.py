"""Live benchmark scorer — runs each entry through the real analysis pipeline.

It records, for every entry, whether the scan completed ("ok"), reported incomplete coverage ("unknown")
or failed ("error"), with its score, pinned to the git revision that ran it. A missing score stays
missing; nothing is filled in. `python -m eval.cli` then computes the results offline.

Usage:
    python -m eval.live_scorer --dataset eval/data/benchmark_v2.json
    python -m eval.live_scorer --dataset eval/data/benchmark_v2.json --output eval/data/live_scores.json
"""

import argparse
import asyncio
import datetime
import json
import logging
import re
import subprocess
import sys
import time

from eval.dataset import load_dataset
from eval.benchmark import FORMAT_SCORES, json_sha256

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.WARNING,
)
logger = logging.getLogger(__name__)


async def score_entries(entries, container):
    """Scan each benchmark entry with the composite analysis pipeline; one record per entry."""
    from core.analyzer import AnalysisContext

    records = []
    total = len(entries)

    for i, entry in enumerate(entries, 1):
        addr = entry.address
        chain_id = entry.chain_id
        tag = f"[{i}/{total}]"
        record = {"chain_id": chain_id, "address": addr.lower(), "status": "error", "score": None,
                  "risk_level": None, "reason": None}

        try:
            ctx = AnalysisContext(address=addr, chain_id=chain_id)
            results = await container.registry.run_all(ctx)
            risk_output = container.risk_engine.compute_from_results(results)
            score = risk_output.get('rug_probability')
            record["score"] = score
            record["risk_level"] = risk_output.get('risk_level')
            if risk_output.get('status') == 'ok' and score is not None:
                record["status"] = "ok"
            else:
                record["status"] = "unknown"
                record["reason"] = "; ".join(
                    f"{name}: {reason}" for name, reason in (risk_output.get('coverage_reasons') or {}).items()
                ) or "Incomplete scan"
            print(f"  {tag} chain={chain_id} {addr[:16]}... status={record['status']} score={score} "
                  f"level={record['risk_level']} class={entry.category or entry.label}")

        except Exception as e:
            logger.error(f"{tag} Error scoring {addr}: {e}")
            record["reason"] = type(e).__name__
            print(f"  X{tag} chain={chain_id} {addr[:16]}... ERROR: {e}")

        records.append(record)
        # Small delay to avoid rate-limiting external APIs
        await asyncio.sleep(0.3)

    return records


def current_revision():
    """The checked-out git revision and whether the working tree has local changes."""
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain"], capture_output=True, text=True, check=True,
    ).stdout
    return revision, bool(status.strip())


async def main_async(args):
    # Pin the scores to the code that produces them before spending any API calls. A revision given by
    # hand cannot be checked for local changes, so that stays unknown.
    if args.revision:
        revision, dirty = args.revision, None
    else:
        revision, dirty = current_revision()

    entries = load_dataset(args.dataset)
    print(f"Loaded {len(entries)} benchmark entries")
    print(f"Chains: {sorted(set(e.chain_id for e in entries))}")
    print(f"Labels: {sum(1 for e in entries if e.label == 'safe')} safe, "
          f"{sum(1 for e in entries if e.label == 'malicious')} malicious")
    print()

    # Initialize pipeline
    print("Initializing analysis pipeline...")
    from core.config import Settings
    from core.container import ServiceContainer

    settings = Settings()
    container = ServiceContainer(settings)
    print("Pipeline ready.\n")

    # Score all entries
    print("Scoring entries (live API calls)...")
    scored_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    start = time.time()
    records = await score_entries(entries, container)
    elapsed = time.time() - start
    decided = sum(1 for record in records if record["status"] == "ok")
    print(f"\nScoring complete in {elapsed:.1f}s ({decided}/{len(entries)} decided)")

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump({
            "format": FORMAT_SCORES,
            "revision": revision,
            "dirty": dirty,
            "scored_at": scored_at,
            "dataset": args.dataset,
            "dataset_sha256": json_sha256(args.dataset),
            "records": records,
        }, f, indent=2)
    print(f"Scores saved to {args.output}")
    print(f"Results: python -m eval.cli --dataset {args.dataset} --scores {args.output}")
    return 0


def main():
    parser = argparse.ArgumentParser(description='ShieldBot live benchmark scorer')
    parser.add_argument('--dataset', default='eval/data/benchmark_v2.json',
                        help='Path to benchmark JSON file')
    parser.add_argument('--output', default='eval/data/live_scores.json',
                        help='Path to save the recorded scores')
    parser.add_argument('--revision',
                        help='The 40-character git revision being scored, where this is not a git checkout')
    args = parser.parse_args()
    if args.revision is not None and not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("--revision must be a full 40-character lowercase git revision")

    return asyncio.run(main_async(args))


if __name__ == '__main__':
    sys.exit(main())
