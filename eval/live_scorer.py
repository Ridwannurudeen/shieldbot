"""Live benchmark scorer — runs each entry through the real analysis pipeline.

Usage:
    python -m eval.live_scorer --dataset eval/data/benchmark_v1.json
    python -m eval.live_scorer --dataset eval/data/benchmark_v1.json --output eval/data/live_scores.json
"""

import argparse
import asyncio
import json
import logging
import sys
import time

from eval.dataset import load_dataset
from eval.benchmark import run_benchmark

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.WARNING,
)
logger = logging.getLogger(__name__)


async def score_entries(entries, container):
    """Score each benchmark entry using the composite analysis pipeline."""
    from core.analyzer import AnalysisContext

    scores = {}
    total = len(entries)

    for i, entry in enumerate(entries, 1):
        addr = entry.address
        chain_id = entry.chain_id
        tag = f"[{i}/{total}]"

        try:
            ctx = AnalysisContext(address=addr, chain_id=chain_id)
            results = await container.registry.run_all(ctx)
            risk_output = container.risk_engine.compute_from_results(results)

            score = risk_output.get('rug_probability', 0)
            level = risk_output.get('risk_level', 'LOW')
            scores[addr.lower()] = score

            mark = "!" if (entry.label == 'malicious') != (score >= 50) else " "
            print(f"  {mark}{tag} chain={chain_id} {addr[:16]}... score={score:.1f} level={level} label={entry.label}")

        except Exception as e:
            logger.error(f"{tag} Error scoring {addr}: {e}")
            print(f"  X{tag} chain={chain_id} {addr[:16]}... ERROR: {e}")

        # Small delay to avoid rate-limiting external APIs
        await asyncio.sleep(0.3)

    return scores


async def main_async(args):
    # Load dataset
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
    start = time.time()
    scores = await score_entries(entries, container)
    elapsed = time.time() - start
    print(f"\nScoring complete in {elapsed:.1f}s ({len(scores)}/{len(entries)} scored)")

    # Save scores
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(scores, f, indent=2)
        print(f"Scores saved to {args.output}")

    # Run benchmark
    print()
    result = run_benchmark(entries, scores, threshold=args.threshold)

    # Print report
    print("=" * 60)
    print("LIVE BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Total entries:       {result.total}")
    print(f"True positives:      {result.true_positives}")
    print(f"False positives:     {result.false_positives}")
    print(f"True negatives:      {result.true_negatives}")
    print(f"False negatives:     {result.false_negatives}")
    print(f"Errors:              {result.errors}")
    print(f"---")
    print(f"Precision:           {result.precision:.2%}")
    print(f"Recall:              {result.recall:.2%}")
    print(f"F1 Score:            {result.f1:.2%}")
    print(f"False Positive Rate: {result.false_positive_rate:.2%}")
    print("=" * 60)

    # Misclassifications
    misses = [d for d in result.details if d.get('correct') is False]
    if misses:
        print(f"\nMISCLASSIFICATIONS ({len(misses)}):")
        for d in misses:
            print(f"  chain={d['chain_id']} {d['address'][:20]}... "
                  f"label={d['label']} score={d['score']:.1f} pred={d['predicted']} "
                  f"cat={d.get('category', '?')}")

    return 0 if result.f1 > 0 else 1


def main():
    parser = argparse.ArgumentParser(description='ShieldBot live benchmark scorer')
    parser.add_argument('--dataset', default='eval/data/benchmark_v1.json',
                        help='Path to benchmark JSON file')
    parser.add_argument('--output', default='eval/data/live_scores.json',
                        help='Path to save scores JSON')
    parser.add_argument('--threshold', type=float, default=50.0,
                        help='Score threshold for flagging as malicious (default: 50)')
    args = parser.parse_args()

    return asyncio.run(main_async(args))


if __name__ == '__main__':
    sys.exit(main())
