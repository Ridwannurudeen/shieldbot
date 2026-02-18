"""CLI entrypoint for running evaluation benchmarks.

Usage:
    python -m eval.cli --dataset eval/data/benchmark_v1.json
"""

import argparse
import json
import sys

from eval.dataset import load_dataset
from eval.benchmark import run_benchmark


def main():
    parser = argparse.ArgumentParser(description='ShieldBot evaluation benchmark')
    parser.add_argument('--dataset', required=True, help='Path to benchmark JSON file')
    parser.add_argument('--scores', help='Path to JSON file with {address: score} map')
    parser.add_argument('--threshold', type=float, default=50.0,
                        help='Score threshold for flagging as malicious (default: 50)')
    args = parser.parse_args()

    # Load dataset
    entries = load_dataset(args.dataset)
    print(f"Loaded {len(entries)} benchmark entries")

    # Load scores (or use placeholder scores for dry run)
    if args.scores:
        with open(args.scores, 'r') as f:
            scores = json.load(f)
    else:
        # Dry run with placeholder scores from the dataset
        print("No --scores file provided, using placeholder scores from dataset")
        scores = {}
        for entry in entries:
            # Use category hints to generate placeholder scores
            if entry.label == 'malicious':
                scores[entry.address.lower()] = 85.0
            else:
                scores[entry.address.lower()] = 15.0

    # Run benchmark
    result = run_benchmark(entries, scores, threshold=args.threshold)

    # Print report
    print("\n" + "=" * 60)
    print("BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Total entries:     {result.total}")
    print(f"True positives:    {result.true_positives}")
    print(f"False positives:   {result.false_positives}")
    print(f"True negatives:    {result.true_negatives}")
    print(f"False negatives:   {result.false_negatives}")
    print(f"Errors:            {result.errors}")
    print(f"---")
    print(f"Precision:         {result.precision:.2%}")
    print(f"Recall:            {result.recall:.2%}")
    print(f"F1 Score:          {result.f1:.2%}")
    print(f"False Positive Rate: {result.false_positive_rate:.2%}")
    print("=" * 60)

    # Print per-entry details
    for d in result.details:
        status = "OK" if d.get('correct') else ("ERR" if d.get('error') else "MISS")
        score = f"{d['score']:.1f}" if d['score'] is not None else "N/A"
        chain = d.get('chain_id', 56)
        print(f"  [{status}] chain={chain} {d['address'][:16]}... label={d['label']} score={score} pred={d.get('predicted', 'N/A')}")

    return 0 if result.f1 > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
