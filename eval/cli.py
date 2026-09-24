"""Benchmark results from recorded scores, offline.

Usage:
    python -m eval.cli --dataset eval/data/benchmark_v2.json --scores eval/data/live_scores.json
    python -m eval.cli --dataset ... --scores ... --threshold 50 --out eval/results/<date>-<revision>.json

The scores are the ones eval.live_scorer recorded. This command never contacts the network and never
makes up a score: without --scores it stops with an error. See eval/README.md for what the numbers mean.
"""

import argparse
import json
import sys

from eval.benchmark import DEFAULT_FLAG_THRESHOLD, build_results


def _percent(value):
    return "n/a" if value is None else f"{value:.1%}"


def main(argv=None):
    parser = argparse.ArgumentParser(description='ShieldBot benchmark results from recorded scores')
    parser.add_argument('--dataset', required=True, help='Path to benchmark JSON file')
    parser.add_argument('--scores', help='Scores recorded by eval.live_scorer (required)')
    parser.add_argument('--threshold', type=float, default=DEFAULT_FLAG_THRESHOLD,
                        help='Score threshold for flagging as malicious (default: 50)')
    parser.add_argument('--out', help='Write the results file (JSON) to this path')
    args = parser.parse_args(argv)
    if not args.scores:
        parser.error(
            "--scores is required. Record scores first with "
            "`python -m eval.live_scorer --dataset <dataset> --output <scores file>`; "
            "this command never makes up scores."
        )

    results = build_results(args.dataset, args.scores, args.threshold)

    overall = results['overall']
    changes = {True: ' (with local changes)', False: '', None: ' (local changes not checked)'}[results['dirty']]
    print(f"Scored at {results['scored_at']} by revision {results['revision']}{changes}, "
          f"threshold {results['threshold']:g}")
    print(f"Entries: {overall['entries']}  unknown rate: {_percent(overall['unknown_rate'])}  "
          f"recall: {_percent(overall['recall'])}  precision: {_percent(overall['precision'])}  "
          f"false positive rate: {_percent(overall['false_positive_rate'])}")
    print(f"{'class':<26}{'entries':>8}{'decided':>9}{'unknown':>9}{'flagged':>9}{'recall':>9}{'precision':>11}")
    for name, tally in results['classes'].items():
        print(f"{name:<26}{tally['entries']:>8}{tally['decided']:>9}{tally['unknown']:>9}{tally['flagged']:>9}"
              f"{_percent(tally.get('recall')):>9}{_percent(tally.get('precision')):>11}")

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
            f.write('\n')
        print(f"Results written to {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
