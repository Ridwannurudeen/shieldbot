"""Freeze census smoke cases and record manually obtained comparator verdicts."""

import argparse
import asyncio
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .report import build_report


SEED = "shieldbot-4663-census-v1"
SELECTION_RULE = (
    "20 distinct tokens; disjoint strata in precedence order: GoPlus flagged, "
    "two-way swaps, buys without sells, mature ineligible, unknown, young, other. "
    "Round-robin across nonempty strata; within each stratum sort SHA-256(seed:token). "
    "Buy/sell means observed pool Swap direction, not successful executable resale."
)
STRATA = (
    "goplus_flagged",
    "two_way",
    "buys_only",
    "ineligible",
    "unknown",
    "young",
    "other",
)


def select_cases(report, probe=None):
    if report.get("chain_id") != 4663:
        raise ValueError("Smoke cases require a chain 4663 census")
    tokens = report["tokens"]
    if len(tokens) < 20:
        raise ValueError(
            f"Need at least 20 distinct census tokens; found {len(tokens)}"
        )
    flagged = {}
    if probe is not None:
        if probe.get("chain_id") != 4663 or probe.get("provider") != "goplus":
            raise ValueError("Probe must be a GoPlus chain 4663 result")
        for record in probe["records"]:
            if record["data_status"] != "available":
                continue
            fields = record["response"]["result"].get(record["token"], {})
            flags = {
                name: fields[name]
                for name in ("is_honeypot", "cannot_sell_all", "transfer_pausable")
                if fields.get(name) in ("1", 1)
            }
            if flags:
                flagged[record["token"]] = flags
    groups = {name: [] for name in STRATA}
    for token in tokens:
        if token["token"] in flagged:
            stratum = "goplus_flagged"
        elif token["buys_window"] > 0 and token["sells_window"] > 0:
            stratum = "two_way"
        elif token["buys_window"] > 0 and token["sells_window"] == 0:
            stratum = "buys_only"
        elif token["eligibility"] == "fail":
            stratum = "ineligible"
        elif token["eligibility"] in ("unknown", "young"):
            stratum = token["eligibility"]
        else:
            stratum = "other"
        groups[stratum].append(token)
    for group in groups.values():
        group.sort(
            key=lambda token: hashlib.sha256(
                f"{SEED}:{token['token']}".encode("utf-8")
            ).hexdigest()
        )
    cases = []
    offsets = dict.fromkeys(STRATA, 0)
    while len(cases) < 20:
        for stratum in STRATA:
            if offsets[stratum] >= len(groups[stratum]):
                continue
            token = groups[stratum][offsets[stratum]]
            offsets[stratum] += 1
            cases.append(
                {
                    "case_id": f"4663:{token['token']}",
                    "token": token["token"],
                    "stratum": stratum,
                    "evidence": {
                        **token,
                        "goplus_flags": flagged.get(token["token"], {}),
                    },
                }
            )
            if len(cases) == 20:
                break
    return {
        "version": 1,
        "chain_id": 4663,
        "seed": SEED,
        "selection_rule": SELECTION_RULE,
        "window": report["window"],
        "population": len(tokens),
        "cases": cases,
    }


def record_verdict(
    cases_path,
    case_id,
    comparator,
    verdict,
    raw_output,
    access_failure=False,
    failure_reason=None,
    notes="",
):
    from .storage import data_directory

    cases_path = Path(cases_path).expanduser().resolve()
    data_directory(cases_path.parent)
    selection = json.loads(cases_path.read_text(encoding="utf-8"))
    if selection.get("version") != 1 or selection.get("chain_id") != 4663:
        raise ValueError("Unsupported smoke-case version or chain")
    if case_id not in {case["case_id"] for case in selection["cases"]}:
        raise ValueError("Case id is not in the fixed selection")
    if not comparator.strip() or not verdict.strip():
        raise ValueError("Comparator and verdict must be nonempty")
    if access_failure and not failure_reason:
        raise ValueError("An access failure requires a reason")
    if failure_reason and not access_failure:
        raise ValueError("A failure reason requires --access-failure")
    path = cases_path.with_suffix(".verdicts.jsonl")
    record = {
        "version": 1,
        "chain_id": 4663,
        "comparator": comparator.strip(),
        "case_id": case_id,
        "verdict": verdict,
        "raw_output": raw_output,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "access_failure": bool(access_failure),
        "failure_reason": failure_reason,
        "notes": notes,
    }
    if path.exists():
        previous = [
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
        ]
        if any(
            item["case_id"] == case_id and item["comparator"] == record["comparator"]
            for item in previous
        ):
            raise ValueError(
                "A verdict for this comparator and case is already recorded"
            )
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


async def run(args):
    from .storage import data_directory, read_snapshot

    if args.command == "select":
        directory = data_directory(args.data_dir, create=False)
        with read_snapshot(directory) as census:
            report = build_report(census)
        probe_path = directory / "probe_goplus.json"
        probe = (
            json.loads(probe_path.read_text(encoding="utf-8"))
            if probe_path.exists()
            else None
        )
        selection = select_cases(report, probe)
        path = Path(args.out).expanduser().resolve()
        data_directory(path.parent)
        with path.open("x", encoding="utf-8") as output:
            output.write(json.dumps(selection, indent=2) + "\n")
        print(f"Selected 20 fixed cases: {path}")
    else:
        raw = Path(args.raw_output).read_text(encoding="utf-8")
        record = record_verdict(
            args.cases,
            args.case_id,
            args.comparator,
            args.verdict,
            raw,
            args.access_failure,
            args.failure_reason,
            args.notes,
        )
        print(
            json.dumps(
                {
                    "case_id": record["case_id"],
                    "comparator": record["comparator"],
                    "recorded": True,
                }
            )
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    select = commands.add_parser(
        "select", help="Freeze a deterministic set of 20 cases"
    )
    select.add_argument("--data-dir", required=True)
    select.add_argument("--out", required=True)
    record = commands.add_parser(
        "record", help="Append a manually obtained comparator verdict"
    )
    record.add_argument("--cases", required=True)
    record.add_argument("--case-id", required=True)
    record.add_argument("--comparator", required=True)
    record.add_argument("--verdict", required=True)
    record.add_argument(
        "--raw-output",
        required=True,
        help="UTF-8 file containing the comparator output",
    )
    record.add_argument("--access-failure", action="store_true")
    record.add_argument("--failure-reason")
    record.add_argument("--notes", default="")
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except (ValueError, FileExistsError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
