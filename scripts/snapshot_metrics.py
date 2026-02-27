#!/usr/bin/env python3
"""
Weekly metrics snapshot — appends a formatted report to metrics/log.md.
Runs via cron every Monday at 09:00 UTC on the VPS.

Usage:
    python3 scripts/snapshot_metrics.py
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

API_URL = os.environ.get("SHIELDBOT_API_URL", "http://127.0.0.1:8000")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
LOG_FILE = Path(__file__).parent.parent / "metrics" / "log.md"


def fetch_stats() -> dict:
    req = urllib.request.Request(
        f"{API_URL}/api/admin/stats",
        headers={"x-admin-secret": ADMIN_SECRET},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def format_snapshot(data: dict, timestamp: str) -> str:
    at = data.get("all_time", {})
    h24 = data.get("last_24h", {})
    h7d = data.get("last_7d", {})
    h30d = data.get("last_30d", {})
    mp = data.get("mempool", {})

    # Chain name map
    chain_names = {
        "56": "BSC", "1": "ETH", "8453": "Base",
        "42161": "Arbitrum", "137": "Polygon", "10": "Optimism", "204": "opBNB",
    }
    by_chain = at.get("by_chain", {})
    chain_rows = "\n".join(
        f"| {chain_names.get(cid, cid)} | {v['contracts']} | {v['scans']} |"
        for cid, v in sorted(by_chain.items(), key=lambda x: -x[1]["scans"])
    )

    lines = [
        f"## {timestamp}",
        "",
        "### All-Time",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Unique contracts scanned | {at.get('unique_contracts_scanned', 0):,} |",
        f"| Total scan events | {at.get('total_scan_events', 0):,} |",
        f"| Threats detected (score ≥ 71) | {at.get('threats_detected', 0):,} |",
        f"| Transactions blocked | {at.get('transactions_blocked', 0):,} |",
        f"| Proceeded past warning | {at.get('transactions_proceeded_past_warning', 0):,} |",
        f"| Deployers indexed | {at.get('deployers_indexed', 0):,} |",
        f"| Community reports filed | {at.get('community_reports', 0):,} |",
        f"| Beta signups | {at.get('beta_signups', 0):,} |",
        "",
        "### Activity Windows",
        "| Period | Scans | Threats | Blocks |",
        "|--------|-------|---------|--------|",
        f"| Last 24h | {h24.get('scans', 0):,} | {h24.get('threats_detected', 0):,} | {h24.get('transactions_blocked', 0):,} |",
        f"| Last 7d  | {h7d.get('scans', 0):,} | {h7d.get('threats_detected', 0):,} | {h7d.get('transactions_blocked', 0):,} |",
        f"| Last 30d | {h30d.get('scans', 0):,} | {h30d.get('threats_detected', 0):,} | {h30d.get('transactions_blocked', 0):,} |",
        "",
        "### By Chain",
        "| Chain | Contracts | Scans |",
        "|-------|-----------|-------|",
        chain_rows,
        "",
        "### Mempool",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Transactions monitored | {mp.get('total_pending_seen', 0):,} |",
        f"| Sandwiches detected | {mp.get('sandwiches_detected', 0):,} |",
        f"| Frontrun detected | {mp.get('frontruns_detected', 0):,} |",
        f"| Suspicious approvals | {mp.get('suspicious_approvals', 0):,} |",
        f"| Chains monitored | {len(mp.get('monitored_chains', []))} |",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


def main():
    if not ADMIN_SECRET:
        print("ERROR: ADMIN_SECRET env var not set", file=sys.stderr)
        sys.exit(1)

    try:
        data = fetch_stats()
    except urllib.error.URLError as e:
        print(f"ERROR: Could not reach API — {e}", file=sys.stderr)
        sys.exit(1)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    snapshot = format_snapshot(data, timestamp)

    LOG_FILE.parent.mkdir(exist_ok=True)

    # Write header if file is new
    if not LOG_FILE.exists():
        LOG_FILE.write_text(
            "# ShieldBot Metrics Log\n\n"
            "Weekly snapshots — every Monday 09:00 UTC.\n\n"
            "---\n\n"
        )

    with LOG_FILE.open("a") as f:
        f.write(snapshot)

    print(f"Snapshot written → {LOG_FILE}")
    print(f"  Contracts scanned: {data['all_time']['unique_contracts_scanned']:,}")
    print(f"  Threats detected:  {data['all_time']['threats_detected']:,}")
    print(f"  Mempool monitored: {data['mempool'].get('total_pending_seen', 0):,}")


if __name__ == "__main__":
    main()
