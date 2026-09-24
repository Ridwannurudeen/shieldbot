"""Evidence documents for the verdicts /api/firewall and /api/scan return.

Every response carries `evidence_hash` = keccak256(canonical_bytes(document)), the same canonical
form and hash as the Robinhood Chain registry's evidence (core.verdict_evidence), and the API
stores the document under that hash. These documents are ShieldBot's own record and are never
recorded on a chain: `schema` names them, and a registry document has no `schema` key, so the two
can never be confused.

A document holds the chain, the target, the verdict (classification, risk_score, risk_level and
status, as the response gave them), coverage and failed_sources, each analyzer's outcome, the
policy mode, the observed block where a scan measured one, the ShieldBot commit and the scan time.
It never holds the caller's address, IP address, API key or calldata: a transaction-specific
verdict carries the decoded function name and the keccak256 of the calldata instead, and any
mention of the caller's address is replaced with "[caller]".
"""

import json
import re
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Dict, List, Optional

from eth_utils import keccak

from core.verdict_evidence import evidence_hash

SCHEMA = "shieldbot-scan-evidence"
SCHEMA_VERSION = 1
CALLER_PLACEHOLDER = "[caller]"

# The caller's address in any form the API accepts: with 0x or 0X, or without a prefix.
_CALLER = re.compile(r"(?:0[xX])?([0-9a-fA-F]{40})")
_HEX_BYTES = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_COMMIT = re.compile(r"[0-9a-f]{40}")


def read_commit(root: Path) -> Optional[str]:
    """The commit checked out in `root`, read from its .git directory; None when it cannot be read.

    deploy/deploy.sh checks out a commit, so HEAD holds the commit itself; a branch checkout names a
    ref, whose commit is in its own file or in packed-refs. Git is not run: the API's systemd unit
    has only the virtualenv on its PATH.
    """
    git = root / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref: "):
            ref = head[len("ref: ") :]
            if (git / ref).is_file():
                head = (git / ref).read_text(encoding="utf-8").strip()
            else:
                packed = (git / "packed-refs").read_text(encoding="utf-8").splitlines()
                head = next((line.split()[0] for line in packed if line.endswith(" " + ref)), "")
    except OSError:
        return None
    return head if _COMMIT.fullmatch(head) else None


# Read once: a deploy restarts the process after it checks out the new commit.
SHIELDBOT_COMMIT = read_commit(Path(__file__).resolve().parents[1])


def analyzer_outcomes(results: List, risk_output: Dict) -> Dict[str, Dict]:
    """Each analyzer's outcome as the engine scored it, and what its providers answered.

    status is failed (the analyzer raised or ran past the registry's deadline), skipped (it does
    not apply to this target), unknown (coverage below 1) or ok. score is the engine's category
    score: None when an analyzer's zero was left out of the mean because its data was unknown.
    fields maps each coverage field the analyzer declares to answered or unknown; a provider that
    failed and one that had no data both leave a field unknown, and reason says which it was.
    field_providers names the provider that answered a field where the analyzer records it.
    """
    outcomes = {}
    for result in results:
        data = result.data or {}
        coverage = risk_output["coverage"][result.name]
        if result.error:
            status = "failed"
        elif data.get("skipped"):
            status = "skipped"
        else:
            status = "unknown" if coverage < 1 else "ok"
        outcome = {
            "status": status,
            "score": risk_output["category_scores"][result.name],
            "coverage": coverage,
        }
        reason = risk_output["coverage_reasons"].get(result.name)
        if reason:
            outcome["reason"] = reason
        fields = data.get("coverage") if isinstance(data.get("coverage"), dict) else {}
        outcome["fields"] = {
            field: "answered" if known is True else "unknown" for field, known in fields.items()
        }
        providers = data.get("field_providers")
        if isinstance(providers, dict) and providers:
            outcome["field_providers"] = providers
        outcomes[result.name] = outcome
    return outcomes


def oldest_simulation_block(results: List) -> Optional[int]:
    """The oldest block a sell simulation in this scan read (Robinhood Chain), or None."""
    blocks = [
        result.data["simulation_block"]
        for result in results
        if not result.error
        and type((result.data or {}).get("simulation_block")) is int
        and result.data["simulation_block"] >= 0
    ]
    return min(blocks, default=None)


def transaction_evidence(
    calldata: str,
    function: Optional[str] = None,
    sign_method: Optional[str] = None,
    typed_data: Optional[Dict] = None,
) -> Dict:
    """What a transaction-specific verdict records about the transaction: names and hashes only.

    calldata_keccak is keccak256 of the calldata's bytes (None when it is not 0x-prefixed hex
    bytes); typed_data_keccak is keccak256 of the typed data's canonical JSON.
    """
    return {
        "function": function,
        "calldata_keccak": (
            "0x" + keccak(bytes.fromhex(calldata[2:])).hex()
            if _HEX_BYTES.fullmatch(calldata)
            else None
        ),
        "sign_method": sign_method,
        "typed_data_primary_type": (
            typed_data["primaryType"]
            if typed_data and isinstance(typed_data.get("primaryType"), str)
            else None
        ),
        "typed_data_keccak": evidence_hash(typed_data) if typed_data else None,
    }


def _without_caller(value, caller: re.Pattern):
    if isinstance(value, str):
        return caller.sub(CALLER_PLACEHOLDER, value)
    if isinstance(value, dict):
        return {
            _without_caller(key, caller): _without_caller(item, caller)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_without_caller(item, caller) for item in value]
    return value


def build_scan_evidence(
    endpoint: str,
    chain_id: int,
    response: Dict,
    scanned_at: int,
    target: Optional[str] = None,
    target_token: Optional[Dict] = None,
    analyzers: Optional[Dict] = None,
    transaction: Optional[Dict] = None,
    observed_block: Optional[int] = None,
    cached_scan_at: Optional[float] = None,
    caller: Optional[str] = None,
) -> Dict:
    """The evidence document for one response of `endpoint`.

    A field the response path does not report (risk_level or failed_sources on the legacy fallback,
    analyzers on a cached or legacy verdict) is None, never a default. A verdict
    served from contract_scores has source "cache", and both cached_scan_at and scanned_at are the
    time of the scan that produced the row, so every hit on one row gives the same document.
    """
    document = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "endpoint": endpoint,
        "source": "scan" if cached_scan_at is None else "cache",
        "cached_scan_at": None if cached_scan_at is None else int(cached_scan_at),
        "chain_id": chain_id,
        "target": target.lower() if target else None,
        "target_token": target_token,
        "classification": response.get("classification"),
        "risk_score": response.get("risk_score"),
        "risk_level": (response.get("shield_score") or {}).get("risk_level")
        or response.get("risk_level"),
        "status": response.get("status"),
        "coverage": response.get("coverage") or {},
        "coverage_reasons": response.get("coverage_reasons") or {},
        "failed_sources": response.get("failed_sources"),
        "notes": response.get("notes"),
        "analyzers": analyzers,
        "policy_mode": response.get("policy_mode"),
        "observed_block": observed_block,
        "transaction": transaction,
        "shieldbot_commit": SHIELDBOT_COMMIT,
        "scanned_at": scanned_at if cached_scan_at is None else int(cached_scan_at),
    }
    caller_hex = _CALLER.fullmatch(caller.strip()) if caller else None
    if caller_hex:
        pattern = re.compile(f"(?:0x)?{caller_hex.group(1)}", re.IGNORECASE)
        document = _without_caller(document, pattern)
    return document


_SUMMARY = (
    ("classification", "Verdict"),
    ("risk_score", "Risk score"),
    ("risk_level", "Risk level"),
    ("status", "Status"),
    ("chain_id", "Chain"),
    ("target", "Target"),
    ("target_token", "Token"),
    ("endpoint", "Endpoint"),
    ("source", "Source"),
    ("cached_scan_at", "Cached scan at"),
    ("policy_mode", "Policy mode"),
    ("failed_sources", "Failed sources"),
    ("notes", "Notes"),
    ("observed_block", "Observed block"),
    ("transaction", "Transaction"),
    ("scanned_at", "Scanned at"),
    ("shieldbot_commit", "ShieldBot commit"),
)

_PAGE_STYLE = """
:root { color-scheme: light dark; --bg: #f7f7f5; --fg: #1c1c1a; --muted: #5d5d58; --line: #d8d8d2; --code: #ecece7; }
@media (prefers-color-scheme: dark) { :root { --bg: #121212; --fg: #ececea; --muted: #a3a39d; --line: #2e2e2b; --code: #1c1c1b; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 32px 0 8px; }
p { margin: 8px 0; color: var(--muted); }
code, pre, td { overflow-wrap: anywhere; }
.hash { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13px; }
.scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; width: 180px; }
pre { background: var(--code); padding: 12px; white-space: pre-wrap; font-size: 12px; margin: 0; }
"""


def _text(value) -> str:
    return escape(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))


def _utc(value) -> str:
    if type(value) not in (int, float):
        return _text(value)
    return (
        escape(datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
        + f" ({int(value)})"
    )


def render_evidence_page(evidence_hash: str, canonical: str, expires_at: float) -> str:
    """One stored document as a self-contained page: no scripts, every value escaped."""
    document = json.loads(canonical)
    summary = "".join(
        f"<tr><th>{escape(label)}</th><td>"
        f"{_utc(document.get(key)) if key in ('scanned_at', 'cached_scan_at') else _text(document.get(key))}"
        "</td></tr>"
        for key, label in _SUMMARY
    )
    reasons = document.get("coverage_reasons") or {}
    coverage = "".join(
        f"<tr><td>{_text(name)}</td><td>{_text(fraction)}</td><td>{_text(reasons.get(name, ''))}</td></tr>"
        for name, fraction in (document.get("coverage") or {}).items()
    )
    analyzers = "".join(
        f"<tr><td>{_text(name)}</td><td>{_text(outcome.get('status'))}</td><td>{_text(outcome.get('score'))}</td>"
        f"<td>{_text(outcome.get('coverage'))}</td><td>{_text(outcome.get('fields'))}</td>"
        f"<td>{_text(outcome.get('reason', ''))}</td></tr>"
        for name, outcome in (document.get("analyzers") or {}).items()
    )
    digest = escape(evidence_hash)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>ShieldBot scan evidence</title>
<style>{_PAGE_STYLE}</style>
</head>
<body>
<main>
<h1>ShieldBot scan evidence</h1>
<p class="hash">{digest}</p>
<p>ShieldBot's own record of one verdict it returned. It is not recorded on any chain, and it is kept until {_utc(expires_at)}.</p>
<h2>Verdict</h2>
<div class="scroll"><table>{summary}</table></div>
<h2>Coverage</h2>
<div class="scroll"><table><tr><th>Source</th><th>Covered</th><th>Reason</th></tr>{coverage}</table></div>
<h2>Analyzers</h2>
<p>{"Not recorded for this verdict." if not analyzers else "Each analyzer as the risk engine scored it."}</p>
<div class="scroll"><table><tr><th>Analyzer</th><th>Status</th><th>Score</th><th>Coverage</th><th>Fields</th><th>Reason</th></tr>{analyzers}</table></div>
<h2>Canonical document</h2>
<p>Verify: keccak256 of these bytes (the UTF-8 text below, exactly as shown, which is the <code>canonical</code> string at <a href="/api/evidence/{digest}">/api/evidence/{digest}</a>) must equal {digest}.</p>
<pre id="canonical">{escape(canonical)}</pre>
</main>
</body>
</html>
"""
