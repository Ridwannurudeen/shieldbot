"""Public evidence documents for ShieldBot verdicts published on Robinhood Chain.

Each on-chain verdict commits to one evidence document: evidence_hash = keccak256(canonical_bytes(payload)).
Anyone can fetch the canonical document, re-hash its exact bytes and compare the result with the
ShieldBotVerdictRegistry VerdictRecorded event. Verifiers should hash the served canonical string itself rather
than re-serialise the JSON, because other languages print numbers such as 1.0 differently.
"""

import json
from enum import IntEnum
from typing import Optional

from eth_utils import keccak

from adapters.robinhood import SIMULATION_PROVIDER
from core.extension_formatter import is_scan_incomplete

SCHEMA_VERSION = 1

# Honeypot fields published in the evidence, when the scan produced them.
HONEYPOT_FIELDS = (
    "is_honeypot",
    "can_buy",
    "can_sell",
    "buy_tax",
    "sell_tax",
    "simulation_failed",
    "simulation_block",
    "field_providers",
    "reason",
)


class Verdict(IntEnum):
    """ShieldBotVerdictRegistry.Verdict; the values are the on-chain codes."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    HONEYPOT = 4


def is_simulation_proven_honeypot(honeypot: Optional[dict]) -> bool:
    """True only when ShieldBot's own buy-then-sell simulation proved the honeypot."""
    if not isinstance(honeypot, dict) or honeypot.get("is_honeypot") is not True:
        return False
    providers = honeypot.get("field_providers")
    return isinstance(providers, dict) and providers.get("is_honeypot") == SIMULATION_PROVIDER


def _honeypot_of(scan_result: dict, honeypot: Optional[dict]) -> Optional[dict]:
    """Explicit honeypot data, else the `honeypot_data` that AgentTools.scan_contract returns."""
    if honeypot is not None:
        return honeypot
    carried = scan_result.get("honeypot_data")
    return carried if isinstance(carried, dict) else None


def verdict_for(scan_result: dict, honeypot: Optional[dict] = None) -> Verdict:
    """Map a scan to its published verdict. An incomplete scan is UNKNOWN, never LOW.

    A simulation-proven honeypot is HONEYPOT even when other fields are missing, because the failed sell is
    itself the evidence.
    """
    honeypot = _honeypot_of(scan_result, honeypot)
    if is_simulation_proven_honeypot(honeypot):
        return Verdict.HONEYPOT
    if is_scan_incomplete(scan_result):
        return Verdict.UNKNOWN
    level = str(scan_result.get("risk_level") or "").upper()
    return Verdict[level] if level in ("LOW", "MEDIUM", "HIGH") else Verdict.UNKNOWN


def build_evidence(
    chain_id: int, subject: str, scan_result: dict, honeypot: Optional[dict], scanned_at: int
) -> dict:
    """Build the public evidence payload for one scan of `subject`."""
    honeypot = _honeypot_of(scan_result, honeypot)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "chain_id": chain_id,
        "subject": subject.lower(),
        "verdict": verdict_for(scan_result, honeypot).name,
        "status": "unknown" if is_scan_incomplete(scan_result) else "ok",
        "coverage": scan_result.get("coverage") or {},
        "coverage_reasons": scan_result.get("coverage_reasons") or {},
        "rug_probability": scan_result.get("rug_probability"),
        "observed_block": 0,
        "scanned_at": scanned_at,
    }
    if honeypot is not None:
        payload["honeypot"] = {
            field: honeypot[field] for field in HONEYPOT_FIELDS if field in honeypot
        }
        block = honeypot.get("simulation_block")
        if type(block) is int and block >= 0:
            payload["observed_block"] = block
    return payload


def canonical_bytes(payload: dict) -> bytes:
    """Sorted keys, compact separators, UTF-8; NaN and Infinity raise ValueError."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def evidence_hash(payload: dict) -> str:
    return "0x" + keccak(canonical_bytes(payload)).hex()
