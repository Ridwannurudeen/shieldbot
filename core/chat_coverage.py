"""Plain-language coverage gaps for AI chat replies."""

import re

from core.risk_engine import database_matches


FIELD_LABELS = {
    "buy_tax": "buy tax",
    "sell_tax": "sell tax",
    "can_sell": "whether the token can be sold",
    "can_buy": "whether the token can be bought",
    "is_honeypot": "honeypot status",
}
UNKNOWN_LINE = "ShieldBot could not finish checking this token, so it has no verdict."

OBSERVED_LINE = "What ShieldBot did observe:"


def _clean_reason(reason: str) -> str:
    reason = re.sub(
        r"(?i)(?:initialize logs scanned over )?blocks?\s+\d+\s*-\s*\d+;?",
        "",
        reason,
    )
    reason = re.sub(r"\b0x[0-9a-fA-F]{8,}\b", "a contract address", reason)
    return " ".join(reason.split(" ;")).strip(" ;")


def _readable_reason(reason: str) -> str:
    clean = _clean_reason(reason)
    pool_match = re.fullmatch(r"(?i)no supported pool found(?: \((.+)\))?", clean)
    if pool_match:
        supported = f" ({pool_match.group(1)})" if pool_match.group(1) else ""
        return f"no pool ShieldBot can simulate a sale on{supported}, so it could not test selling"

    fields_match = re.fullmatch(r"(?i)unknown fields:\s*(.+)", clean)
    if fields_match:
        fields = [field.strip().lower() for field in fields_match.group(1).split(",")]
        labels = [FIELD_LABELS[field] for field in fields if field in FIELD_LABELS]
        if labels:
            if len(labels) == 1:
                return f"{labels[0]} is unknown"
            return f"{', '.join(labels[:-1])} and {labels[-1]} are unknown"
        return "some scan details are unknown"

    return clean.replace("_", " ") or "scan details are unavailable"


def readable_coverage_gaps(reasons: dict) -> list[str]:
    """Translate coverage reason values without exposing internal block ranges."""
    if not isinstance(reasons, dict):
        return []
    gaps = []
    for reason in reasons.values():
        if not reason:
            continue
        for part in str(reason).split(";"):
            if not _clean_reason(part):
                continue
            gap = _readable_reason(part)
            if gap not in gaps:
                gaps.append(gap)
    return gaps

def observed_facts(coverage: dict, market: dict = None, contract: dict = None) -> list[str]:
    """What the scan measured, in the server's own fixed words and from structured values only, each only when
    its check was covered: the contract's age, verification and scam database result (the structural analyzer's
    data, read by its per-field coverage), and from a covered market read the pair's liquidity, 24h volume and
    age, a new pair being one under 24 hours old. Never a flag, a reason, an address, a score or a level."""
    facts = []
    contract = contract or {}
    fields = contract.get("coverage") or {}
    if fields.get("contract_age_days") is True and contract.get("contract_age_days") is not None:
        facts.append(f"Contract age {contract['contract_age_days']} days")
    if fields.get("is_verified") is True and isinstance(contract.get("is_verified"), bool):
        facts.append("Source code verified" if contract["is_verified"] else "Source code not verified")
    if fields.get("scam_database") is True and isinstance(contract.get("scam_matches"), list):
        matches = len(database_matches(contract["scam_matches"]))
        facts.append(
            f"Scam database: {matches} match{'es' if matches != 1 else ''}" if matches else "Scam database: no match"
        )
    market = market or {}
    if (coverage or {}).get("market", 0) >= 1:
        if market.get("liquidity_usd") is not None:
            facts.append(f"Liquidity ${market['liquidity_usd']:,.2f}")
        if market.get("volume_24h") is not None:
            facts.append(f"24h volume ${market['volume_24h']:,.2f}")
        if market.get("pair_age_hours") is not None:
            facts.append(f"Pair age {market['pair_age_hours']:.1f} hours")
            if market["pair_age_hours"] < 24:
                facts.append("New pair (under 24 hours old)")
    return facts


def unknown_reply(reasons: dict, observed=()) -> str:
    """The Unknown reply, in the server's own words only: the plain first line, the readable gaps, then what the
    scan observed. No model text: a scan without a verdict has none to explain, and a model's sentence could
    judge the token in any words or language."""
    parts = [UNKNOWN_LINE, *(f"- {gap}" for gap in readable_coverage_gaps(reasons))]
    if observed:
        parts.extend(["", OBSERVED_LINE, *(f"- {fact}" for fact in observed)])
    return "\n".join(parts)
