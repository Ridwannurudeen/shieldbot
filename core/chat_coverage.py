"""Plain-language coverage gaps for AI chat replies."""

import re


FIELD_LABELS = {
    "buy_tax": "buy tax",
    "sell_tax": "sell tax",
    "can_sell": "whether the token can be sold",
    "can_buy": "whether the token can be bought",
    "is_honeypot": "honeypot status",
}
UNKNOWN_LINE = "ShieldBot could not finish checking this token, so it has no verdict."

OBSERVED_LINE = "What ShieldBot did observe:"
# The flags that name a check which could not run (core.risk_engine adds them): notes, not observations.
_NOTE_FLAG = re.compile(r"^(?:Sellability|Honeypot coverage) unknown:")


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

def observed_facts(flags, coverage: dict, market: dict = None) -> list[str]:
    """What the scan itself measured, in plain words: its observation flags (a note about a check that could
    not run is not one) and, when the market analyzer was covered, the pair's liquidity, volume and age. Never
    a score or a level, and nothing from a check the scan did not cover."""
    facts = [str(flag) for flag in flags or () if not _NOTE_FLAG.match(str(flag))]
    market = market or {}
    if (coverage or {}).get("market", 0) >= 1:
        if market.get("liquidity_usd") is not None:
            facts.append(f"Liquidity ${market['liquidity_usd']:,.2f}")
        if market.get("volume_24h") is not None:
            facts.append(f"24h volume ${market['volume_24h']:,.2f}")
        if market.get("pair_age_hours") is not None:
            facts.append(f"Pair age {market['pair_age_hours']:.1f} hours")
    return facts


def unknown_reply(reasons: dict, observed=()) -> str:
    """The Unknown reply, in the server's own words only: the plain first line, the readable gaps, then what the
    scan observed. No model text: a scan without a verdict has none to explain, and a model's sentence could
    judge the token in any words or language."""
    parts = [UNKNOWN_LINE, *(f"- {gap}" for gap in readable_coverage_gaps(reasons))]
    if observed:
        parts.extend(["", OBSERVED_LINE, *(f"- {fact}" for fact in observed)])
    return "\n".join(parts)
