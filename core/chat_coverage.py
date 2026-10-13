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
    if clean.lower() == "no supported pool found":
        return "no pool ShieldBot can simulate a sale on, so it could not test selling"

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
