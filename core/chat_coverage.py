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

# On an Unknown scan the model may explain what is missing, never judge the token: a paragraph that
# calls it safe or risky, gives a score or verdict, or rules out a honeypot or scam is dropped.
_VERDICT_CLAIM = re.compile(
    r"(?i)\b(?:safe|safety|unsafe|legit(?:imate)?|trustworthy|risk[- ](?:free|score|verdict|level|rating)"
    r"|(?:low|medium|high|minimal|no)[- ]risk|verdict|score|rug(?:[- ]?pull)?|scam|honeypot[- ]free"
    r"|not\s+a\s+honeypot|(?:block|caution|proceed)\s+recommended)\b|\b\d{1,3}\s*/\s*100\b"
)


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

# Internal scan detail the model may repeat from its tool data; never shown to the user.
_BLOCK_RANGE = re.compile(
    r"(?i)\s*\(?(?:initialize logs )?(?:scanned )?(?:over )?blocks?\s+\d+\s*-\s*\d+\)?"
)


def without_verdict_claims(text: str) -> str:
    """The model's explanation with every paragraph that judges the token removed."""
    paragraphs = re.split(r"\n\s*\n", text or "")
    kept = [
        _BLOCK_RANGE.sub("", p).strip()
        for p in paragraphs
        if p.strip() and not _VERDICT_CLAIM.search(p)
    ]
    return "\n\n".join(kept)


def unknown_reply(reasons: dict, model_text: str = "") -> str:
    """The Unknown reply: the plain first line, the readable gaps, then any explanation left."""
    parts = [UNKNOWN_LINE, *(f"- {gap}" for gap in readable_coverage_gaps(reasons))]
    explanation = without_verdict_claims(model_text)
    if explanation:
        parts.extend(["", explanation])
    return "\n".join(parts)
