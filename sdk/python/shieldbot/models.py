"""Data models for the ShieldBot SDK."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Verdict:
    """Result of a ShieldBot transaction check."""
    verdict: str  # "ALLOW" | "WARN" | "BLOCK"
    score: float
    flags: List[str] = field(default_factory=list)
    evidence: Optional[str] = None
    policy_check: Optional[Dict] = None
    cached: bool = False
    latency_ms: float = 0

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    @property
    def blocked(self) -> bool:
        return self.verdict == "BLOCK"
