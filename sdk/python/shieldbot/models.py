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
    status: str = "unknown"
    coverage: Dict[str, float] = field(default_factory=dict)
    coverage_reasons: Dict[str, str] = field(default_factory=dict)
    risk_display: str = ""
    risk_level: Optional[str] = None
    category_scores: Dict[str, Optional[float]] = field(default_factory=dict)
    confidence: Optional[float] = None
    analysis_unavailable: bool = False

    def __post_init__(self):
        incomplete = self.status != "ok" or self.risk_level == "UNKNOWN" or not self.coverage or any(value != 1 for value in self.coverage.values())
        if incomplete:
            self.status = "unknown"
            self.risk_display = (
                "Unknown (analysis unavailable)" if self.analysis_unavailable
                else "Unknown (incomplete provider coverage)"
            )
            if self.verdict == "ALLOW" and not self.analysis_unavailable:
                self.verdict = "WARN"
        elif not self.risk_display:
            self.risk_display = f"{self.score}%"

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    @property
    def blocked(self) -> bool:
        return self.verdict == "BLOCK"
