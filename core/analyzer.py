"""Analyzer ABC and data classes for pluggable analysis pipeline."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AnalysisContext:
    """Input context for analyzers."""
    address: str
    chain_id: int = 56
    from_address: Optional[str] = None
    is_token: Optional[bool] = True
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalyzerResult:
    """Output from a single analyzer."""
    name: str
    weight: float
    score: float  # 0-100
    flags: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


def has_transaction(ctx: AnalysisContext) -> bool:
    """Whether the context carries a transaction or signature request. A firewall request passes its
    calldata even when it is empty (a native send); a scan of an address alone passes none of these."""
    return any(key in ctx.extra for key in ('calldata', 'typed_data', 'authorization_list'))


class Analyzer(ABC):
    """Base class for pluggable analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique analyzer name."""

    @property
    @abstractmethod
    def weight(self) -> float:
        """Weight in composite score (0.0-1.0)."""

    @abstractmethod
    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        """Run analysis and return result."""
