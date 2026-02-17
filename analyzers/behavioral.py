"""Behavioral analyzer — wraps EthosService."""

import logging
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult

logger = logging.getLogger(__name__)


class BehavioralAnalyzer(Analyzer):
    """Analyzes wallet reputation via Ethos Network."""

    def __init__(self, ethos_service):
        self._service = ethos_service

    @property
    def name(self) -> str:
        return "behavioral"

    @property
    def weight(self) -> float:
        return 0.20

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        # Use from_address for reputation if available, else target address
        addr = ctx.from_address or ctx.address
        data = await self._service.fetch_wallet_reputation(addr)
        score, flags = self._compute(data)
        return AnalyzerResult(
            name=self.name, weight=self.weight,
            score=score, flags=flags, data=data,
        )

    def _compute(self, d: dict) -> tuple:
        score = 0
        flags = []
        if d.get('severe_reputation_flag'):
            score += 50
            flags.append('Severe reputation warning')
        elif d.get('low_reputation_flag'):
            score += 30
            flags.append('Low wallet reputation')
        if d.get('scam_flags'):
            score += 40
            flags.append('Ethos scam flags present')
        return min(score, 100), flags
