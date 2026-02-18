"""Honeypot analyzer — wraps HoneypotService."""

import logging
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult

logger = logging.getLogger(__name__)


class HoneypotAnalyzer(Analyzer):
    """Analyzes honeypot status and tax info."""

    def __init__(self, honeypot_service):
        self._service = honeypot_service

    @property
    def name(self) -> str:
        return "honeypot"

    @property
    def weight(self) -> float:
        return 0.15

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        data = await self._service.fetch_honeypot_data(ctx.address, chain_id=ctx.chain_id)
        score, flags = self._compute(data)
        return AnalyzerResult(
            name=self.name, weight=self.weight,
            score=score, flags=flags, data=data,
        )

    def _compute(self, d: dict) -> tuple:
        score = 0
        flags = []
        if d.get('is_honeypot'):
            score += 80
            flags.append('Honeypot detected')
        if d.get('simulation_failed') and not d.get('is_honeypot'):
            score += 40
            flags.append('Honeypot simulation failed — treat as suspicious')
        if d.get('can_sell') is False:
            score += 60
            flags.append('Cannot sell token')
        sell_tax = d.get('sell_tax', 0)
        buy_tax = d.get('buy_tax', 0)
        if sell_tax > 50:
            score += 40
            flags.append(f'Extreme sell tax: {sell_tax}%')
        elif sell_tax > 20:
            score += 20
        if buy_tax > 20:
            score += 10
        return min(score, 100), flags
