"""Market analyzer — wraps DexService."""

import logging
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult

logger = logging.getLogger(__name__)


class MarketAnalyzer(Analyzer):
    """Analyzes market data: liquidity, pair age, volatility, wash trading."""

    def __init__(self, dex_service):
        self._service = dex_service

    @property
    def name(self) -> str:
        return "market"

    @property
    def weight(self) -> float:
        return 0.25

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        data = await self._service.fetch_token_market_data(ctx.address)
        score, flags = self._compute(data)
        return AnalyzerResult(
            name=self.name, weight=self.weight,
            score=score, flags=flags, data=data,
        )

    def _compute(self, d: dict) -> tuple:
        score = 0
        flags = []
        if d.get('low_liquidity_flag'):
            score += 30
            flags.append('Low liquidity (<$10k)')
        if d.get('new_pair_flag'):
            score += 25
            flags.append('New pair (<24h)')
        if d.get('volatility_flag'):
            score += 20
            flags.append('Extreme volatility (>200%)')
        if d.get('wash_trade_flag'):
            score += 25
            flags.append('Possible wash trading')
        fdv = d.get('fdv', 0)
        volume_24h = d.get('volume_24h', 0)
        if fdv > 1_000_000 and volume_24h < 1000:
            score += 20
            volume_ratio = (volume_24h / fdv * 100) if fdv > 0 else 0
            flags.append(
                f'Dead/Low activity (${fdv:,.0f} FDV, ${volume_24h:,.0f} volume, {volume_ratio:.4f}%)'
            )
        return min(score, 100), flags
