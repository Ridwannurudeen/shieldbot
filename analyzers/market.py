"""Market analyzer — wraps DexService."""

import asyncio
import logging
import time
from adapters.botchain import canonical_token_reason
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
from services.robinhood_assets import official_asset_reason

logger = logging.getLogger(__name__)

# An interactive scan uses the market data when it answers this long before the analyzers' deadline, so
# the analyzer returns an Unknown with a named reason, not an error, before the registry cancels it. The
# lookup runs on and fills the provider's caches for the next scan.
MARKET_RESULT_RESERVE_SECONDS = 0.5
STILL_RUNNING = 'Market lookup still running at the request deadline; it continues for the next scan'


class MarketAnalyzer(Analyzer):
    """Analyzes market data: liquidity, pair age, volatility, wash trading.

    An official Robinhood Chain token (services.robinhood_assets) is skipped: the canonical WETH and
    USDG are the quote side of every pair, so DexScreener prices no pair in them, and a tokenised
    stock's pairs say nothing about the stock. The gap is named in a note, not scored. BOT Chain's
    canonical WBOT (adapters.botchain) is skipped the same way: every BDEX pool is priced in it.
    """

    def __init__(self, dex_service, robinhood_assets=None):
        self._service = dex_service
        self._assets = robinhood_assets

    @property
    def name(self) -> str:
        return "market"

    @property
    def weight(self) -> float:
        return 0.25

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        # DEX market data is only meaningful for ERC-20 tokens.
        # Non-token contracts (marketplaces, bridges, governance) have no
        # trading pairs — zero liquidity is expected, not suspicious.
        if ctx.is_token is False:
            return AnalyzerResult(
                name=self.name, weight=self.weight,
                score=0, flags=[], data={'skipped': True, 'reason': 'non-token contract'},
            )
        official = await self._assets.official(ctx.address, ctx.chain_id) if self._assets else None
        reason = (
            official_asset_reason(official, 'market-pair checks do not apply') if official is not None
            else canonical_token_reason(ctx.address, ctx.chain_id, 'market-pair checks do not apply')
        )
        if reason is not None:
            return AnalyzerResult(
                name=self.name, weight=self.weight,
                score=0, flags=[], data={'skipped': True, 'reason': reason, 'notes': [reason]},
            )

        lookup = asyncio.ensure_future(self._service.fetch_token_market_data(ctx.address, chain_id=ctx.chain_id))
        lookup.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
        deadline = ctx.extra.get('deadline')
        timeout = None if deadline is None else max(0.0, deadline - MARKET_RESULT_RESERVE_SECONDS - time.monotonic())
        await asyncio.wait((lookup,), timeout=timeout)
        data = {'status': 'unknown', 'reason': STILL_RUNNING} if not lookup.done() else lookup.result()
        score, flags = self._compute(data)
        # An ok market may lack only the 24h change. The volatility check only adds risk, so a check
        # that did not run is a note, not a danger signal.
        if data.get('status') == 'ok' and data.get('volatility_flag') is None:
            data = {**data, 'notes': ['Volatility unknown: 24h price change unavailable']}
        return AnalyzerResult(
            name=self.name, weight=self.weight,
            score=score, flags=flags, data=data,
        )

    def _compute(self, d: dict) -> tuple:
        score = 0
        flags = []
        if d.get('status') == 'unknown':
            flags.append(f"Market data unknown: {d.get('reason') or 'provider data unavailable'}")
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
        fdv = d.get('fdv')
        volume_24h = d.get('volume_24h')
        if fdv is not None and volume_24h is not None and fdv > 1_000_000 and volume_24h < 1000:
            score += 20
            volume_ratio = (volume_24h / fdv * 100) if fdv > 0 else 0
            flags.append(
                f'Dead/Low activity (${fdv:,.0f} FDV, ${volume_24h:,.0f} volume, {volume_ratio:.4f}%)'
            )
        return min(score, 100), flags
