"""Analyzer registry — collects and runs all registered analyzers."""

import asyncio
import logging
import time
from typing import Callable, List, Optional

from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
from utils.web3_client import UnsupportedChainError

logger = logging.getLogger(__name__)

# Overall deadlines for one scan's analyzers, set from the provider timeouts on the scan path:
# honeypot.is 10 s per request, called twice in a row (honeypot, then taxes) before the GoPlus
# fallback (8 s, usually already cached by the structural analyzer's scam check); explorer calls
# 15 s; DexScreener, Ethos and TokenSniffer 10 s; the 4663 buy/sell simulation 30 s per RPC
# request, with 1 s and 2 s of rate-limit backoff.
#
# Interactive scans get 25 s: both honeypot.is timeouts plus the cached GoPlus answer fit, and the
# answer still arrives before the extension abandons a firewall request at 30 s, so a hung
# provider yields an incomplete answer instead of none.
RUN_ALL_DEADLINE_SECONDS = 25
# Background scans (the hunter sweep and the launch watch) have no client waiting, so they get
# 45 s: one full 30 s simulator request, its 3 s of backoff and a healthy scan's other work (p90
# 5.4 s measured live on 4663), or the whole honeypot.is chain with an uncached GoPlus call (28 s).
BACKGROUND_SCAN_DEADLINE_SECONDS = 45
# A streamed firewall request (POST /api/firewall with Accept: text/event-stream) gets its interim
# verdict this many seconds after the handler starts, or sooner when a Block-level floor is known. The
# clock starts with the handler, not with run_all: the handler's pre-steps (token info, selector
# lookup, cache read, bytecode, is_token and the verification lookup, which can take 16 s) run before
# the analyzers do. Every required check is an external call that rarely finishes this fast from
# cold, so the interim is usually Unknown; it is a tenth of the extension's 30 s abort, which leaves
# the final verdict the rest of that time.
FIRST_VERDICT_SECONDS = 3


class AnalyzerRegistry:
    """Registry for pluggable analyzers."""

    def __init__(self):
        self._analyzers: List[Analyzer] = []

    def register(self, analyzer: Analyzer):
        """Register an analyzer."""
        self._analyzers.append(analyzer)
        logger.info(f"Registered analyzer: {analyzer.name} (weight={analyzer.weight})")

    def unregister(self, name: str):
        """Remove an analyzer by name."""
        self._analyzers = [a for a in self._analyzers if a.name != name]

    def get_all(self) -> List[Analyzer]:
        """Return all registered analyzers."""
        return list(self._analyzers)

    @property
    def total_raw_weight(self) -> float:
        """Sum of all registered analyzer raw weights."""
        return sum(a.weight for a in self._analyzers)

    async def run_all(
        self,
        ctx: AnalysisContext,
        deadline: Optional[float] = None,
        on_result: Optional[Callable[[AnalyzerResult], None]] = None,
    ) -> List[AnalyzerResult]:
        """Run all analyzers and return results with normalized weights.

        Each result's weight is normalized so that all weights sum to 1.0,
        regardless of how many analyzers are registered. An analyzer still running at the
        deadline (RUN_ALL_DEADLINE_SECONDS unless ``deadline`` is given) is cancelled and
        reported exactly like one that raised TimeoutError: unavailable, never safe.

        ``on_result``, when given, is called with an analyzer's result as soon as that analyzer
        returns normally, never for one that raises or runs past the deadline, so a caller can read
        results while the others still run. It gets the object before weight normalization and the
        observed_at stamp below, and must not mutate it. The results are the same with or without it.
        """
        observed_at = time.time()

        async def analyze(analyzer: Analyzer) -> AnalyzerResult:
            result = await analyzer.analyze(ctx)
            if on_result is not None:
                on_result(result)
            return result

        tasks = [asyncio.ensure_future(analyze(a)) for a in self._analyzers]
        pending = set()
        try:
            if tasks:
                _, pending = await asyncio.wait(
                    tasks, timeout=RUN_ALL_DEADLINE_SECONDS if deadline is None else deadline
                )
        finally:
            for task in tasks:
                task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        results = [
            asyncio.TimeoutError() if task in pending else task.exception() or task.result()
            for task in tasks
        ]

        final = []
        for analyzer, result in zip(self._analyzers, results):
            if isinstance(result, UnsupportedChainError):
                raise result
            if isinstance(result, Exception):
                logger.error("Analyzer %s failed: %s", analyzer.name, type(result).__name__)
                # Cautious neutral score (not 0/safe) — fail-closed on missing data
                final.append(AnalyzerResult(
                    name=analyzer.name,
                    weight=analyzer.weight,
                    score=50,
                    flags=[f"{analyzer.name} analysis unavailable"],
                    error=f"{analyzer.name} analysis unavailable ({type(result).__name__})",
                ))
            else:
                # Local/uncached analyzers start measuring here; providers carrying cached
                # measurements keep their original observation time.
                if result.data and not result.data.get('skipped'):
                    result.data = {**result.data, 'observed_at': min(observed_at, result.data.get('observed_at', observed_at))}
                final.append(result)

        # Normalize weights so they sum to 1.0
        total = sum(r.weight for r in final)
        if total > 0 and abs(total - 1.0) > 1e-9:
            for r in final:
                r.weight = r.weight / total

        return final
