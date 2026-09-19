"""Analyzer registry — collects and runs all registered analyzers."""

import asyncio
import logging
from typing import List

from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
from utils.web3_client import UnsupportedChainError

logger = logging.getLogger(__name__)

# Overall deadline for one scan's analyzers. It outlasts the longest single provider timeout on
# the scan path (15 s explorer calls; honeypot.is, DexScreener, Ethos and TokenSniffer use 10 s),
# so a slow provider still reports its own reason, and it ends before the extension abandons a
# firewall request at 30 s, so a hung provider yields an incomplete answer instead of none.
RUN_ALL_DEADLINE_SECONDS = 20


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

    async def run_all(self, ctx: AnalysisContext) -> List[AnalyzerResult]:
        """Run all analyzers and return results with normalized weights.

        Each result's weight is normalized so that all weights sum to 1.0,
        regardless of how many analyzers are registered. An analyzer still running at
        RUN_ALL_DEADLINE_SECONDS is cancelled and reported exactly like one that raised
        TimeoutError: unavailable, never safe.
        """
        tasks = [asyncio.ensure_future(a.analyze(ctx)) for a in self._analyzers]
        pending = set()
        try:
            if tasks:
                _, pending = await asyncio.wait(tasks, timeout=RUN_ALL_DEADLINE_SECONDS)
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
                final.append(result)

        # Normalize weights so they sum to 1.0
        total = sum(r.weight for r in final)
        if total > 0 and abs(total - 1.0) > 1e-9:
            for r in final:
                r.weight = r.weight / total

        return final
