"""Analyzer registry — collects and runs all registered analyzers."""

import logging
from typing import List

from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult

logger = logging.getLogger(__name__)


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
        regardless of how many analyzers are registered.
        """
        import asyncio
        tasks = [a.analyze(ctx) for a in self._analyzers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final = []
        for analyzer, result in zip(self._analyzers, results):
            if isinstance(result, Exception):
                logger.error(f"Analyzer {analyzer.name} failed: {result}")
                final.append(AnalyzerResult(
                    name=analyzer.name,
                    weight=analyzer.weight,
                    score=0,
                    error=str(result),
                ))
            else:
                final.append(result)

        # Normalize weights so they sum to 1.0
        total = sum(r.weight for r in final)
        if total > 0 and abs(total - 1.0) > 1e-9:
            for r in final:
                r.weight = r.weight / total

        return final
