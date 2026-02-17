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

    def get_all(self) -> List[Analyzer]:
        """Return all registered analyzers."""
        return list(self._analyzers)

    async def run_all(self, ctx: AnalysisContext) -> List[AnalyzerResult]:
        """Run all analyzers and return results (including failed ones)."""
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
        return final
