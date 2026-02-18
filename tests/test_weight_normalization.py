"""Tests for dynamic weight normalization in AnalyzerRegistry."""

import pytest
from unittest.mock import AsyncMock, PropertyMock

from core.analyzer import AnalysisContext, AnalyzerResult, Analyzer
from core.registry import AnalyzerRegistry


class FakeAnalyzer(Analyzer):
    """Minimal analyzer for testing."""

    def __init__(self, name: str, weight: float, score: float = 50.0):
        self._name = name
        self._weight = weight
        self._score = score

    @property
    def name(self) -> str:
        return self._name

    @property
    def weight(self) -> float:
        return self._weight

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        return AnalyzerResult(
            name=self._name,
            weight=self._weight,
            score=self._score,
        )


@pytest.mark.asyncio
async def test_weights_already_sum_to_one():
    """When 4 analyzers have weights summing to 1.0, they remain unchanged."""
    registry = AnalyzerRegistry()
    registry.register(FakeAnalyzer("structural", 0.40))
    registry.register(FakeAnalyzer("market", 0.25))
    registry.register(FakeAnalyzer("behavioral", 0.20))
    registry.register(FakeAnalyzer("honeypot", 0.15))

    ctx = AnalysisContext(address="0x" + "a" * 40)
    results = await registry.run_all(ctx)

    weights = [r.weight for r in results]
    assert abs(sum(weights) - 1.0) < 1e-9
    assert abs(weights[0] - 0.40) < 1e-9
    assert abs(weights[1] - 0.25) < 1e-9
    assert abs(weights[2] - 0.20) < 1e-9
    assert abs(weights[3] - 0.15) < 1e-9


@pytest.mark.asyncio
async def test_six_analyzers_renormalize():
    """When 6 analyzers are registered, weights are re-normalized to sum to 1.0."""
    registry = AnalyzerRegistry()
    registry.register(FakeAnalyzer("structural", 0.40))
    registry.register(FakeAnalyzer("market", 0.25))
    registry.register(FakeAnalyzer("behavioral", 0.20))
    registry.register(FakeAnalyzer("honeypot", 0.15))
    registry.register(FakeAnalyzer("intent", 0.15))
    registry.register(FakeAnalyzer("signature", 0.10))

    ctx = AnalysisContext(address="0x" + "a" * 40)
    results = await registry.run_all(ctx)

    total = sum(r.weight for r in results)
    assert abs(total - 1.0) < 1e-9

    # Relative proportions preserved: structural should still be the largest
    by_name = {r.name: r.weight for r in results}
    assert by_name["structural"] > by_name["market"] > by_name["behavioral"]


@pytest.mark.asyncio
async def test_single_analyzer_gets_full_weight():
    """A single analyzer should get weight 1.0 after normalization."""
    registry = AnalyzerRegistry()
    registry.register(FakeAnalyzer("structural", 0.40))

    ctx = AnalysisContext(address="0x" + "a" * 40)
    results = await registry.run_all(ctx)

    assert len(results) == 1
    assert abs(results[0].weight - 1.0) < 1e-9


@pytest.mark.asyncio
async def test_registry_handles_removal():
    """After removing an analyzer, remaining weights re-normalize."""
    registry = AnalyzerRegistry()
    registry.register(FakeAnalyzer("structural", 0.40))
    registry.register(FakeAnalyzer("market", 0.25))
    registry.register(FakeAnalyzer("honeypot", 0.15))

    # Remove market
    registry.unregister("market")
    assert len(registry.get_all()) == 2

    ctx = AnalysisContext(address="0x" + "a" * 40)
    results = await registry.run_all(ctx)

    total = sum(r.weight for r in results)
    assert abs(total - 1.0) < 1e-9


def test_total_raw_weight_property():
    """total_raw_weight returns the sum of all raw analyzer weights."""
    registry = AnalyzerRegistry()
    registry.register(FakeAnalyzer("a", 0.40))
    registry.register(FakeAnalyzer("b", 0.25))
    registry.register(FakeAnalyzer("c", 0.15))

    assert abs(registry.total_raw_weight - 0.80) < 1e-9
