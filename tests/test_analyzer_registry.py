"""Tests for analyzer registry and pluggable analyzers."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from core.analyzer import AnalysisContext, AnalyzerResult
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine


class TestAnalyzerRegistry:
    @pytest.mark.asyncio
    async def test_register_and_run_all(self):
        registry = AnalyzerRegistry()

        mock_analyzer = MagicMock()
        mock_analyzer.name = "test"
        mock_analyzer.weight = 0.5
        mock_analyzer.analyze = AsyncMock(return_value=AnalyzerResult(
            name="test", weight=0.5, score=50.0, flags=["test flag"],
        ))

        registry.register(mock_analyzer)
        assert len(registry.get_all()) == 1

        ctx = AnalysisContext(address="0xABC", chain_id=56)
        results = await registry.run_all(ctx)
        assert len(results) == 1
        assert results[0].name == "test"
        assert results[0].score == 50.0

    @pytest.mark.asyncio
    async def test_run_all_handles_exception(self):
        registry = AnalyzerRegistry()

        failing = MagicMock()
        failing.name = "failing"
        failing.weight = 0.5
        failing.analyze = AsyncMock(side_effect=Exception("boom"))

        registry.register(failing)

        ctx = AnalysisContext(address="0xABC")
        results = await registry.run_all(ctx)
        assert len(results) == 1
        assert results[0].error == "boom"
        assert results[0].score == 0

    @pytest.mark.asyncio
    async def test_multiple_analyzers(self):
        registry = AnalyzerRegistry()

        for name, weight, score in [("a", 0.4, 80), ("b", 0.3, 50), ("c", 0.3, 20)]:
            m = MagicMock()
            m.name = name
            m.weight = weight
            m.analyze = AsyncMock(return_value=AnalyzerResult(
                name=name, weight=weight, score=score,
            ))
            registry.register(m)

        ctx = AnalysisContext(address="0xABC")
        results = await registry.run_all(ctx)
        assert len(results) == 3


class TestStructuralAnalyzer:
    @pytest.mark.asyncio
    async def test_basic_analysis(self):
        from analyzers.structural import StructuralAnalyzer

        mock_service = MagicMock()
        mock_service.fetch_contract_data = AsyncMock(return_value={
            'is_verified': False,
            'contract_age_days': 3,
            'has_mint': True,
            'has_proxy': False,
            'has_pause': False,
            'has_blacklist': False,
            'scam_matches': [],
            'ownership_renounced': True,
        })

        analyzer = StructuralAnalyzer(mock_service)
        assert analyzer.name == "structural"
        assert analyzer.weight == 0.40

        ctx = AnalysisContext(address="0xABC")
        result = await analyzer.analyze(ctx)
        # 25 (not verified) + 20 (age < 7) + 15 (mint) = 60
        assert result.score == 60
        assert 'Contract not verified' in result.flags


class TestRiskEngineFromResults:
    def test_identical_output_shape(self):
        """compute_from_results should produce the same output keys as compute_composite_risk."""
        engine = RiskEngine()

        # Old path
        old = engine.compute_composite_risk(
            {'is_verified': True, 'contract_age_days': 100},
            {'is_honeypot': False, 'can_sell': True, 'sell_tax': 0, 'buy_tax': 0},
            {'low_liquidity_flag': False, 'liquidity_usd': 200000},
            {'severe_reputation_flag': False, 'reputation_score': 80},
        )

        # New path
        results = [
            AnalyzerResult(name="structural", weight=0.40, score=0, data={
                'is_verified': True, 'contract_age_days': 100,
            }),
            AnalyzerResult(name="market", weight=0.25, score=0, data={
                'low_liquidity_flag': False, 'liquidity_usd': 200000,
            }),
            AnalyzerResult(name="behavioral", weight=0.20, score=0, data={
                'severe_reputation_flag': False, 'reputation_score': 80,
            }),
            AnalyzerResult(name="honeypot", weight=0.15, score=0, data={
                'is_honeypot': False, 'can_sell': True, 'sell_tax': 0, 'buy_tax': 0,
            }),
        ]
        new = engine.compute_from_results(results)

        # Same keys
        assert set(old.keys()) == set(new.keys())
        # Both should be LOW risk with same probability
        assert old['risk_level'] == new['risk_level'] == 'LOW'
        assert old['rug_probability'] == new['rug_probability']

    def test_escalation_honeypot(self):
        engine = RiskEngine()
        results = [
            AnalyzerResult(name="structural", weight=0.40, score=0, data={}),
            AnalyzerResult(name="market", weight=0.25, score=0, data={}),
            AnalyzerResult(name="behavioral", weight=0.20, score=0, data={}),
            AnalyzerResult(name="honeypot", weight=0.15, score=100, data={
                'is_honeypot': True,
            }, flags=['Honeypot detected']),
        ]
        out = engine.compute_from_results(results)
        assert out['rug_probability'] >= 80  # Floor at 80 for honeypot
        assert out['risk_archetype'] == 'honeypot'
