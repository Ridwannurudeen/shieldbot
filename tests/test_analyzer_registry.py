"""Tests for analyzer registry and pluggable analyzers."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from core.analyzer import AnalysisContext, AnalyzerResult
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine


class TestAnalyzerRegistry:
    @pytest.mark.asyncio
    async def test_routing_error_propagates_from_gather(self):
        from utils.web3_client import UnsupportedChainError

        registry = AnalyzerRegistry()
        analyzer = MagicMock()
        analyzer.name = 'routing'
        analyzer.weight = 1
        error = UnsupportedChainError('unsupported chain')
        analyzer.analyze = AsyncMock(side_effect=error)
        registry.register(analyzer)
        with pytest.raises(UnsupportedChainError) as caught:
            await registry.run_all(AnalysisContext(address='0xABC'))
        assert caught.value is error

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
        assert results[0].error == "failing analysis unavailable (Exception)"
        assert results[0].score == 50  # fail-closed: cautious neutral, not 0 (safe)
        assert "failing analysis unavailable" in results[0].flags

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


class TestMarketProviderCoverage:
    @pytest.mark.asyncio
    async def test_requested_chain_filters_selection_and_volume(self):
        from unittest.mock import patch
        from services.dex_service import DexService

        pairs = [
            {'chainId': 'bsc', 'liquidity': {'usd': 900000}, 'volume': {'h24': 800000}},
            {'chainId': 'robinhood', 'liquidity': {'usd': 12000}, 'volume': {'h24': 300}},
            {'chainId': 'robinhood', 'liquidity': {'usd': 1000}, 'volume': {'h24': 200}},
        ]
        response = AsyncMock(status=200)
        response.json.return_value = pairs
        session = MagicMock()
        session.get.return_value.__aenter__.return_value = response
        with patch('services.dex_service.aiohttp.ClientSession') as session_type, patch(
            'services.dex_service.get_dexscreener_slug', return_value='robinhood'
        ) as slug:
            session_type.return_value.__aenter__.return_value = session
            result = await DexService().fetch_token_market_data('0xABC', chain_id=4663)
        slug.assert_called_once_with(4663)
        assert result['liquidity_usd'] == 12000
        assert result['volume_24h'] == 500

    @pytest.mark.asyncio
    @pytest.mark.parametrize('pairs', [[], [{'chainId': 'ethereum', 'liquidity': {'usd': 999999}}], [{'chainId': 'bsc'}]])
    async def test_absent_market_metrics_are_unknown(self, pairs):
        from unittest.mock import patch
        from services.dex_service import DexService
        from analyzers.market import MarketAnalyzer

        response = AsyncMock(status=200)
        response.json.return_value = pairs
        session = MagicMock()
        session.get.return_value.__aenter__.return_value = response
        with patch('services.dex_service.aiohttp.ClientSession') as session_type:
            session_type.return_value.__aenter__.return_value = session
            result = await MarketAnalyzer(DexService()).analyze(AnalysisContext(address='0xABC'))
        assert result.data['liquidity_usd'] is None
        assert result.data['volume_24h'] is None
        assert result.data['status'] == 'unknown'
        assert result.data['coverage']['liquidity_usd'] is False
        assert any('unknown' in flag.lower() for flag in result.flags)

    @pytest.mark.asyncio
    async def test_market_propagates_chain_and_handles_none(self):
        from analyzers.market import MarketAnalyzer

        service = MagicMock()
        service.fetch_token_market_data = AsyncMock(return_value={
            'fdv': None, 'volume_24h': None, 'status': 'unknown',
            'reason': 'No pairs on requested chain',
        })
        result = await MarketAnalyzer(service).analyze(AnalysisContext(address='0xABC', chain_id=4663))
        service.fetch_token_market_data.assert_awaited_once_with('0xABC', chain_id=4663)
        assert result.data['status'] == 'unknown'
        assert result.flags

    def test_fully_covered_market_score_unchanged(self):
        from analyzers.market import MarketAnalyzer

        score, flags = MarketAnalyzer(MagicMock())._compute({
            'low_liquidity_flag': True, 'new_pair_flag': True,
            'volatility_flag': False, 'wash_trade_flag': False,
            'fdv': 2000000, 'volume_24h': 200,
        })
        assert score == 75
        assert len(flags) == 3

    @pytest.mark.asyncio
    async def test_legacy_non_bsc_checks_are_explicitly_unknown(self):
        from scanner.token_scanner import TokenScanner

        web3 = MagicMock()
        scanner = TokenScanner(web3)
        result = {'checks': {'can_sell': True}, 'risks': []}
        await scanner._check_honeypot('0xABC', result, chain_id=4663)
        assert await scanner._check_taxes('0xABC', result, chain_id=4663) is False
        assert result['is_honeypot'] is None
        assert result['checks']['can_sell'] is None
        assert result['buy_tax'] is None
        assert result['sell_tax'] is None
        assert any('honeypot' in flag.lower() and 'unknown' in flag.lower() for flag in result['risks'])
        assert any('tax' in flag.lower() and 'unknown' in flag.lower() for flag in result['risks'])
        assert scanner._calculate_safety_level(result) != 'safe'
        web3.check_honeypot.assert_not_called()
        web3.get_tax_info.assert_not_called()


    @pytest.mark.asyncio
    @pytest.mark.parametrize('failure', [None, RuntimeError('provider unavailable')])
    async def test_legacy_bsc_missing_provider_data_stays_unknown(self, failure):
        from scanner.token_scanner import TokenScanner

        web3 = MagicMock()
        web3.check_honeypot = AsyncMock(return_value={'is_honeypot': None, 'status': 'unknown'}, side_effect=failure)
        web3.get_tax_info = AsyncMock(return_value={'buy_tax': None, 'sell_tax': None}, side_effect=failure)
        scanner = TokenScanner(web3)
        result = {'checks': {'can_sell': True}, 'risks': []}
        await scanner._check_honeypot('0xABC', result)
        assert await scanner._check_taxes('0xABC', result) is False
        assert result['is_honeypot'] is None
        assert result['checks']['can_sell'] is None
        assert result['buy_tax'] is None
        assert result['sell_tax'] is None
        assert scanner._calculate_safety_level(result) == 'unknown'

    @pytest.mark.asyncio
    @pytest.mark.parametrize('http_status,failure', [(500, None), (200, TimeoutError()), (200, RuntimeError('unavailable'))])
    async def test_dex_provider_failures_are_unknown(self, http_status, failure):
        from unittest.mock import patch
        from services.dex_service import DexService

        response = AsyncMock(status=http_status)
        response.json.side_effect = failure
        session = MagicMock()
        session.get.return_value.__aenter__.return_value = response
        with patch('services.dex_service.aiohttp.ClientSession') as session_type:
            session_type.return_value.__aenter__.return_value = session
            result = await DexService().fetch_token_market_data('0xABC')
        assert result['status'] == 'unknown'
        assert result['liquidity_usd'] is None
        assert result['low_liquidity_flag'] is None
        assert result['reason']


class TestProviderCoverageRisk:
    def test_unknown_honeypot_excluded_and_displayed(self):
        from core.extension_formatter import format_extension_alert
        from core.telegram_formatter import format_full_report

        unknown = {
            "status": "unknown", "reason": "Provider unavailable",
            "is_honeypot": None, "can_sell": None, "can_buy": None,
            "buy_tax": None, "sell_tax": None,
        }
        contract = {"is_verified": True, "is_contract": True, "contract_age_days": 100}
        market = {"liquidity_usd": 200000, "pair_age_hours": 100}
        ethos = {"reputation_score": 80}
        results = [
            AnalyzerResult("structural", .40, 10, data=contract),
            AnalyzerResult("market", .25, 0, data=market),
            AnalyzerResult("behavioral", .20, 0, data=ethos),
            AnalyzerResult("honeypot", .15, 0, data=unknown),
        ]
        output = RiskEngine().compute_from_results(results)
        assert output["rug_probability"] == 4.7
        assert output["category_scores"]["honeypot"] is None
        assert output["risk_level"] == "MEDIUM"
        assert output["risk_archetype"] == "unknown"
        assert output["confidence_level"] <= 85
        alert = format_extension_alert(output)
        assert alert["risk_classification"] == "CAUTION"
        assert "unknown" in alert["recommended_action"].lower()
        report = format_full_report(output, contract, market, ethos, unknown)
        assert "Buy Tax: Unknown" in report
        assert "Sell Tax: Unknown" in report
        assert "Sellability: Unknown" in report
        assert "Provider unavailable" in report
        assert "Generally Safe" not in report
        assert "Not Honeypot" not in report

    def test_legacy_null_provider_fields(self):
        output = RiskEngine().compute_composite_risk(
            {"is_verified": True},
            {"is_honeypot": None, "can_sell": None, "buy_tax": None, "sell_tax": None},
            {"status": "unknown", "liquidity_usd": None, "fdv": None, "volume_24h": None},
            {},
        )
        assert output["risk_level"] == "MEDIUM"
        assert output["risk_archetype"] == "unknown"
        assert output["category_scores"]["honeypot"] is None
        assert output["category_scores"]["market"] is None
        assert "Cannot sell token" not in output["critical_flags"]

    def test_failed_analyzer_score_excluded(self):
        output = RiskEngine().compute_from_results([
            AnalyzerResult("structural", .5, 20, data={"is_verified": True}),
            AnalyzerResult("market", .5, 50, error="timeout"),
        ])
        assert output["rug_probability"] == 20
        assert output["category_scores"]["market"] is None
        assert output["confidence_level"] <= 50
        assert output["risk_level"] == "MEDIUM"

    def test_simulation_failure_remains_suspicious(self):
        output = RiskEngine().compute_from_results([
            AnalyzerResult("structural", .85, 0, data={"is_contract": True}),
            AnalyzerResult("honeypot", .15, 40, data={
                "status": "unknown", "simulation_failed": True,
                "is_honeypot": None, "can_sell": None, "sell_tax": None,
            }),
        ])
        assert output["rug_probability"] > 0
        assert output["risk_level"] != "LOW"

    def test_confirmed_honeypot_with_unknown_liquidity(self):
        output = RiskEngine().compute_from_results([
            AnalyzerResult("market", .25, 0, data={"liquidity_usd": None, "status": "unknown"}),
            AnalyzerResult("honeypot", .75, 80, data={"is_honeypot": True, "sell_tax": None}),
        ])
        assert output["rug_probability"] >= 80
        assert output["risk_archetype"] == "honeypot"

    def test_no_observations_have_no_category_scores(self):
        output = RiskEngine().compute_composite_risk({}, {}, {}, {})
        assert all(value is None for value in output['category_scores'].values())
        assert output['confidence_level'] == 0
        assert output['risk_level'] == 'MEDIUM'
        assert output['risk_archetype'] == 'unknown'

    def test_partial_honeypot_coverage_does_not_discount_risk(self):
        output = RiskEngine().compute_from_results([
            AnalyzerResult('structural', .85, 40, data={'is_verified': True, 'ownership_renounced': True}),
            AnalyzerResult('honeypot', .15, 0, data={'is_honeypot': False, 'can_sell': None}),
        ])
        assert output['rug_probability'] == 40
        assert output['category_scores']['honeypot'] is None
        assert output['status'] == 'unknown'

    def test_fully_covered_regression(self):
        output = RiskEngine().compute_from_results([
            AnalyzerResult("structural", .40, 25, data={"is_verified": True, "contract_age_days": 100}),
            AnalyzerResult("market", .25, 20, data={"liquidity_usd": 50000}),
            AnalyzerResult("behavioral", .20, 30, data={"reputation_score": 70}),
            AnalyzerResult("honeypot", .15, 0, data={
                "is_honeypot": False, "can_sell": True, "buy_tax": 0, "sell_tax": 0,
            }),
        ])
        assert output["rug_probability"] == 21
        assert output["risk_level"] == "LOW"
        assert output["risk_archetype"] == "legitimate"
        assert output["confidence_level"] == 80

    def test_formatters_empty_market_data_is_unknown(self):
        from core.telegram_formatter import format_full_report
        output = {"rug_probability": 0, "risk_level": "MEDIUM", "status": "unknown"}
        report = format_full_report(output, {}, {}, {}, {})
        assert "Liquidity: Unknown" in report
        assert "Buy Tax: Unknown" in report
        assert "Verified: Unknown" in report
        assert "Generally Safe" not in report


class TestHoneypotUnknowns:
    @pytest.mark.asyncio
    @pytest.mark.parametrize('data', [
        {},
        {'is_honeypot': None, 'buy_tax': None, 'sell_tax': None, 'can_sell': None},
    ])
    async def test_unknown_data_has_coverage_and_flag(self, data):
        from analyzers.honeypot import HoneypotAnalyzer
        service = MagicMock()
        service.fetch_honeypot_data = AsyncMock(return_value=data)
        result = await HoneypotAnalyzer(service).analyze(AnalysisContext(address='0xABC'))
        assert result.data['status'] == 'unknown'
        assert not any(result.data['coverage'].values())
        assert any('Sellability unknown' in flag for flag in result.flags)

    @pytest.mark.asyncio
    @pytest.mark.parametrize('data, expected', [
        ({'is_honeypot': True, 'sell_tax': None, 'buy_tax': None}, 80),
        ({'simulation_failed': True, 'sell_tax': None, 'buy_tax': None}, 40),
        ({'can_sell': False, 'sell_tax': None, 'buy_tax': None}, 60),
        ({'is_honeypot': False, 'can_buy': True, 'can_sell': True, 'sell_tax': 55, 'buy_tax': 25}, 50),
    ])
    async def test_known_risk_survives_unknown_fields(self, data, expected):
        from analyzers.honeypot import HoneypotAnalyzer
        service = MagicMock()
        service.fetch_honeypot_data = AsyncMock(return_value=data)
        result = await HoneypotAnalyzer(service).analyze(AnalysisContext(address='0xABC'))
        assert result.score == expected


class TestHoneypotTransferRestrictions:
    @pytest.mark.asyncio
    @pytest.mark.parametrize('field, flag', [
        ('cannot_sell_all', 'Cannot sell all tokens'),
        ('transfer_pausable', 'Token transfers can be paused'),
    ])
    async def test_restrictions_are_suspicious_without_claiming_no_sales(self, field, flag):
        from analyzers.honeypot import HoneypotAnalyzer
        service = MagicMock()
        service.fetch_honeypot_data = AsyncMock(return_value={field: True, 'can_sell': None})
        result = await HoneypotAnalyzer(service).analyze(AnalysisContext(address='0xABC'))
        assert flag in result.flags
        assert 'Cannot sell token' not in result.flags
        assert result.score > 0
        assert result.data['can_sell'] is None
