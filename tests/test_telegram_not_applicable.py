from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine
from core.telegram_formatter import format_full_report


def _report(risk):
    return format_full_report(risk, {}, {}, {}, chain_id=56)


def test_a_skipped_market_analyzer_shows_its_reason_instead_of_a_zero_score():
    report = _report(
        {
            'rug_probability': 0,
            'risk_level': 'LOW',
            'status': 'ok',
            'category_scores': {'market': 0.0},
            'not_applicable': {'market': 'X does not apply'},
        }
    )

    assert '  Market: Not applicable (X does not apply)' in report
    assert '  Market: 0.0/100' not in report


def test_a_skipped_market_without_a_reason_has_no_parentheses():
    report = _report(
        {
            'rug_probability': 0,
            'risk_level': 'LOW',
            'status': 'ok',
            'category_scores': {'market': 0.0},
            'coverage_reasons': {'market': 'Must not be shown for a skipped category'},
            'not_applicable': {'market': ''},
        }
    )

    assert '  Market: Not applicable\n' in report
    assert 'Market: Not applicable (' not in report


def test_scored_and_unknown_categories_keep_their_existing_rendering():
    report = _report(
        {
            'rug_probability': 0,
            'risk_level': 'LOW',
            'status': 'ok',
            'category_scores': {'structural': 12, 'market': 7.5},
            'not_applicable': {},
        }
    )

    assert '  Structural: 12/100\n' in report
    assert '  Market: 7.5/100\n' in report
    assert '  Behavioral: Unknown\n' in report


def _results(market_data):
    return [
        AnalyzerResult(
            'structural', 0.4, 20,
            data={'status': 'ok', 'is_verified': True, 'contract_age_days': 30},
        ),
        AnalyzerResult('market', 0.25, 0, data=market_data),
        AnalyzerResult('behavioral', 0.2, 30, data={'status': 'ok'}),
        AnalyzerResult(
            'honeypot', 0.15, 0,
            data={'is_honeypot': False, 'can_sell': True, 'buy_tax': 0, 'sell_tax': 0},
        ),
    ]


def test_engine_output_keeps_zero_scores_and_reports_skipped_analyzers():
    skipped = RiskEngine().compute_from_results(
        _results({'skipped': True, 'reason': 'X does not apply'})
    )
    scored = RiskEngine().compute_from_results(_results({'status': 'ok'}))

    assert skipped['not_applicable'] == {'market': 'X does not apply'}
    assert skipped['category_scores']['market'] == 0.0
    assert scored['not_applicable'] == {}
    assert scored['category_scores']['market'] == 0


def test_direct_engine_output_also_carries_not_applicable_categories():
    skipped = RiskEngine().compute_composite_risk(
        {}, {}, {'skipped': True, 'reason': 'X does not apply'}, {}, is_token=False
    )
    scored = RiskEngine().compute_composite_risk({}, {}, {}, {}, is_token=False)

    assert skipped['not_applicable'] == {'market': 'X does not apply'}
    assert skipped['category_scores']['market'] == 0.0
    assert scored['not_applicable'] == {}
