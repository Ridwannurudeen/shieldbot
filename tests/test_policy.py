"""Tests for core.policy.PolicyEngine."""

import pytest
from core.policy import PolicyEngine, PolicyMode
from core.analyzer import AnalyzerResult


def _make_result(name, score=50.0, weight=0.25, error=None):
    return AnalyzerResult(name=name, weight=weight, score=score, error=error)


class TestPolicyStrict:
    def test_strict_blocks_on_failure(self):
        engine = PolicyEngine("STRICT")
        results = [
            _make_result("structural", score=30),
            _make_result("market", score=20, error="timeout"),  # failed
            _make_result("behavioral", score=10),
            _make_result("honeypot", score=0),
        ]
        risk_output = {'rug_probability': 25, 'risk_level': 'LOW', 'critical_flags': []}

        out = engine.apply(results, risk_output)
        assert out['partial'] is True
        assert out['policy_override'] == 'BLOCK_RECOMMENDED'
        assert out['rug_probability'] >= 80
        assert 'market' in out['failed_sources']

    def test_strict_no_failure_passes(self):
        engine = PolicyEngine("STRICT")
        results = [
            _make_result("structural", score=30),
            _make_result("market", score=20),
            _make_result("behavioral", score=10),
            _make_result("honeypot", score=0),
        ]
        risk_output = {'rug_probability': 25, 'risk_level': 'LOW'}

        out = engine.apply(results, risk_output)
        assert out['partial'] is False
        assert out['policy_override'] is None
        assert out['rug_probability'] == 25


class TestPolicyBalanced:
    def test_balanced_warns_on_failure(self):
        engine = PolicyEngine("BALANCED")
        results = [
            _make_result("structural", score=30),
            _make_result("market", score=20, error="timeout"),
            _make_result("behavioral", score=10),
            _make_result("honeypot", score=0),
        ]
        risk_output = {'rug_probability': 25, 'risk_level': 'LOW', 'critical_flags': []}

        out = engine.apply(results, risk_output)
        assert out['partial'] is True
        assert out['policy_override'] is None  # Balanced doesn't force BLOCK
        assert out['rug_probability'] == 25  # Score unchanged
        assert any('Partial analysis' in f for f in out['critical_flags'])

    def test_balanced_no_failure(self):
        engine = PolicyEngine("BALANCED")
        results = [_make_result("structural"), _make_result("market")]
        risk_output = {'rug_probability': 50, 'risk_level': 'MEDIUM'}

        out = engine.apply(results, risk_output)
        assert out['partial'] is False
        assert out['failed_sources'] == []


class TestPolicyModes:
    def test_mode_enum(self):
        assert PolicyMode.STRICT.value == "STRICT"
        assert PolicyMode.BALANCED.value == "BALANCED"

    def test_case_insensitive_init(self):
        engine = PolicyEngine("strict")
        assert engine.mode == PolicyMode.STRICT

    def test_multiple_failures_strict(self):
        engine = PolicyEngine("STRICT")
        results = [
            _make_result("structural", error="timeout"),
            _make_result("honeypot", error="timeout"),
        ]
        risk_output = {'rug_probability': 10, 'risk_level': 'LOW', 'critical_flags': []}

        out = engine.apply(results, risk_output)
        assert out['policy_override'] == 'BLOCK_RECOMMENDED'
        assert len(out['failed_sources']) == 2


def _covered(name, **coverage):
    """A result that failed without raising: its provider left the named fields unknown."""
    status = 'ok' if all(coverage.values()) else 'unknown'
    return AnalyzerResult(name=name, weight=0.2, score=0, data={'coverage': coverage, 'status': status})


STRUCTURAL = _covered("structural", is_verified=True, contract_age_days=True, scam_database=True)
HONEYPOT = _covered("honeypot", is_honeypot=True, can_sell=True, buy_tax=True, sell_tax=True, can_buy=True)


class TestPolicyIncompleteCoverage:
    # Providers swallow failures into unknown results: no error, a required field unknown.
    RESULTS = [STRUCTURAL, _covered("honeypot", is_honeypot=True, can_sell=False, buy_tax=True)]

    def _risk(self):
        return {'rug_probability': 25, 'risk_level': 'MEDIUM', 'critical_flags': []}

    def test_strict_blocks_on_incomplete_coverage(self):
        out = PolicyEngine("STRICT").apply(self.RESULTS, self._risk())
        assert out['partial'] is True
        assert out['failed_sources'] == ['honeypot']
        assert out['policy_override'] == 'BLOCK_RECOMMENDED'
        assert out['risk_level'] == 'HIGH'
        assert out['rug_probability'] == 80
        assert out['critical_flags'][0] == (
            "Policy override: 1 analyzer(s) unavailable or incomplete (honeypot)"
        )

    def test_balanced_warns_on_incomplete_coverage(self):
        out = PolicyEngine("BALANCED").apply(self.RESULTS, self._risk())
        assert out['partial'] is True
        assert out['failed_sources'] == ['honeypot']
        assert out['policy_override'] is None
        assert out['rug_probability'] == 25
        assert out['risk_level'] == 'MEDIUM'
        assert out['critical_flags'] == ["Partial analysis: honeypot unavailable or incomplete"]

    def test_skipped_analyzers_are_covered_not_failed(self):
        skipped = AnalyzerResult(name="honeypot", weight=0.2, score=0, data={'skipped': True})
        out = PolicyEngine("STRICT").apply([STRUCTURAL, skipped], self._risk())
        assert out['partial'] is False
        assert out['policy_override'] is None

    def test_errored_analyzer_is_named_once(self):
        structural = _covered("structural", is_verified=False, contract_age_days=True, scam_database=True)
        results = [structural, _make_result("honeypot", error="timeout")]
        out = PolicyEngine("STRICT").apply(results, self._risk())
        assert out['failed_sources'] == ['honeypot', 'structural']

    @pytest.mark.parametrize('result', [
        _covered("structural", is_verified=True, contract_age_days=False, scam_database=True),
        _covered("structural", is_verified=True, contract_age_days=True, scam_database=False),
        _covered("honeypot", is_honeypot=False, can_sell=True),
        _covered("intent", selector_verification=True, counterparty=False),
        _covered("intent", selector_verification=False),
        _covered("signature", counterparty=False),
        # An unknown result that does not say which fields it lacks may lack any of them.
        AnalyzerResult(name="structural", weight=0.2, score=0, data={'status': 'unknown'}),
    ], ids=['contract-age', 'scam-lookup', 'honeypot', 'grant-counterparty', 'target-verification',
            'permit-counterparty', 'unknown-without-coverage'])
    def test_strict_blocks_when_a_required_field_is_unknown(self, result):
        out = PolicyEngine("STRICT").apply([result], self._risk())
        assert out['failed_sources'] == [result.name]
        assert out['policy_override'] == 'BLOCK_RECOMMENDED'

    @pytest.mark.parametrize('result', [
        # DexScreener fields describe the market, and Ethos the counterparty's standing: a gap in
        # either never decides a verdict.
        _covered("market", liquidity_usd=True, pair_age_hours=False, price_change_24h=False),
        AnalyzerResult(name="behavioral", weight=0.2, score=0, data={'status': 'unknown', 'reason': 'Ethos HTTP 503'}),
        _covered("honeypot", is_honeypot=True, can_sell=True, buy_tax=False, sell_tax=False, can_buy=False),
        _covered("structural", is_verified=True, contract_age_days=True, scam_database=True, bytecode=False),
    ], ids=['market', 'reputation', 'taxes', 'bytecode'])
    def test_strict_ignores_informational_gaps(self, result):
        out = PolicyEngine("STRICT").apply([STRUCTURAL, HONEYPOT, result], self._risk())
        assert out['partial'] is False
        assert out['policy_override'] is None
        assert out['rug_probability'] == 25
