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


class TestPolicyIncompleteCoverage:
    # Providers swallow failures into unknown results: no error, coverage below 1.
    RESULTS = [_make_result("structural", score=0), _make_result("honeypot", score=0)]

    def _risk(self, coverage):
        return {'rug_probability': 25, 'risk_level': 'MEDIUM', 'critical_flags': [], 'coverage': coverage}

    def test_strict_blocks_on_incomplete_coverage(self):
        out = PolicyEngine("STRICT").apply(self.RESULTS, self._risk({'structural': 1, 'honeypot': 0.5}))
        assert out['partial'] is True
        assert out['failed_sources'] == ['honeypot']
        assert out['policy_override'] == 'BLOCK_RECOMMENDED'
        assert out['risk_level'] == 'HIGH'
        assert out['rug_probability'] == 80
        assert out['critical_flags'][0] == (
            "Policy override: 1 analyzer(s) unavailable or incomplete (honeypot)"
        )

    def test_balanced_warns_on_incomplete_coverage(self):
        out = PolicyEngine("BALANCED").apply(self.RESULTS, self._risk({'structural': 1, 'honeypot': 0.5}))
        assert out['partial'] is True
        assert out['failed_sources'] == ['honeypot']
        assert out['policy_override'] is None
        assert out['rug_probability'] == 25
        assert out['risk_level'] == 'MEDIUM'
        assert out['critical_flags'] == ["Partial analysis: honeypot unavailable or incomplete"]

    def test_skipped_analyzers_are_covered_not_failed(self):
        out = PolicyEngine("STRICT").apply(self.RESULTS, self._risk({'structural': 1, 'honeypot': 1}))
        assert out['partial'] is False
        assert out['policy_override'] is None

    def test_errored_analyzer_is_named_once(self):
        results = [_make_result("structural", score=0), _make_result("honeypot", error="timeout")]
        out = PolicyEngine("STRICT").apply(results, self._risk({'structural': 0.5, 'honeypot': 0}))
        assert out['failed_sources'] == ['honeypot', 'structural']
