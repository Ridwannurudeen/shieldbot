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
