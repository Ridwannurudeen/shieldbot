"""Tests for utils/risk_scorer.py — scoring logic, blending, confidence."""

import pytest
from utils.risk_scorer import (
    calculate_risk_score,
    blend_scores,
    compute_confidence,
    score_level_from_int,
)


# --- calculate_risk_score ---

class TestCalculateRiskScore:
    def test_empty_findings_returns_zero(self):
        score, level, _ = calculate_risk_score([])
        assert score == 0
        assert level == "LOW"

    def test_single_critical_finding(self):
        findings = [{"severity": "critical", "message": "Scam DB match"}]
        score, level, _ = calculate_risk_score(findings)
        assert score == 40
        assert level == "MEDIUM"

    def test_multiple_criticals_cap_at_100(self):
        findings = [{"severity": "critical", "message": f"issue {i}"} for i in range(5)]
        score, _, _ = calculate_risk_score(findings)
        assert score == 100

    def test_high_severity(self):
        findings = [{"severity": "high", "message": "Unverified"}]
        score, _, _ = calculate_risk_score(findings)
        assert score == 25

    def test_medium_severity(self):
        findings = [{"severity": "medium", "message": "Ownership not renounced"}]
        score, _, _ = calculate_risk_score(findings)
        assert score == 15

    def test_info_severity_is_zero_weight(self):
        findings = [{"severity": "info", "message": "Standard transfer"}]
        score, _, _ = calculate_risk_score(findings)
        assert score == 0

    def test_mixed_severities(self):
        findings = [
            {"severity": "critical", "message": "Honeypot"},
            {"severity": "high", "message": "Unverified"},
            {"severity": "medium", "message": "New contract"},
            {"severity": "info", "message": "Transfer function"},
        ]
        score, _, _ = calculate_risk_score(findings)
        # 40 + 25 + 15 + 0 = 80
        assert score == 80
        assert score >= 71  # HIGH threshold

    def test_high_threshold_boundary(self):
        # 71 should be HIGH
        findings = [
            {"severity": "critical", "message": "a"},
            {"severity": "high", "message": "b"},
            {"severity": "low", "message": "c"},
            {"severity": "low", "message": "d"},
        ]
        score, level, _ = calculate_risk_score(findings)
        # 40 + 25 + 5 + 5 = 75
        assert level == "HIGH"

    def test_medium_threshold_boundary(self):
        # 31 should be MEDIUM
        findings = [
            {"severity": "high", "message": "a"},
            {"severity": "low", "message": "b"},
            {"severity": "low", "message": "c"},
        ]
        score, level, _ = calculate_risk_score(findings)
        # 25 + 5 + 5 = 35
        assert level == "MEDIUM"


# --- blend_scores ---

class TestBlendScores:
    def test_none_ai_returns_heuristic_only(self):
        assert blend_scores(50, None) == 50

    def test_with_valid_ai_score(self):
        # 60% * 50 + 40% * 80 = 30 + 32 = 62
        assert blend_scores(50, 80) == 62

    def test_both_zero(self):
        assert blend_scores(0, 0) == 0

    def test_both_max(self):
        assert blend_scores(100, 100) == 100

    def test_clamps_to_0_100(self):
        result = blend_scores(0, 0)
        assert 0 <= result <= 100

    def test_ai_lower_reduces_score(self):
        # 60% * 80 + 40% * 20 = 48 + 8 = 56
        assert blend_scores(80, 20) == 56


# --- compute_confidence ---

class TestComputeConfidence:
    def test_empty_sources(self):
        assert compute_confidence({}) == 0

    def test_all_sources_responded(self):
        sources = {
            "bscscan": True,
            "bytecode": True,
            "scam_db": True,
            "honeypot_api": True,
            "contract_age": True,
            "ai": True,
            "source_code": True,
        }
        assert compute_confidence(sources) == 100

    def test_no_sources_responded(self):
        sources = {
            "bscscan": False,
            "bytecode": False,
            "scam_db": False,
        }
        assert compute_confidence(sources) == 0

    def test_partial_sources(self):
        sources = {
            "bscscan": True,
            "bytecode": True,
            "scam_db": False,
            "ai": False,
        }
        # bscscan(20) + bytecode(15) responded, scam_db(15) + ai(15) didn't
        # achieved=35, total=65
        result = compute_confidence(sources)
        assert 50 <= result <= 60  # ~53.8


# --- score_level_from_int ---

class TestScoreLevelFromInt:
    def test_low_at_30(self):
        assert score_level_from_int(30) == "LOW"

    def test_medium_at_31(self):
        assert score_level_from_int(31) == "MEDIUM"

    def test_medium_at_70(self):
        assert score_level_from_int(70) == "MEDIUM"

    def test_high_at_71(self):
        assert score_level_from_int(71) == "HIGH"

    def test_high_at_100(self):
        assert score_level_from_int(100) == "HIGH"

    def test_low_at_0(self):
        assert score_level_from_int(0) == "LOW"
