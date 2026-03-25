"""Tests for the agent threshold-based policy engine."""

import pytest
from agent.policy_engine import AgentPolicyEngine, PolicyVerdict


@pytest.fixture
def engine():
    return AgentPolicyEngine()


@pytest.fixture
def default_policy():
    return {
        "mode": "threshold",
        "auto_allow_below": 25,
        "auto_block_above": 70,
        "max_spend_per_tx_usd": 500,
        "max_spend_daily_usd": 5000,
        "max_slippage": 0.05,
        "always_allow": ["0x10ed43c718714eb63d5aa57b78b54704e256024e"],
        "always_block": ["0xscammer"],
        "active_hours": "00:00-23:59",
        "timeout_action": "block",
        "fail_mode": "cached_then_block",
    }


def test_auto_allow_below_threshold(engine, default_policy):
    """Score below auto_allow → ALLOW, all checks pass."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=12,
        target_address="0xsometoken",
        tx_value_usd=100,
        daily_spend_usd=0,
        simulated_slippage=0.01,
    )
    assert result.verdict == "ALLOW"
    assert result.all_passed is True


def test_auto_block_above_threshold(engine, default_policy):
    """Score above auto_block → BLOCK."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=85,
        target_address="0xsometoken",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    assert result.verdict == "BLOCK"
    assert "risk_threshold" in result.failed_checks


def test_middle_range_asks_owner(engine, default_policy):
    """Score in middle range → WARN (ask owner)."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=45,
        target_address="0xsometoken",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    assert result.verdict == "WARN"
    assert result.needs_owner_approval is True


def test_always_allow_overrides(engine, default_policy):
    """Address in always_allow passes regardless of score."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=90,
        target_address="0x10ed43c718714eb63d5aa57b78b54704e256024e",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    assert result.verdict == "ALLOW"
    assert "allowlist" in result.checks["contract_list"]


def test_always_block_overrides(engine, default_policy):
    """Address in always_block blocks regardless of score."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=5,
        target_address="0xscammer",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    assert result.verdict == "BLOCK"
    assert "blocklist" in result.checks["contract_list"]


def test_spending_limit_exceeded(engine, default_policy):
    """Tx value exceeding per-tx limit → BLOCK."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=10,
        target_address="0xsafe",
        tx_value_usd=600,
        daily_spend_usd=0,
    )
    assert result.verdict == "BLOCK"
    assert "spending_limit" in result.failed_checks


def test_daily_spend_exceeded(engine, default_policy):
    """Daily spend exceeded → BLOCK."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=10,
        target_address="0xsafe",
        tx_value_usd=100,
        daily_spend_usd=4950,
    )
    assert result.verdict == "BLOCK"
    assert "daily_limit" in result.failed_checks


def test_slippage_exceeded(engine, default_policy):
    """Simulated slippage over max → BLOCK."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=10,
        target_address="0xsafe",
        tx_value_usd=100,
        daily_spend_usd=0,
        simulated_slippage=0.12,
    )
    assert result.verdict == "BLOCK"
    assert "slippage_cap" in result.failed_checks


def test_empty_policy_defaults(engine):
    """Empty policy uses safe defaults."""
    result = engine.evaluate(
        policy={},
        risk_score=50,
        target_address="0xsafe",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    # Default thresholds: allow < 25, block > 70, so 50 = WARN
    assert result.verdict == "WARN"


def test_boundary_exact_allow_threshold(engine, default_policy):
    """Score exactly at auto_allow_below (25) falls to WARN (exclusive boundary)."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=25,
        target_address="0xsafe",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    assert result.verdict == "WARN"
    assert result.needs_owner_approval is True


def test_boundary_exact_block_threshold(engine, default_policy):
    """Score exactly at auto_block_above (70) falls to WARN (exclusive boundary)."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=70,
        target_address="0xsafe",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    assert result.verdict == "WARN"
    assert result.needs_owner_approval is True
