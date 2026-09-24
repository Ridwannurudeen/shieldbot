"""Tests for IntentMismatchAnalyzer."""

import pytest
from core.analyzer import AnalysisContext
from analyzers.intent import IntentMismatchAnalyzer
from utils.web3_client import Web3Client


@pytest.fixture
def analyzer():
    return IntentMismatchAnalyzer(Web3Client())


@pytest.mark.asyncio
async def test_safe_swap(analyzer):
    """A normal swap to PancakeSwap should produce low score."""
    # swapExactETHForTokens selector
    calldata = "0x7ff36ab5" + "0" * 256
    ctx = AnalysisContext(
        address="0x10ED43C718714eb63d5aA57B78B54704E256024E",
        chain_id=56,
        extra={'calldata': calldata, 'value': '0x2386F26FC10000'},
    )
    result = await analyzer.analyze(ctx)
    assert result.score < 30
    assert result.name == "intent"


@pytest.mark.asyncio
async def test_unlimited_approval_to_unverified(analyzer):
    """Unlimited approval to a non-whitelisted address should flag."""
    # approve(address,uint256) with max uint
    spender = "0000000000000000000000003ee505ba316879d246760e89f0a29a4403afa498"
    amount = "f" * 64  # max uint256
    calldata = "0x095ea7b3" + spender + amount
    ctx = AnalysisContext(
        address="0x" + "a" * 40,
        chain_id=56,
        extra={'calldata': calldata, 'value': '0'},
    )
    result = await analyzer.analyze(ctx)
    assert result.score >= 35
    assert any('Unlimited approval' in f for f in result.flags)
    assert result.data['is_unlimited']


@pytest.mark.asyncio
async def test_value_with_approval_mismatch(analyzer):
    """Sending native value on an approval call is suspicious."""
    # approve(address,uint256) with small amount + native value
    spender = "0000000000000000000000003ee505ba316879d246760e89f0a29a4403afa498"
    amount = "0" * 60 + "0100"  # small amount
    calldata = "0x095ea7b3" + spender + amount
    ctx = AnalysisContext(
        address="0x" + "a" * 40,
        chain_id=56,
        extra={'calldata': calldata, 'value': '0x2386F26FC10000'},
    )
    result = await analyzer.analyze(ctx)
    assert result.score >= 30
    assert any('Native value' in f for f in result.flags)


@pytest.mark.asyncio
async def test_missing_calldata_graceful(analyzer):
    """Missing calldata should not crash — score 0."""
    ctx = AnalysisContext(
        address="0x" + "a" * 40,
        chain_id=56,
        extra={},
    )
    result = await analyzer.analyze(ctx)
    assert result.score == 0
    assert result.data.get('intent') == 'native_transfer'


@pytest.mark.asyncio
async def test_unknown_selector_flagged(analyzer):
    """Unknown selector on a confirmed unverified token gets a moderate score."""
    calldata = "0xdeadbeef" + "0" * 128
    ctx = AnalysisContext(
        address="0x" + "b" * 40,
        chain_id=56,
        extra={'calldata': calldata, 'value': '0', 'is_verified': False},
    )
    result = await analyzer.analyze(ctx)
    assert result.score >= 20
    assert any('Unknown function selector' in f for f in result.flags)


@pytest.mark.asyncio
@pytest.mark.parametrize('verified', [None, True, False])
async def test_unknown_selector_tristate_reaches_risk(analyzer, verified):
    from core.risk_engine import RiskEngine

    result = await analyzer.analyze(AnalysisContext(
        address='0x' + 'b' * 40,
        extra={'calldata': '0xdeadbeef', 'is_verified': verified},
    ))
    assert result.score == (20 if verified is False else 0)
    assert bool(result.flags) is (verified is not True)
    assert result.data['status'] == ('unknown' if verified is None else 'ok')
    result.weight = 1
    risk = RiskEngine().compute_from_results([result], is_token=False)
    assert risk['coverage']['intent'] == (0 if verified is None else 1)
    assert risk['status'] == ('unknown' if verified is None else 'ok')
    if verified is None:
        assert risk['risk_level'] == 'MEDIUM'
        assert risk['coverage_reasons']['intent']
        assert risk['risk_archetype'] == 'unknown'
