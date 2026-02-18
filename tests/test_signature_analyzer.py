"""Tests for SignaturePermitAnalyzer."""

import time
import pytest
from core.analyzer import AnalysisContext
from analyzers.signature import SignaturePermitAnalyzer


@pytest.fixture
def analyzer():
    return SignaturePermitAnalyzer()


@pytest.mark.asyncio
async def test_max_uint_permit_to_unknown(analyzer):
    """MAX_UINT permit to unknown spender should score high."""
    typed_data = {
        "primaryType": "Permit",
        "domain": {"name": "TestToken", "version": "1"},
        "message": {
            "owner": "0x" + "a" * 40,
            "spender": "0x" + "b" * 40,
            "value": str((1 << 256) - 1),
            "nonce": "0",
            "deadline": str(int(time.time()) + 365 * 2 * 86400),
        },
    }
    ctx = AnalysisContext(
        address="0x" + "a" * 40,
        chain_id=1,
        extra={'typed_data': typed_data, 'sign_method': 'eth_signTypedData_v4'},
    )
    result = await analyzer.analyze(ctx)
    assert result.score >= 50
    assert any('unlimited' in f.lower() for f in result.flags)
    assert any('unknown spender' in f.lower() for f in result.flags)


@pytest.mark.asyncio
async def test_permit2_to_uniswap_safe(analyzer):
    """Permit2 to Uniswap Universal Router should be lower risk."""
    typed_data = {
        "primaryType": "PermitSingle",
        "domain": {"name": "Permit2"},
        "message": {
            "details": {
                "token": "0x" + "c" * 40,
                "amount": "1000000000",
                "expiration": str(int(time.time()) + 3600),
                "nonce": "0",
            },
            "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            "sigDeadline": str(int(time.time()) + 3600),
        },
    }
    ctx = AnalysisContext(
        address="0x" + "a" * 40,
        chain_id=1,
        extra={'typed_data': typed_data, 'sign_method': 'eth_signTypedData_v4'},
    )
    result = await analyzer.analyze(ctx)
    # Known spender, reasonable amount — should be low
    assert result.score < 30


@pytest.mark.asyncio
async def test_no_typed_data_score_zero(analyzer):
    """No typed data should produce score 0."""
    ctx = AnalysisContext(
        address="0x" + "a" * 40,
        chain_id=1,
        extra={},
    )
    result = await analyzer.analyze(ctx)
    assert result.score == 0
    assert result.data['has_typed_data'] is False


@pytest.mark.asyncio
async def test_seaport_zero_price(analyzer):
    """Seaport order with zero consideration should flag as phishing."""
    typed_data = {
        "primaryType": "OrderComponents",
        "domain": {"name": "Seaport"},
        "message": {
            "offer": [
                {"itemType": 2, "token": "0x" + "d" * 40, "identifierOrCriteria": "1",
                 "startAmount": "1", "endAmount": "1"},
            ],
            "consideration": [],
            "orderType": 0,
        },
    }
    ctx = AnalysisContext(
        address="0x" + "a" * 40,
        chain_id=1,
        extra={'typed_data': typed_data, 'sign_method': 'eth_signTypedData_v4'},
    )
    result = await analyzer.analyze(ctx)
    assert result.score >= 40
    assert any('zero-price' in f.lower() for f in result.flags)


@pytest.mark.asyncio
async def test_personal_sign_benign(analyzer):
    """personal_sign should be benign (login signature)."""
    ctx = AnalysisContext(
        address="0x" + "a" * 40,
        chain_id=1,
        extra={'sign_method': 'personal_sign'},
    )
    result = await analyzer.analyze(ctx)
    assert result.score == 0
