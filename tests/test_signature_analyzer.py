"""Tests for SignaturePermitAnalyzer."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from core.analyzer import AnalysisContext
from analyzers.signature import SignaturePermitAnalyzer
from services.counterparty_service import PERMIT2

UNIVERSAL_ROUTER = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"
SPENDER = "0x" + "5" * 40
MAX = str((1 << 256) - 1)


def _facts(**overrides):
    return {
        "address": SPENDER, "allowlisted": None, "is_contract": True, "delegated": False,
        "is_verified": True, "age_days": 400, "labels": [], "label_source": "",
        "coverage": {"code": True, "verification": True, "age": True, "labels": True},
        "reason": None, "observed_at": 0, **overrides,
    }


def _service(facts=None):
    """A counterparty service whose chain adapter lists the Universal Router."""
    def allowlisted_name(address, chain_id):
        lower = address.lower()
        if lower == UNIVERSAL_ROUTER.lower():
            return "Uniswap Universal Router"
        return "Permit2" if lower == PERMIT2 else None
    return SimpleNamespace(allowlisted_name=allowlisted_name, fetch=AsyncMock(return_value=facts))


def _typed(primary_type, message):
    return {"primaryType": primary_type, "domain": {"name": "Permit2"}, "message": message}


async def _analyze(analyzer, typed_data, chain_id=1):
    return await analyzer.analyze(AnalysisContext(
        address="0x" + "a" * 40, chain_id=chain_id,
        extra={"typed_data": typed_data, "sign_method": "eth_signTypedData_v4"},
    ))


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
async def test_permit2_to_uniswap_safe():
    """Permit2 to Uniswap Universal Router should be lower risk."""
    service = _service()
    analyzer = SignaturePermitAnalyzer(service)
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
    # The chain adapter lists the Universal Router, so there is nothing to look up or add.
    assert result.score == 0
    service.fetch.assert_not_awaited()


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


@pytest.mark.asyncio
async def test_signature_propagates_unsupported_chain(analyzer, monkeypatch):
    from unittest.mock import MagicMock
    from utils.web3_client import UnsupportedChainError

    failure = UnsupportedChainError('unsupported chain')
    monkeypatch.setattr(analyzer, '_check_permit', MagicMock(side_effect=failure))
    with pytest.raises(UnsupportedChainError) as raised:
        await analyzer.analyze(AnalysisContext(
            address='0x' + 'a' * 40,
            extra={'typed_data': {'primaryType': 'Permit'}},
        ))
    assert raised.value is failure


BATCH_TO_WALLET = _typed("PermitBatchTransferFrom", {
    "permitted": [{"token": "0x" + c * 40, "amount": MAX} for c in "cde"],
    "spender": SPENDER, "nonce": "0", "deadline": str(int(time.time()) + 1800),
})


@pytest.mark.asyncio
async def test_signature_transfer_batch_to_a_wallet_is_blocked():
    service = _service(_facts(is_contract=False, is_verified=None, age_days=None))
    result = await _analyze(SignaturePermitAnalyzer(service), BATCH_TO_WALLET)
    assert result.score == 100
    assert result.data["floor"] == 100
    assert result.data["sig_type"] == "permit2_transfer"
    assert result.data["status"] == "ok"
    assert result.flags[0] == "Approval to a wallet address, not a contract (drainer pattern)"
    service.fetch.assert_awaited_once_with(SPENDER, 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("primary_type", ["PermitTransferFrom", "PermitWitnessTransferFrom"])
async def test_signature_transfer_to_a_verified_protocol_is_caution(primary_type):
    typed = _typed(primary_type, {
        "permitted": {"token": "0x" + "c" * 40, "amount": "1000"},
        "spender": SPENDER, "nonce": "0", "deadline": str(int(time.time()) + 1800),
        **({"witness": {"orderHash": "0x" + "0" * 64}} if "Witness" in primary_type else {}),
    })
    result = await _analyze(SignaturePermitAnalyzer(_service(_facts())), typed)
    # A pull right to a verified, old contract outside the allowlist: the SignatureTransfer base.
    assert result.score == 30
    assert "floor" not in result.data
    assert result.data["status"] == "ok"
    assert result.flags == [f"Permit: spender {SPENDER[:10]}... is not a known protocol (verified contract)"]


@pytest.mark.asyncio
@pytest.mark.parametrize("value, expected", [(MAX, 40), ("1000", 10)])
async def test_eip2612_permit_to_a_verified_protocol(value, expected):
    typed = {"primaryType": "Permit", "domain": {"name": "Token"}, "message": {
        "spender": SPENDER, "value": value, "deadline": str(int(time.time()) + 1800),
    }}
    result = await _analyze(SignaturePermitAnalyzer(_service(_facts())), typed)
    assert result.score == expected


@pytest.mark.asyncio
async def test_unlimited_eip2612_permit_to_an_unverified_contract_is_blocked():
    typed = {"primaryType": "Permit", "domain": {"name": "Token"}, "message": {
        "spender": SPENDER, "value": MAX, "deadline": str(int(time.time()) + 1800),
    }}
    result = await _analyze(SignaturePermitAnalyzer(_service(_facts(is_verified=False))), typed)
    assert result.score == 85
    assert result.data["floor"] == 85
    assert result.flags[0] == "Spender contract is unverified"


@pytest.mark.asyncio
async def test_dai_permit_with_allowed_true_is_unlimited():
    # DAI's permit has no amount: allowed true grants the spender everything.
    typed = {'primaryType': 'Permit', 'domain': {'name': 'Dai Stablecoin'}, 'message': {
        'holder': '0x' + 'a' * 40, 'spender': SPENDER, 'nonce': '0', 'expiry': '0', 'allowed': True,
    }}
    result = await _analyze(SignaturePermitAnalyzer(_service(_facts(is_verified=False, age_days=90))), typed)
    assert result.data['floor'] == 85
    assert 'Permit: unlimited token approval' in result.flags


@pytest.mark.asyncio
@pytest.mark.parametrize('message', [
    {'holder': '0x' + 'a' * 40, 'spender': SPENDER, 'nonce': '0', 'expiry': '0', 'allowed': False},
    {'owner': '0x' + 'a' * 40, 'spender': SPENDER, 'value': '0', 'nonce': '0', 'deadline': '1'},
    {'owner': '0x' + 'a' * 40, 'spender': SPENDER, 'value': '0x0', 'nonce': '0', 'deadline': '1'},
    {'owner': '0x' + 'a' * 40, 'spender': SPENDER, 'value': 0, 'nonce': '0', 'deadline': '1'},
], ids=['dai-allowed-false', 'eip2612-zero-value', 'eip2612-hex-zero', 'eip2612-int-zero'])
async def test_a_revoke_permit_judges_no_spender(message):
    service = _service(_facts(is_contract=False, is_verified=None, age_days=None))
    result = await _analyze(SignaturePermitAnalyzer(service), {'primaryType': 'Permit', 'domain': {}, 'message': message})
    service.fetch.assert_not_awaited()
    assert result.score == 0
    assert 'floor' not in result.data
    assert result.data.get('status', 'ok') == 'ok'


UNREADABLE = 'Permit: amount could not be read; treated as unlimited'


@pytest.mark.asyncio
@pytest.mark.parametrize('field, value, flag', [
    # A JSON 1e30 arrives as a float; none of these is a readable non-negative integer.
    ('value', 1e30, UNREADABLE),
    ('value', {'hex': '0x' + 'f' * 64}, UNREADABLE),
    ('value', '-5', UNREADABLE),
    ('value', '1.5', UNREADABLE),
    ('value', '1e30', UNREADABLE),
    ('value', True, UNREADABLE),
    # Only allowed False revokes a DAI-style permit; anything else grants everything.
    ('allowed', 'false', 'Permit: unlimited token approval'),
    ('allowed', None, 'Permit: unlimited token approval'),
], ids=['float', 'object', 'negative', 'fraction', 'exponent', 'bool', 'dai-string-false', 'dai-null'])
async def test_an_unreadable_permit_amount_is_the_largest_grant(field, value, flag):
    message = {'owner': '0x' + 'a' * 40, 'spender': SPENDER, 'nonce': '0', 'deadline': '1', field: value}
    service = _service(_facts(is_verified=False, age_days=90))
    result = await _analyze(SignaturePermitAnalyzer(service), {'primaryType': 'Permit', 'domain': {}, 'message': message})
    service.fetch.assert_awaited_once()
    # Unverified spender, unlimited grant: 85, not the SAFE of a revoke.
    assert result.data['floor'] == 85
    assert result.score == 85
    assert flag in result.flags


@pytest.mark.asyncio
@pytest.mark.parametrize('amount', [1e30, '-1', 'lots'], ids=['float', 'negative', 'text'])
async def test_an_unreadable_signature_transfer_amount_is_unlimited(amount):
    typed = _typed('PermitTransferFrom', {
        'permitted': {'token': '0x' + 'c' * 40, 'amount': amount},
        'spender': SPENDER, 'nonce': '0', 'deadline': str(int(time.time()) + 1800),
    })
    result = await _analyze(SignaturePermitAnalyzer(_service(_facts(is_verified=False, age_days=90))), typed)
    assert result.data['floor'] == 85
    assert 'Permit2 transfer: amount could not be read; treated as unlimited' in result.flags


def _single(amount):
    return _typed('PermitSingle', {
        'details': {'token': '0x' + 'c' * 40, 'amount': amount, 'expiration': '0', 'nonce': '0'},
        'spender': SPENDER, 'sigDeadline': '0',
    })


def _batch(*amounts):
    return _typed('PermitBatch', {
        'details': [{'token': '0x' + 'c' * 40, 'amount': a, 'expiration': '0', 'nonce': '0'} for a in amounts],
        'spender': SPENDER, 'sigDeadline': '0',
    })


@pytest.mark.asyncio
@pytest.mark.parametrize('typed', [_single('0'), _single(0), _single('0x0'), _batch('0', 0, '0x00')],
                         ids=['single-zero', 'single-int-zero', 'single-hex-zero', 'batch-all-zero'])
async def test_a_permit2_allowance_revoke_judges_no_spender(typed):
    service = _service(_facts(is_contract=False, is_verified=None, age_days=None))
    result = await _analyze(SignaturePermitAnalyzer(service), typed)
    service.fetch.assert_not_awaited()
    assert 'floor' not in result.data
    assert result.score == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('typed, floor, flag', [
    (_single('1000'), 60, None),
    (_single(1e30), 85, 'Permit2: amount could not be read; treated as unlimited'),
    (_single('-1'), 85, 'Permit2: amount could not be read; treated as unlimited'),
    (_batch('0', '1000'), 60, None),
    (_batch('0', 1.5), 85, 'Permit2 Batch: amount for token #2 could not be read; treated as unlimited'),
], ids=['single-limited', 'single-float', 'single-negative', 'batch-one-grant', 'batch-unreadable'])
async def test_a_permit2_allowance_grant_judges_the_spender(typed, floor, flag):
    service = _service(_facts(is_verified=False, age_days=90))
    result = await _analyze(SignaturePermitAnalyzer(service), typed)
    service.fetch.assert_awaited_once()
    assert result.data['floor'] == floor
    if flag:
        assert flag in result.flags


@pytest.mark.asyncio
async def test_unknown_spender_facts_are_unknown_not_clean():
    typed = _typed("PermitSingle", {
        "details": {"token": "0x" + "c" * 40, "amount": "1000", "expiration": "0", "nonce": "0"},
        "spender": SPENDER, "sigDeadline": "0",
    })
    unknown = _facts(is_contract=None, labels=None, reason="Spender facts unknown: code (RPC), labels (GoPlus HTTP 429)",
                     coverage={"code": False, "verification": True, "age": True, "labels": False})
    result = await _analyze(SignaturePermitAnalyzer(_service(unknown)), typed)
    assert result.score == 25
    assert result.flags == [f"Permit: approval to unknown spender {SPENDER[:10]}..."]
    assert result.data["status"] == "unknown"
    assert result.data["coverage"] == {"counterparty": False}
    assert result.data["reason"] == unknown["reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [8453, 42161])
async def test_chain_adapter_router_is_allowlisted(chain_id):
    from adapters.arbitrum import ArbitrumAdapter
    from adapters.base_chain import BaseChainAdapter
    from services.counterparty_service import CounterpartyService
    from utils.web3_client import Web3Client

    client = Web3Client()
    client.register_adapter(BaseChainAdapter())
    client.register_adapter(ArbitrumAdapter())
    typed = _typed("PermitSingle", {
        "details": {"token": "0x" + "c" * 40, "amount": MAX, "expiration": "0", "nonce": "0"},
        "spender": UNIVERSAL_ROUTER, "sigDeadline": "0",
    })
    result = await _analyze(SignaturePermitAnalyzer(CounterpartyService(client, None)), typed, chain_id)
    # Only the unlimited amount counts: no lookup, no spender points.
    assert result.score == 25
    assert "status" not in result.data
