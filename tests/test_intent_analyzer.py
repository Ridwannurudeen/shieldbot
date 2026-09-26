"""Tests for IntentMismatchAnalyzer."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from eth_utils import keccak
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
    # A bare analyzer has no counterparty lookup: the spender is unknown, never clean.
    assert result.data['status'] == 'unknown'
    assert result.data['coverage']['counterparty'] is False
    assert 'floor' not in result.data


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
    assert result.data['status'] == 'unknown'
    assert result.data['coverage']['counterparty'] is False


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


TOKEN = '0x' + 'a' * 40
SPENDER = '0x' + '5' * 40
OWNER = '0x' + 'b' * 40
ROUTER = '0x10ed43c718714eb63d5aa57b78b54704e256024e'
MAX = 2 ** 256 - 1


def _word(value):
    if isinstance(value, bool):
        value = int(value)
    return format(value, '064x') if isinstance(value, int) else value[2:].rjust(64, '0')


def _call(selector, *args):
    return '0x' + selector + ''.join(_word(arg) for arg in args)


def _facts(**overrides):
    return {
        'address': SPENDER, 'allowlisted': None, 'is_contract': True, 'delegated': False,
        'is_verified': True, 'age_days': 400, 'labels': [], 'label_source': '',
        'coverage': {'code': True, 'verification': True, 'age': True, 'labels': True},
        'reason': None, 'observed_at': 0, **overrides,
    }


def _service(facts=None):
    return SimpleNamespace(
        allowlisted_name=lambda address, chain_id: 'PancakeSwap V2 Router' if address.lower() == ROUTER else None,
        fetch=AsyncMock(return_value=facts or _facts()),
    )


async def _intent(calldata, facts=None, value='0', **extra):
    service = _service(facts)
    result = await IntentMismatchAnalyzer(Web3Client(), service).analyze(AnalysisContext(
        address=TOKEN, chain_id=56, from_address=OWNER,
        extra={'calldata': calldata, 'value': value, **extra},
    ))
    return result, service


WALLET = 'Approval to a wallet address, not a contract (drainer pattern)'
UNLIMITED = _call('095ea7b3', SPENDER, MAX)
LIMITED = _call('095ea7b3', SPENDER, 1000)


@pytest.mark.asyncio
@pytest.mark.parametrize('calldata, facts, floor, flag', [
    (UNLIMITED, _facts(is_contract=False, is_verified=None, age_days=None), 100, WALLET),
    (LIMITED, _facts(is_contract=False, is_verified=None, age_days=None), 100, WALLET),
    (LIMITED, _facts(delegated=True, is_verified=None, age_days=None), 100,
     'Approval to an EIP-7702 delegated wallet, not a protocol contract'),
    (LIMITED, _facts(labels=['stealing_attack'], label_source='GoPlus'), 100,
     'Spender flagged by GoPlus: stealing_attack (GoPlus)'),
    (LIMITED, _facts(is_verified=False, age_days=2), 85, 'Spender contract is unverified and 2 days old'),
    (UNLIMITED, _facts(is_verified=False, age_days=90), 85, 'Spender contract is unverified'),
    (LIMITED, _facts(is_verified=False, age_days=90), 60, 'Spender contract is unverified'),
    (UNLIMITED, _facts(age_days=3), 60, 'Spender contract is 3 days old'),
    (LIMITED, _facts(age_days=3), None, None),
    (UNLIMITED, _facts(), None, None),
    (_call('39509351', SPENDER, 5), _facts(is_contract=False), 100, WALLET),
    (_call('a22cb465', SPENDER, True), _facts(is_verified=False, age_days=90), 85, 'Spender contract is unverified'),
], ids=['eoa-unlimited', 'eoa-limited', 'delegated', 'labelled', 'unverified-new', 'unverified-unlimited',
        'unverified-limited', 'verified-new-unlimited', 'verified-new-limited', 'verified-old',
        'increase-allowance', 'approval-for-all'])
async def test_grant_floors(calldata, facts, floor, flag):
    result, service = await _intent(calldata, facts)
    service.fetch.assert_awaited_once_with(SPENDER, 56)
    assert result.data.get('floor') == floor
    assert result.data['status'] == 'ok'
    assert result.data['coverage'] == {'selector_verification': True, 'counterparty': True}
    assert result.data['counterparty'] is service.fetch.return_value
    if flag:
        assert result.flags[0] == flag


@pytest.mark.asyncio
async def test_wallet_grant_blocks_through_the_engine():
    from core.analyzer import AnalyzerResult
    from core.risk_engine import RiskEngine

    intent, _ = await _intent(UNLIMITED, _facts(is_contract=False, is_verified=None, age_days=None))
    intent.weight = 0.12
    structural = AnalyzerResult('structural', 0.88, 0, flags=['Proxy/upgradeable contract'], data={
        'is_contract': True, 'is_verified': True, 'contract_age_days': 900,
    })
    risk = RiskEngine().compute_from_results([structural, intent], is_token=False)
    assert (risk['rug_probability'], risk['risk_level'], risk['transaction_floor']) == (100, 'HIGH', 100)
    assert risk['critical_flags'][0] == WALLET


@pytest.mark.asyncio
@pytest.mark.parametrize('calldata', [
    _call('095ea7b3', SPENDER, 0),
    _call('a22cb465', SPENDER, False),
    _call('8fcbaf0c', OWNER, SPENDER, 0, 0, False, 27, 0, 0),
    _call('095ea7b3', ROUTER, MAX),
    _call('2b67b570', OWNER) + '0' * 512,
    _call('2a2d80d1', OWNER) + '0' * 512,
    _call('30f28b7a', OWNER) + '0' * 512,
    '0xedd9444b' + '0' * 512,
], ids=['revoke', 'revoke-approval-for-all', 'dai-revoke', 'allowlisted', 'permit2-permit',
        'permit2-permit-batch', 'permit2-transfer', 'permit2-transfer-batch'])
async def test_no_lookup_and_no_floor(calldata):
    result, service = await _intent(calldata)
    service.fetch.assert_not_awaited()
    assert 'floor' not in result.data
    assert 'counterparty' not in result.data['coverage']


@pytest.mark.asyncio
@pytest.mark.parametrize('calldata, floor', [
    (_call('d505accf', OWNER, SPENDER, 1000, 1, 27, 0, 0), 60),
    (_call('d505accf', OWNER, SPENDER, MAX, 1, 27, 0, 0), 85),
    # A DAI permit is all or nothing, so allowed=true is an unlimited grant.
    (_call('8fcbaf0c', OWNER, SPENDER, 0, 0, True, 27, 0, 0), 85),
], ids=['permit-limited', 'permit-unlimited', 'dai-permit'])
async def test_permit_calldata_judges_the_spender_not_the_owner(calldata, floor):
    result, service = await _intent(calldata, _facts(is_verified=False, age_days=90))
    service.fetch.assert_awaited_once_with(SPENDER, 56)
    assert result.data['floor'] == floor


@pytest.mark.asyncio
async def test_unknown_spender_code_is_unknown_without_a_floor():
    from core.analyzer import AnalyzerResult
    from core.risk_engine import RiskEngine

    reason = 'Spender facts unknown: code (RPC)'
    result, _ = await _intent(UNLIMITED, _facts(is_contract=None, reason=reason))
    assert 'floor' not in result.data
    assert result.data['status'] == 'unknown'
    assert result.data['coverage'] == {'selector_verification': True, 'counterparty': False}
    assert result.data['reason'] == reason
    assert result.flags[-1] == reason
    result.weight = 1
    risk = RiskEngine().compute_from_results([result], is_token=False)
    assert risk['coverage']['intent'] == 0.5
    assert risk['status'] == 'unknown'
    assert risk['risk_level'] == 'MEDIUM'


@pytest.mark.asyncio
async def test_labelled_spender_with_unknown_code_still_floors():
    result, _ = await _intent(LIMITED, _facts(
        is_contract=None, labels=['phishing_activities'], reason='Spender facts unknown: code (RPC)',
    ))
    assert result.data['floor'] == 100
    assert result.data['status'] == 'unknown'
    assert result.flags[0] == 'Spender flagged by GoPlus: phishing_activities'


CLAIM = '0x4e71d92d'


@pytest.mark.asyncio
@pytest.mark.parametrize('is_verified, floor, target, status', [
    (False, 85, 'an unverified contract', 'ok'),
    (True, 60, 'the contract', 'ok'),
    (None, 60, 'a contract of unknown verification', 'unknown'),
])
async def test_claim_with_native_value_floors(is_verified, floor, target, status):
    result, service = await _intent(CLAIM, value=hex(10 ** 17), is_verified=is_verified)
    service.fetch.assert_not_awaited()
    assert result.data['floor'] == floor
    assert result.data['status'] == status
    assert result.data['coverage']['counterparty'] is (status == 'ok')
    assert result.flags[0] == f'claim() sends 0.1 native value to {target}'


@pytest.mark.asyncio
@pytest.mark.parametrize('calldata, flag', [
    (_call('095ea7b3', '0x000000000022D473030F116dDEE9F6B43aC78BA3', MAX), 'Unlimited approval to Permit2'),
    # A permit names the owner first; the allowlist is checked against the spender.
    (_call('d505accf', OWNER, ROUTER, MAX, 1, 27, 0, 0), 'Unlimited approval to PancakeSwap V2 Router'),
], ids=['permit2', 'permit-to-router'])
async def test_bare_analyzer_allowlists_the_chains_routers_and_permit2(calldata, flag):
    result = await IntentMismatchAnalyzer(Web3Client()).analyze(AnalysisContext(
        address=TOKEN, chain_id=56, extra={'calldata': calldata},
    ))
    assert (result.score, result.flags) == (5, [flag])
    assert result.data['status'] == 'ok'
    assert 'counterparty' not in result.data


CLAIM_AIRDROP = '0x' + keccak(text='claimAirdrop()')[:4].hex()
PAYABLE = _call('40c10f19', OWNER, 1)  # mint(address,uint256)


async def _payable(calldata, is_verified, creation=None, **extra):
    web3 = SimpleNamespace(get_contract_creation_info=AsyncMock(return_value=creation))
    service = _service()
    result = await IntentMismatchAnalyzer(web3, service).analyze(AnalysisContext(
        address=TOKEN, chain_id=56, from_address=OWNER,
        extra={'calldata': calldata, 'value': hex(10 ** 17), 'is_verified': is_verified, **extra},
    ))
    service.fetch.assert_not_awaited()
    return result, web3.get_contract_creation_info


@pytest.mark.asyncio
async def test_paying_a_fresh_unverified_contract_blocks():
    from core.risk_engine import RiskEngine

    result, creation = await _payable(CLAIM_AIRDROP, False, {'age_days': 2})
    creation.assert_awaited_once_with(TOKEN, chain_id=56)
    assert result.data['floor'] == 85
    assert result.data['status'] == 'ok'
    assert result.flags[0] == f'{CLAIM_AIRDROP} sends 0.1 native value to an unverified contract 2 days old'
    result.weight = 1
    risk = RiskEngine().compute_from_results([result], is_token=False)
    assert (risk['rug_probability'], risk['risk_level']) == (85, 'HIGH')


@pytest.mark.asyncio
@pytest.mark.parametrize('creation, floor, target, known', [
    ({'age_days': 30}, 60, 'an unverified contract', True),
    # An unknown age may hide a fresh deployment (85) but is not evidence of one: the verdict is
    # the older contract's 60 and stays Unknown, as for an approval (judge_spender).
    (None, 60, 'an unverified contract of unknown age', False),
    ({'age_days': None}, 60, 'an unverified contract of unknown age', False),
], ids=['old', 'no-creation-record', 'no-creation-time'])
async def test_paying_an_unverified_contract_floors_by_age(creation, floor, target, known):
    result, _ = await _payable(PAYABLE, False, creation)
    assert result.data['floor'] == floor
    assert result.data['status'] == ('ok' if known else 'unknown')
    assert result.data['coverage']['counterparty'] is known
    assert result.flags[0] == f'mint(address,uint256) sends 0.1 native value to {target}'
    if not known:
        assert result.flags[-1] == 'Contract age unavailable for a payment to an unverified contract'


@pytest.mark.asyncio
async def test_paying_a_verified_contract_has_no_floor():
    result, creation = await _payable(PAYABLE, True, {'age_days': 900})
    creation.assert_not_awaited()
    assert 'floor' not in result.data
    assert result.data['status'] == 'ok'
    assert result.data['coverage'] == {'selector_verification': True, 'counterparty': True}


@pytest.mark.asyncio
async def test_paying_a_contract_of_unknown_verification_is_unknown():
    result, creation = await _payable(PAYABLE, None)
    creation.assert_not_awaited()
    assert result.data['floor'] == 60
    assert result.data['status'] == 'unknown'
    assert result.data['coverage']['counterparty'] is False
    assert result.flags[0] == 'mint(address,uint256) sends 0.1 native value to a contract of unknown verification'


@pytest.mark.asyncio
async def test_payment_flag_names_the_call_by_its_signature():
    # The decoder's names can carry their own parentheses ("permit (Permit2)"); the signature is
    # the call exactly, with nothing appended.
    from utils.calldata_decoder import KNOWN_SELECTORS

    result, _ = await _payable('0x2b67b570' + '0' * 64, False, {'age_days': 30})
    assert result.flags[0] == f"{KNOWN_SELECTORS['2b67b570']['signature']} sends 0.1 native value to an unverified contract"


@pytest.mark.asyncio
@pytest.mark.parametrize('calldata', [CLAIM, CLAIM_AIRDROP, PAYABLE])
async def test_paying_a_wallet_has_no_payment_floor(calldata):
    result, creation = await _payable(calldata, False, {'age_days': 1}, is_contract=False)
    creation.assert_not_awaited()
    assert 'floor' not in result.data
    assert result.data['status'] == 'ok'


@pytest.mark.asyncio
async def test_a_slow_creation_lookup_leaves_the_age_unknown(monkeypatch):
    import asyncio

    import services.counterparty_service as counterparty_module

    monkeypatch.setattr(counterparty_module, 'PROVIDER_TIMEOUT', 0.05)

    async def hang(*args, **kwargs):
        await asyncio.sleep(60)

    analyzer = IntentMismatchAnalyzer(SimpleNamespace(get_contract_creation_info=hang), _service())
    result = await asyncio.wait_for(analyzer.analyze(AnalysisContext(
        address=TOKEN, chain_id=56, extra={'calldata': PAYABLE, 'value': hex(10 ** 17), 'is_verified': False},
    )), 5)
    assert result.data['floor'] == 60
    assert result.data['status'] == 'unknown'


@pytest.mark.asyncio
async def test_value_on_a_router_swap_is_not_a_payment_to_the_token():
    swap = '0x7ff36ab5' + '0' * 256
    result, creation = await _payable(swap, False, {'age_days': 1}, whitelisted_router='PancakeSwap V2 Router')
    creation.assert_not_awaited()
    assert 'floor' not in result.data


@pytest.mark.asyncio
async def test_claim_without_value_has_no_floor():
    result, _ = await _intent(CLAIM, value='0', is_verified=False)
    assert 'floor' not in result.data
    assert result.data['status'] == 'ok'
    assert result.data['coverage'] == {'selector_verification': True}


SPENDER_WORDINGS = {
    'Unlimited approval to non-whitelisted contract',
    'Unlimited approval to a wallet address',
    'Unlimited approval to non-whitelisted address',
}


@pytest.mark.asyncio
@pytest.mark.parametrize('facts, wording', [
    (_facts(), 'Unlimited approval to non-whitelisted contract'),
    (_facts(is_contract=False, is_verified=None, age_days=None), 'Unlimited approval to a wallet address'),
    (_facts(is_contract=False, is_verified=None, age_days=None, labels=['stealing_attack'],
            label_source='SlowMist,BlockSec'), 'Unlimited approval to a wallet address'),
    (_facts(delegated=True, is_verified=None, age_days=None), 'Unlimited approval to a wallet address'),
    (_facts(is_contract=None, reason='Spender facts unknown: code (RPC)'),
     'Unlimited approval to non-whitelisted address'),
], ids=['contract', 'wallet', 'labelled-wallet', 'delegated-wallet', 'unknown'])
async def test_unlimited_approval_names_what_the_spender_is(facts, wording):
    # A wallet is never called a contract, and a spender whose code is unknown is neither.
    result, _ = await _intent(UNLIMITED, facts)
    assert [flag for flag in result.flags if flag in SPENDER_WORDINGS] == [wording]
    assert result.score == 35
