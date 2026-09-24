"""Token identification failures must not bypass token analysis."""

import asyncio
import threading
from unittest.mock import AsyncMock, MagicMock

import pytest
from web3.exceptions import BadFunctionCallOutput, ContractLogicError, OffchainLookup

from analyzers.honeypot import HoneypotAnalyzer
from analyzers.intent import IntentMismatchAnalyzer
from analyzers.market import MarketAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.extension_formatter import format_extension_alert
from core.risk_engine import RiskEngine
from utils.web3_client import Web3Client


ADDRESS = '0x1111111111111111111111111111111111111111'


@pytest.fixture
def identification_client():
    client = Web3Client.__new__(Web3Client)
    client.erc20_abi = []
    client._adapters = {56: MagicMock()}
    return client


@pytest.fixture
def covered_results():
    return [
        AnalyzerResult('structural', .4, 0, data={
            'is_contract': True, 'is_verified': True, 'contract_age_days': 100,
            'ownership_renounced': True,
        }),
        AnalyzerResult('behavioral', .2, 0, data={'reputation_score': 80}),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', [
    TimeoutError('RPC timeout'),
    ConnectionError('RPC unavailable'),
    OffchainLookup({'sender': ADDRESS, 'urls': [], 'callData': '0x'}, data='0x556f1830'),
])
async def test_identification_failure_cannot_become_safe(identification_client, covered_results, failure):
    identification_client.get_web3().eth.contract.return_value.functions.symbol.return_value.call.side_effect = failure
    is_token = await identification_client.is_token_contract(ADDRESS)
    ctx = AnalysisContext(ADDRESS, is_token=is_token)
    honeypot_service = MagicMock(fetch_honeypot_data=AsyncMock(return_value={
        'status': 'unknown', 'reason': 'Provider unavailable',
    }))
    dex_service = MagicMock(fetch_token_market_data=AsyncMock(return_value={
        'status': 'unknown', 'reason': 'Provider unavailable',
    }))
    honeypot = await HoneypotAnalyzer(honeypot_service).analyze(ctx)
    market = await MarketAnalyzer(dex_service).analyze(ctx)
    risk = RiskEngine().compute_from_results(covered_results + [honeypot, market], is_token=is_token)

    assert risk['status'] == 'unknown'
    assert risk['risk_level'] != 'LOW'
    assert format_extension_alert(risk)['risk_classification'] != 'SAFE'
    assert risk['coverage']['honeypot'] == risk['coverage']['market'] == 0
    assert risk['category_scores']['honeypot'] is risk['category_scores']['market'] is None
    assert is_token is None
    honeypot_service.fetch_honeypot_data.assert_awaited_once_with(ADDRESS, chain_id=56)
    dex_service.fetch_token_market_data.assert_awaited_once_with(ADDRESS, chain_id=56)


@pytest.mark.asyncio
async def test_successful_identification_is_true(identification_client):
    identification_client.get_web3().eth.contract.return_value.functions.symbol.return_value.call.return_value = 'TOKEN'
    assert await identification_client.is_token_contract(ADDRESS) is True


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', [
    ContractLogicError('execution reverted'),
    BadFunctionCallOutput('Empty reply'),
])
async def test_confirmed_non_token_skips_with_full_coverage(identification_client, covered_results, failure):
    w3 = identification_client.get_web3()
    w3.eth.contract.return_value.functions.symbol.return_value.call.side_effect = failure
    w3.eth.contract.return_value.address = ADDRESS
    w3.eth.call.return_value = b''
    is_token = await identification_client.is_token_contract(ADDRESS)
    assert is_token is False
    if isinstance(failure, BadFunctionCallOutput):
        w3.eth.call.assert_called_once_with({'to': ADDRESS, 'data': '0x95d89b41'})
    ctx = AnalysisContext(ADDRESS, is_token=is_token)
    honeypot_service = MagicMock(fetch_honeypot_data=AsyncMock())
    dex_service = MagicMock(fetch_token_market_data=AsyncMock())
    honeypot = await HoneypotAnalyzer(honeypot_service).analyze(ctx)
    market = await MarketAnalyzer(dex_service).analyze(ctx)
    risk = RiskEngine().compute_from_results(covered_results + [honeypot, market], is_token=is_token)

    for result in (honeypot, market):
        assert result.data['skipped'] is True
        assert result.score == 0
        assert result.flags == []
        assert risk['coverage'][result.name] == 1
    assert risk['status'] == 'ok'
    assert risk['risk_level'] == 'LOW'
    honeypot_service.fetch_honeypot_data.assert_not_awaited()
    dex_service.fetch_token_market_data.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('reply, failure', [
    (b'\x12\x34', None),
    (None, None),
    (None, TimeoutError('RPC timeout')),
])
async def test_bad_symbol_output_without_confirmed_empty_reply_is_unknown(identification_client, reply, failure):
    w3 = identification_client.get_web3()
    w3.eth.contract.return_value.functions.symbol.return_value.call.side_effect = BadFunctionCallOutput('Cannot decode symbol')
    w3.eth.call.return_value = reply
    w3.eth.call.side_effect = failure
    assert await identification_client.is_token_contract(ADDRESS) is None


@pytest.mark.asyncio
@pytest.mark.parametrize('is_token', [None, True])
async def test_unknown_identification_can_be_covered_by_providers(covered_results, is_token):
    ctx = AnalysisContext(ADDRESS, is_token=is_token)
    honeypot_service = MagicMock(fetch_honeypot_data=AsyncMock(return_value={
        'is_honeypot': False, 'can_sell': True, 'can_buy': True, 'buy_tax': 0, 'sell_tax': 0,
    }))
    dex_service = MagicMock(fetch_token_market_data=AsyncMock(return_value={
        'status': 'ok', 'liquidity_usd': 200000, 'pair_age_hours': 100,
    }))
    honeypot = await HoneypotAnalyzer(honeypot_service).analyze(ctx)
    market = await MarketAnalyzer(dex_service).analyze(ctx)
    risk = RiskEngine().compute_from_results(covered_results + [honeypot, market], is_token=is_token)

    honeypot_service.fetch_honeypot_data.assert_awaited_once()
    dex_service.fetch_token_market_data.assert_awaited_once()
    assert risk['coverage']['honeypot'] == risk['coverage']['market'] == 1
    assert risk['status'] == 'ok'
    assert risk['risk_level'] == 'LOW'


@pytest.mark.asyncio
@pytest.mark.parametrize('entrypoint', ['direct', 'registry'])
@pytest.mark.parametrize('evidence', [{'is_honeypot': True}, {'can_sell': False}])
async def test_unknown_token_identification_preserves_adverse_evidence(covered_results, entrypoint, evidence):
    service = MagicMock(fetch_honeypot_data=AsyncMock(return_value=evidence))
    honeypot = await HoneypotAnalyzer(service).analyze(AnalysisContext(ADDRESS, is_token=None))
    market = AnalyzerResult('market', .25, 0, data={'status': 'unknown'})
    engine = RiskEngine()
    if entrypoint == 'direct':
        risk = engine.compute_composite_risk(
            covered_results[0].data, honeypot.data, market.data, covered_results[1].data,
            is_token=None,
        )
    else:
        risk = engine.compute_from_results(covered_results + [honeypot, market], is_token=None)

    assert risk['risk_archetype'] == 'honeypot'
    assert risk['risk_level'] != 'LOW'
    assert risk['category_scores']['honeypot'] > 0
    assert risk['status'] == 'unknown'
    assert any('unknown:' in flag for flag in risk['critical_flags'])
    if evidence.get('is_honeypot'):
        assert risk['rug_probability'] >= 80


def test_unknown_token_identification_requires_honeypot_even_if_other_results_are_complete(covered_results):
    covered_results[0].weight = .8
    risk = RiskEngine().compute_from_results(covered_results, is_token=None)
    assert risk['status'] == 'unknown'
    assert risk['risk_level'] != 'LOW'
    assert 'Sellability unknown: No honeypot data' in risk['critical_flags']


@pytest.mark.asyncio
@pytest.mark.parametrize('is_token', [None, False, True])
@pytest.mark.parametrize('is_verified', [None, False, True])
async def test_unknown_selector_exemption_requires_confirmed_non_token_or_verification(is_token, is_verified):
    result = await IntentMismatchAnalyzer().analyze(AnalysisContext(
        ADDRESS, is_token=is_token,
        extra={'calldata': '0xdeadbeef', 'is_verified': is_verified},
    ))
    exempt = is_token is False or is_verified is True
    assert result.score == (20 if not exempt and is_verified is False else 0)
    assert result.data['status'] == ('unknown' if not exempt and is_verified is None else 'ok')


def _held_until(released, result):
    """A provider call that returns only after a coroutine on the event loop has released it.

    If the call ran on the event loop thread, that coroutine could not run, the wait would time out
    and the call would fail.
    """
    def call(*args, **kwargs):
        if not released.wait(timeout=2):
            raise TimeoutError('the provider call held the event loop')
        return result
    return call


async def _release(released):
    released.set()


@pytest.mark.asyncio
async def test_symbol_lookup_leaves_the_event_loop_free(identification_client):
    released = threading.Event()
    w3 = identification_client.get_web3()
    w3.eth.contract.return_value.functions.symbol.return_value.call.side_effect = _held_until(released, 'TOKEN')
    releaser = asyncio.create_task(_release(released))
    assert await identification_client.is_token_contract(ADDRESS) is True
    await releaser


@pytest.mark.asyncio
async def test_empty_reply_check_leaves_the_event_loop_free(identification_client):
    released = threading.Event()
    w3 = identification_client.get_web3()
    w3.eth.contract.return_value.functions.symbol.return_value.call.side_effect = BadFunctionCallOutput('Empty reply')
    w3.eth.call.side_effect = _held_until(released, b'')
    releaser = asyncio.create_task(_release(released))
    assert await identification_client.is_token_contract(ADDRESS) is False
    await releaser


@pytest.mark.asyncio
async def test_transfer_check_leaves_the_event_loop_free(identification_client):
    released = threading.Event()
    w3 = identification_client.get_web3()
    w3.eth.contract.return_value.functions.decimals.return_value.call.side_effect = _held_until(released, 18)
    releaser = asyncio.create_task(_release(released))
    assert await identification_client.can_transfer_token(ADDRESS) is True
    await releaser


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', [
    ContractLogicError('execution reverted'),
    BadFunctionCallOutput('Empty reply'),
    TimeoutError('RPC timeout'),
])
async def test_transfer_check_failure_is_still_false(identification_client, failure):
    w3 = identification_client.get_web3()
    w3.eth.contract.return_value.functions.decimals.return_value.call.side_effect = failure
    assert await identification_client.can_transfer_token(ADDRESS) is False
