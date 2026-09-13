"""Provider failures must remain unknown throughout token analysis."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from analyzers.honeypot import HoneypotAnalyzer
from adapters.evm_base import EvmAdapter
from core.analyzer import AnalysisContext
from core.extension_formatter import format_extension_alert
from core.risk_engine import RiskEngine
from core.telegram_formatter import format_full_report
from services.honeypot_service import HoneypotService, map_goplus_token_security
from utils.scam_db import ScamDatabase
from utils.web3_client import Web3Client


ADDRESS = '0x1111111111111111111111111111111111111111'
FIELDS = ('is_honeypot', 'buy_tax', 'sell_tax', 'can_buy', 'can_sell')


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['404', '500', 'timeout', 'exception', 'unsupported'])
async def test_provider_failure_stays_unknown_through_formatters(failure):
    adapter = EvmAdapter.__new__(EvmAdapter)
    adapter._honeypot_chain_id = None if failure == 'unsupported' else 4663
    adapter._chain_name = 'Test chain'
    client = Web3Client.__new__(Web3Client)
    client._adapters = {4663: adapter}
    response = MagicMock(status=int(failure) if failure.isdigit() else 200)
    response.json = AsyncMock(return_value={})
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    if failure == 'timeout':
        session.get.side_effect = asyncio.TimeoutError()
    elif failure == 'exception':
        session.get.side_effect = RuntimeError('provider failed')
    with patch.object(ScamDatabase, 'fetch_token_security', new=AsyncMock(return_value={
        'status': 'unknown', 'reason': 'GoPlus unavailable', 'data': {},
    })), patch('adapters.evm_base.aiohttp.ClientSession') as http:
        http.return_value.__aenter__ = AsyncMock(return_value=session)
        service = HoneypotService(client)
        data = await service.fetch_honeypot_data(ADDRESS, chain_id=4663)
        assert data['status'] == 'unknown'
        assert all(data[field] is None for field in FIELDS)
        result = await HoneypotAnalyzer(service).analyze(AnalysisContext(ADDRESS, chain_id=4663))
        if failure == 'unsupported':
            http.assert_not_called()
    risk = RiskEngine().compute_from_results([result])
    assert risk['risk_level'] != 'LOW'
    extension = format_extension_alert(risk)
    telegram = format_full_report(risk, {}, {}, {}, data)
    assert extension['risk_classification'] != 'SAFE'
    assert extension['risk_display'].startswith('Unknown')
    assert 'unknown' in str(extension).lower()
    assert 'Unknown' in telegram
    assert 'Generally Safe' not in telegram
    assert 'Not Honeypot' not in telegram
    assert 'Buy Tax: 0%' not in telegram
    assert 'Sell Tax: 0%' not in telegram
    assert 'Can Sell: \u2705' not in telegram


@pytest.mark.asyncio
async def test_goplus_fallback_maps_fractional_taxes_and_field_providers():
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [56, 4663]
    client.check_honeypot = AsyncMock(return_value={'is_honeypot': None})
    client.get_tax_info = AsyncMock(return_value={'buy_tax': None, 'sell_tax': None})
    raw = {'is_honeypot': '0', 'buy_tax': '0.05', 'sell_tax': '0.125',
           'cannot_buy': '0', 'cannot_sell_all': '0', 'transfer_pausable': '0'}
    with patch.object(ScamDatabase, 'fetch_token_security', new=AsyncMock(return_value={
        'status': 'ok', 'reason': None, 'data': raw,
    }), create=True):
        data = await HoneypotService(client).fetch_honeypot_data(ADDRESS, chain_id=4663)
    assert data['buy_tax'] == 5
    assert data['sell_tax'] == 12.5
    assert data['is_honeypot'] is False
    assert data['can_buy'] is True
    assert data['can_sell'] is True
    assert data['status'] == 'ok'
    assert all(data['field_providers'][field] == 'goplus' for field in FIELDS)


@pytest.mark.asyncio
@pytest.mark.parametrize('raw', [{}, {field: '' for field in (
    'is_honeypot', 'buy_tax', 'sell_tax', 'cannot_buy', 'cannot_sell_all', 'transfer_pausable'
)}, {'is_honeypot': 'invalid', 'buy_tax': 'NaN', 'sell_tax': '-1'}])
async def test_empty_or_invalid_goplus_fields_are_unknown(raw):
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [56, 4663]
    client.check_honeypot = AsyncMock(return_value={})
    client.get_tax_info = AsyncMock(return_value={})
    with patch.object(ScamDatabase, 'fetch_token_security', new=AsyncMock(return_value={
        'status': 'ok', 'reason': None, 'data': raw,
    }), create=True):
        data = await HoneypotService(client).fetch_honeypot_data(ADDRESS, chain_id=4663)
    assert all(data[field] is None for field in FIELDS)
    assert data['status'] == 'unknown'
    assert data['reason']


@pytest.mark.asyncio
async def test_complete_primary_provider_does_not_fetch_goplus():
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [56, 4663]
    client.check_honeypot = AsyncMock(return_value={'is_honeypot': False})
    client.get_tax_info = AsyncMock(return_value={'buy_tax': 0, 'sell_tax': 5})
    with patch.object(ScamDatabase, 'fetch_token_security', new=AsyncMock(), create=True) as fetch:
        data = await HoneypotService(client).fetch_honeypot_data(ADDRESS)
    fetch.assert_not_awaited()
    assert data['status'] == 'ok'
    assert data['sell_tax'] == 5


@pytest.mark.asyncio
@pytest.mark.parametrize('concurrent', [False, True])
async def test_goplus_shared_fetch_across_both_scan_paths(concurrent):
    import utils.scam_db as scam_module
    scam_module._GOPLUS_CACHE.clear()

    response = MagicMock(status=200)
    response.json = AsyncMock(return_value={'code': 1, 'result': {ADDRESS: {
        'is_honeypot': '1', 'buy_tax': '0', 'sell_tax': '1',
        'cannot_buy': '0', 'cannot_sell_all': '1', 'transfer_pausable': '0',
    }}})
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    session.get.return_value.__aexit__ = AsyncMock(return_value=False)
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [56, 4663]
    client.check_honeypot = AsyncMock(return_value={})
    client.get_tax_info = AsyncMock(return_value={})
    with patch('utils.scam_db.aiohttp.ClientSession') as session_type:
        session_type.return_value.__aenter__ = AsyncMock(return_value=session)
        session_type.return_value.__aexit__ = AsyncMock(return_value=False)
        db = ScamDatabase()
        service = HoneypotService(client)
        if concurrent:
            matches, data = await asyncio.gather(
                db._check_goplus(ADDRESS, 4663), service.fetch_honeypot_data(ADDRESS, 4663),
            )
        else:
            matches = await db._check_goplus(ADDRESS, 4663)
            data = await service.fetch_honeypot_data(ADDRESS, 4663)
    assert len(matches) == 1
    assert data['is_honeypot'] is True
    assert data['can_sell'] is False
    assert session.get.call_count == 1
    assert '/4663?' in session.get.call_args.args[0]
    scam_module._GOPLUS_CACHE.clear()


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['404', '500', 'timeout', 'exception', 'missing_token', 'wrong_token', 'bad_code', 'malformed'])
async def test_goplus_http_failures_are_unknown(failure):
    import utils.scam_db as scam_module
    scam_module._GOPLUS_CACHE.clear()
    payload = {'code': 1, 'result': {}}
    if failure == 'wrong_token':
        payload['result']['0x2222222222222222222222222222222222222222'] = {'is_honeypot': '0'}
    elif failure == 'bad_code':
        payload = {'code': 0, 'result': {ADDRESS: {'is_honeypot': '0'}}}
    elif failure == 'malformed':
        payload = []
    response = MagicMock(status=int(failure) if failure.isdigit() else 200)
    response.json = AsyncMock(return_value=payload)
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    if failure in ('timeout', 'exception'):
        session.get.side_effect = TimeoutError() if failure == 'timeout' else RuntimeError('offline')
    with patch('utils.scam_db.aiohttp.ClientSession') as http:
        http.return_value.__aenter__ = AsyncMock(return_value=session)
        result = await ScamDatabase.fetch_token_security(ADDRESS, 4663)
        cached = await ScamDatabase.fetch_token_security(ADDRESS.upper().replace('0X', '0x'), 4663)
    assert result == cached
    assert result['status'] == 'unknown'
    assert result['data'] == {}
    assert result['reason']
    assert session.get.call_count == 1
    scam_module._GOPLUS_CACHE.clear()


@pytest.mark.asyncio
async def test_unregistered_chain_is_an_error_before_any_provider_call():
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [56]
    with patch.object(ScamDatabase, 'fetch_token_security', new=AsyncMock()) as fetch:
        with pytest.raises(ValueError, match='No registered adapter for chain 4663'):
            await HoneypotService(client).fetch_honeypot_data(ADDRESS, 4663)
    client.check_honeypot.assert_not_called()
    fetch.assert_not_awaited()


@pytest.mark.parametrize('flag', ['cannot_sell_all', 'transfer_pausable'])
def test_goplus_restriction_does_not_claim_all_sales_impossible(flag):
    raw = {'is_honeypot': '0', 'buy_tax': '0', 'sell_tax': '0',
           'cannot_buy': '0', 'cannot_sell_all': '0', 'transfer_pausable': '0'}
    raw[flag] = '1'
    data = map_goplus_token_security(raw)
    assert data[flag] is True
    assert data['can_sell'] is None


@pytest.mark.parametrize('value', ['NaN', 'Infinity', '-0.1', '1.01', 'bad', '', None, True, 0])
def test_goplus_tax_format_requires_a_fraction_string(value):
    data = map_goplus_token_security({'buy_tax': value, 'sell_tax': value})
    assert data['buy_tax'] is None
    assert data['sell_tax'] is None


@pytest.mark.asyncio
async def test_primary_extreme_taxes_are_preserved_without_fallback():
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [56]
    client.check_honeypot = AsyncMock(return_value={'is_honeypot': False})
    client.get_tax_info = AsyncMock(return_value={'buy_tax': 101, 'sell_tax': 120})
    with patch.object(ScamDatabase, 'fetch_token_security', new=AsyncMock(return_value={
        'status': 'ok', 'reason': None, 'data': {'buy_tax': '0', 'sell_tax': '0'},
    })) as fetch:
        data = await HoneypotService(client).fetch_honeypot_data(ADDRESS)
    assert data['buy_tax'] == 101
    assert data['sell_tax'] == 120
    assert data['can_buy'] is False
    assert data['can_sell'] is False
    fetch.assert_not_awaited()


@pytest.mark.parametrize('method', ['compute_composite_risk', 'compute_from_results'])
def test_fully_covered_discount_matches_baseline(method):
    from core.analyzer import AnalyzerResult
    contract = {'is_verified': False, 'is_contract': True, 'has_mint': True,
                'has_proxy': True, 'has_pause': True, 'has_blacklist': True,
                'contract_age_days': 1, 'scam_matches': ['match'], 'ownership_renounced': True}
    honeypot = {'is_honeypot': False, 'can_sell': False, 'buy_tax': 0, 'sell_tax': 0}
    market = {'liquidity_usd': 200000, 'fdv': 200000, 'volume_24h': 2000,
              'pair_age_hours': 100}
    ethos = {'reputation_score': 80}
    engine = RiskEngine()
    if method == 'compute_composite_risk':
        result = engine.compute_composite_risk(contract, honeypot, market, ethos)
    else:
        result = engine.compute_from_results([
            AnalyzerResult('structural', .4, 100, data=contract),
            AnalyzerResult('market', .25, 0, data=market),
            AnalyzerResult('behavioral', .2, 0, data=ethos),
            AnalyzerResult('honeypot', .15, 60, data=honeypot),
        ])
    assert result['rug_probability'] == 29
    assert result['risk_level'] == 'LOW'


@pytest.mark.asyncio
async def test_complete_primary_honeypot_score_matches_baseline():
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [56]
    client.check_honeypot = AsyncMock(return_value={'is_honeypot': True})
    client.get_tax_info = AsyncMock(return_value={'buy_tax': 0, 'sell_tax': 5})
    with patch.object(ScamDatabase, 'fetch_token_security', new=AsyncMock()) as fetch:
        result = await HoneypotAnalyzer(HoneypotService(client)).analyze(AnalysisContext(ADDRESS))
    assert result.score == 80
    assert 'Honeypot detected' in result.flags
    fetch.assert_not_awaited()
