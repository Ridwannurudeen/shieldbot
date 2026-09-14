"""Provider failures must remain unknown throughout token analysis."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from analyzers.honeypot import HoneypotAnalyzer
from adapters.evm_base import EvmAdapter
from core.analyzer import AnalysisContext, AnalyzerResult
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


@pytest.mark.asyncio
@pytest.mark.parametrize('renounced', [False, True])
@pytest.mark.parametrize('entrypoint', ['direct', 'registry'])
async def test_failed_simulation_with_clean_fallback_never_becomes_safe(renounced, entrypoint):
    adapter = EvmAdapter.__new__(EvmAdapter)
    adapter._honeypot_chain_id = 56
    adapter._chain_name = 'BSC'
    client = Web3Client.__new__(Web3Client)
    client._adapters = {56: adapter}
    response = AsyncMock(status=200)
    response.json.return_value = {'simulationSuccess': False}
    session = MagicMock()
    session.get.return_value.__aenter__.return_value = response
    raw = {'is_honeypot': '0', 'buy_tax': '0', 'sell_tax': '0',
           'cannot_buy': '0', 'cannot_sell_all': '0', 'transfer_pausable': '0'}
    with patch('adapters.evm_base.aiohttp.ClientSession') as http, patch.object(
        ScamDatabase, 'fetch_token_security', new=AsyncMock(return_value={
            'status': 'ok', 'reason': None, 'data': raw,
        }),
    ):
        http.return_value.__aenter__.return_value = session
        service = HoneypotService(client)
        data = await service.fetch_honeypot_data(ADDRESS)
        result = await HoneypotAnalyzer(service).analyze(AnalysisContext(ADDRESS))
    contract = {'is_contract': True, 'is_verified': True, 'ownership_renounced': renounced,
                'contract_age_days': 100}
    market = {'liquidity_usd': 200000, 'fdv': 200000, 'volume_24h': 2000, 'pair_age_hours': 100}
    ethos = {'reputation_score': 80}
    engine = RiskEngine()
    if entrypoint == 'direct':
        risk = engine.compute_composite_risk(contract, data, market, ethos)
    else:
        risk = engine.compute_from_results([
            AnalyzerResult('structural', .4, 0 if renounced else 5, data=contract),
            AnalyzerResult('market', .25, 0, data=market),
            AnalyzerResult('behavioral', .2, 0, data=ethos), result,
        ])
    alert = format_extension_alert(risk)
    report = format_full_report(risk, contract, market, ethos, data)
    assert risk['risk_level'] == 'MEDIUM'
    assert risk['rug_probability'] == (6 if renounced else 8)
    assert risk['coverage']['honeypot'] < 1
    assert risk['status'] == 'unknown'
    assert alert['risk_classification'] == 'CAUTION'
    assert alert['risk_display'].startswith('Unknown')
    assert 'Generally Safe' not in report
    assert 'Sellability: Unknown' in report
    assert 'simulation failed' in report.lower()
    assert data['status'] == result.data['status'] == 'unknown'
    assert data['coverage']['can_sell'] is False
    assert result.data['coverage']['can_sell'] is False
    assert data['can_sell'] is result.data['can_sell'] is None
    assert result.score == 40


@pytest.mark.asyncio
@pytest.mark.parametrize('field, flag', [
    ('cannot_sell_all', 'Cannot sell all tokens'),
    ('transfer_pausable', 'Token transfers can be paused'),
    ('cannot_buy', 'Cannot buy token'),
])
async def test_partial_goplus_restrictions_score_in_both_engine_paths(field, flag):
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [4663]
    client.check_honeypot = AsyncMock(return_value={})
    client.get_tax_info = AsyncMock(return_value={})
    with patch.object(ScamDatabase, 'fetch_token_security', new=AsyncMock(return_value={
        'status': 'ok', 'reason': None, 'data': {field: '1'},
    })):
        result = await HoneypotAnalyzer(HoneypotService(client)).analyze(AnalysisContext(ADDRESS, chain_id=4663))
    direct = RiskEngine().compute_composite_risk({}, result.data, {}, {})
    registry = RiskEngine().compute_from_results([result])
    assert result.score == 20
    assert flag in result.flags
    for risk in (direct, registry):
        assert risk['category_scores']['honeypot'] == 20
        assert risk['rug_probability'] == 20
        assert flag in risk['critical_flags']
        assert risk['risk_archetype'] != 'honeypot'
    assert result.data['can_sell'] is None
    if field == 'cannot_buy':
        assert result.data['can_buy'] is False


@pytest.mark.parametrize('failed', [False, True])
@pytest.mark.parametrize('entrypoint', ['direct', 'registry'])
def test_successful_unrestricted_parity_and_failed_simulation_exception(failed, entrypoint):
    # Parity applies to successful simulations with none of the three restrictions.
    # Baseline unrestricted input: structural 70 * .4 = 28 (LOW).
    # An unresolved failure adds 40 * .15 = 6 and cannot be coverage-complete.
    contract = {'is_contract': True, 'is_verified': False, 'contract_age_days': 1,
                'has_mint': True, 'has_blacklist': True, 'ownership_renounced': True}
    data = {'is_honeypot': False, 'can_buy': True, 'can_sell': True,
            'buy_tax': 0, 'sell_tax': 0, 'simulation_failed': failed,
            'cannot_buy': False, 'cannot_sell_all': False, 'transfer_pausable': False,
            'status': 'ok', 'coverage': {field: True for field in FIELDS}}
    market = {'liquidity_usd': 50000, 'fdv': 200000, 'volume_24h': 2000, 'pair_age_hours': 100}
    ethos = {'reputation_score': 80}
    if entrypoint == 'direct':
        risk = RiskEngine().compute_composite_risk(contract, data, market, ethos)
    else:
        risk = RiskEngine().compute_from_results([
            AnalyzerResult('structural', .4, 70, data=contract),
            AnalyzerResult('market', .25, 0, data=market),
            AnalyzerResult('behavioral', .2, 0, data=ethos),
            AnalyzerResult('honeypot', .15, 40 if failed else 0, data=data),
        ])
    assert risk['rug_probability'] == (34 if failed else 28)
    assert risk['risk_level'] == ('MEDIUM' if failed else 'LOW')
    assert risk['status'] == ('unknown' if failed else 'ok')
    assert (risk['coverage']['honeypot'] < 1) is failed


@pytest.mark.asyncio
@pytest.mark.parametrize('restriction,flag', [
    ('cannot_buy', 'Cannot buy token'),
    ('cannot_sell_all', 'Cannot sell all tokens'),
    ('transfer_pausable', 'Token transfers can be paused'),
])
@pytest.mark.parametrize('entrypoint', ['direct', 'registry'])
async def test_complete_restrictions_are_deliberate_parity_exceptions(restriction, flag, entrypoint):
    # c1d1adf ignored these restrictions: 70 * .4 = 28 (LOW) in both paths.
    # Each known restriction now adds 20 * .15 = 3, retaining complete coverage.
    contract = {'is_contract': True, 'is_verified': False, 'contract_age_days': 1,
                'has_mint': True, 'has_blacklist': True, 'ownership_renounced': True}
    data = {'is_honeypot': False, 'can_buy': restriction != 'cannot_buy', 'can_sell': True,
            'buy_tax': 0, 'sell_tax': 0, 'simulation_failed': False,
            'cannot_buy': False, 'cannot_sell_all': False, 'transfer_pausable': False,
            'status': 'ok', 'coverage': {field: True for field in FIELDS}}
    data[restriction] = True
    market = {'liquidity_usd': 50000, 'fdv': 200000, 'volume_24h': 2000, 'pair_age_hours': 100}
    ethos = {'reputation_score': 80}
    service = MagicMock()
    service.fetch_honeypot_data = AsyncMock(return_value=data)
    result = await HoneypotAnalyzer(service).analyze(AnalysisContext(ADDRESS))
    if entrypoint == 'direct':
        risk = RiskEngine().compute_composite_risk(contract, data, market, ethos)
    else:
        risk = RiskEngine().compute_from_results([
            AnalyzerResult('structural', .4, 70, data=contract),
            AnalyzerResult('market', .25, 0, data=market),
            AnalyzerResult('behavioral', .2, 0, data=ethos), result,
        ])
    assert risk['rug_probability'] == 31
    assert risk['risk_level'] == 'MEDIUM'
    assert risk['category_scores']['honeypot'] == result.score == 20
    assert flag in risk['critical_flags']
    assert risk['risk_archetype'] != 'honeypot'
    assert risk['status'] == result.data['status'] == 'ok'
    assert all(value == 1 for value in risk['coverage'].values())
    assert all(result.data['coverage'].values())


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', [TimeoutError(), RuntimeError('GoPlus failed')])
@pytest.mark.parametrize('partial', [False, True])
async def test_goplus_escape_is_normalized_inside_service(failure, partial):
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [56]
    client.check_honeypot = AsyncMock(return_value={'is_honeypot': False} if partial else {})
    client.get_tax_info = AsyncMock(return_value={'buy_tax': 5} if partial else {})
    with patch.object(ScamDatabase, 'fetch_token_security', new=AsyncMock(side_effect=failure)):
        data = await HoneypotService(client).fetch_honeypot_data(ADDRESS)
    assert data['status'] == 'unknown'
    assert 'GoPlus' in data['reason']
    assert type(failure).__name__ in data['reason']
    assert data['sell_tax'] is data['can_sell'] is None
    if partial:
        assert data['is_honeypot'] is False
        assert data['buy_tax'] == 5
        assert data['field_providers']['buy_tax'] == 'honeypot.is'
    else:
        assert all(data[field] is None for field in FIELDS)


@pytest.mark.asyncio
@pytest.mark.parametrize('verified,age,score', [(None, 100, 0), (True, None, 0), (None, None, 0), (False, 100, 25)])
async def test_structural_tristate_coverage_and_penalty(verified, age, score):
    from analyzers.structural import StructuralAnalyzer

    service = MagicMock()
    service.fetch_contract_data = AsyncMock(return_value={
        'is_contract': True, 'is_verified': verified, 'contract_age_days': age,
    })
    sniffer = MagicMock()
    sniffer.is_enabled.return_value = True
    sniffer.fetch = AsyncMock(return_value={})
    result = await StructuralAnalyzer(service, sniffer).analyze(AnalysisContext(ADDRESS))
    assert result.score == score
    assert ('Contract not verified' in result.flags) is (verified is False)
    assert result.data['coverage']['is_verified'] is (verified is not None)
    assert result.data['coverage']['contract_age_days'] is (age is not None)
    if verified is None or age is None:
        assert result.data['status'] == 'unknown'
        assert result.data['reason']
    else:
        assert result.data['status'] == 'ok'
    if verified is None:
        sniffer.fetch.assert_not_awaited()
    result.weight = 1
    risk = RiskEngine().compute_from_results([result], is_token=False)
    assert risk['status'] == result.data['status']
    if verified is None or age is None:
        assert risk['risk_level'] == 'MEDIUM'
        assert risk['risk_archetype'] == 'unknown'
        assert risk['coverage_reasons']['structural'] == result.data['reason']


@pytest.mark.parametrize('entrypoint', ['direct', 'registry'])
@pytest.mark.parametrize('verified,age', [(None, 100), (True, None), (None, None)])
def test_structural_unknown_reaches_both_risk_entrypoints(entrypoint, verified, age):
    contract = {'is_contract': True, 'is_verified': verified, 'contract_age_days': age}
    honeypot = {'is_honeypot': False, 'can_sell': True, 'buy_tax': 0, 'sell_tax': 0}
    market = {'liquidity_usd': 200000, 'pair_age_hours': 100}
    ethos = {'reputation_score': 80}
    if entrypoint == 'direct':
        risk = RiskEngine().compute_composite_risk(contract, honeypot, market, ethos)
    else:
        risk = RiskEngine().compute_from_results([
            AnalyzerResult('structural', .4, 0, data=contract),
            AnalyzerResult('market', .25, 0, data=market),
            AnalyzerResult('behavioral', .2, 0, data=ethos),
            AnalyzerResult('honeypot', .15, 0, data=honeypot),
        ])
    assert risk['status'] == 'unknown'
    assert risk['coverage']['structural'] < 1
    assert risk['risk_level'] == 'MEDIUM'
    assert risk['coverage_reasons']['structural']
    assert risk['risk_archetype'] == 'unknown'
    assert 'Contract not verified' not in risk['critical_flags']
    assert risk['rug_probability'] == 0


@pytest.mark.parametrize('verified,expected', [(None, 8), (False, 55)])
def test_unknown_verification_does_not_trigger_unverified_escalation(verified, expected):
    risk = RiskEngine().compute_from_results([
        AnalyzerResult('structural', .4, 20, data={
            'is_contract': True, 'is_verified': verified, 'contract_age_days': 100,
            'has_mint': True, 'ownership_renounced': False,
        }),
        AnalyzerResult('market', .25, 0, data={'liquidity_usd': 50000}),
        AnalyzerResult('behavioral', .2, 0, data={'reputation_score': 80}),
        AnalyzerResult('honeypot', .15, 0, data={
            'is_honeypot': False, 'can_sell': True, 'buy_tax': 0, 'sell_tax': 0,
        }),
    ])
    assert risk['rug_probability'] == expected


@pytest.mark.asyncio
async def test_structural_preserves_explicit_service_unknown():
    from analyzers.structural import StructuralAnalyzer

    service = MagicMock()
    service.fetch_contract_data = AsyncMock(return_value={
        'is_contract': True, 'is_verified': True, 'contract_age_days': 100,
        'status': 'unknown', 'reason': 'Bytecode provider unavailable',
    })
    result = await StructuralAnalyzer(service).analyze(AnalysisContext(ADDRESS))
    assert result.data['status'] == 'unknown'
    result.weight = 1
    risk = RiskEngine().compute_from_results([result], is_token=False)
    assert risk['status'] == 'unknown'
    assert risk['coverage']['structural'] < 1
    assert risk['coverage_reasons']['structural'] == 'Bytecode provider unavailable'
    assert risk['risk_level'] == 'MEDIUM'


@pytest.mark.parametrize('entrypoint', ['direct', 'registry'])
@pytest.mark.parametrize('component', ['structural', 'market', 'behavioral', 'honeypot'])
def test_explicit_unknown_overrides_complete_fields(entrypoint, component):
    data = {
        'structural': {'is_contract': True, 'is_verified': True, 'contract_age_days': 100},
        'market': {'liquidity_usd': 200000, 'pair_age_hours': 100},
        'behavioral': {'reputation_score': 80},
        'honeypot': {'is_honeypot': False, 'can_sell': True, 'buy_tax': 0, 'sell_tax': 0},
    }
    data[component]['coverage'] = {field: True for field in data[component]}
    data[component]['status'] = 'unknown'
    data[component]['reason'] = 'Provider response incomplete'
    if entrypoint == 'direct':
        risk = RiskEngine().compute_composite_risk(
            data['structural'], data['honeypot'], data['market'], data['behavioral'],
        )
    else:
        risk = RiskEngine().compute_from_results([
            AnalyzerResult(name, weight, 0, data=data[name])
            for name, weight in [('structural', .4), ('market', .25), ('behavioral', .2), ('honeypot', .15)]
        ])
    assert risk['status'] == 'unknown'
    assert risk['coverage'][component] < 1
    assert risk['coverage_reasons'][component] == 'Provider response incomplete'
    assert risk['risk_level'] == 'MEDIUM'
    assert risk['risk_archetype'] == 'unknown'
    assert risk['rug_probability'] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('unknown', [False, True])
async def test_zero_weight_result_preserves_unknown_without_invalidating_skip(unknown):
    from core.registry import AnalyzerRegistry

    registry = AnalyzerRegistry()
    for result in [
        AnalyzerResult('structural', 1, 0, data={'is_verified': True, 'contract_age_days': 100}),
        AnalyzerResult('intent', 0, 0, data={
            'status': 'unknown', 'coverage': {'selector_verification': False},
            'reason': 'Verification unavailable',
        } if unknown else {'skipped': True, 'reason': 'Not applicable'}),
    ]:
        analyzer = MagicMock()
        analyzer.name = result.name
        analyzer.analyze = AsyncMock(return_value=result)
        registry.register(analyzer)
    results = await registry.run_all(AnalysisContext(ADDRESS, is_token=False))
    risk = RiskEngine().compute_from_results(results, is_token=False)
    assert risk['status'] == ('unknown' if unknown else 'ok')
    assert risk['risk_level'] == ('MEDIUM' if unknown else 'LOW')
    assert risk['coverage']['intent'] == (0 if unknown else 1)


@pytest.mark.asyncio
async def test_honeypot_preserves_explicit_service_unknown():
    service = MagicMock()
    service.fetch_honeypot_data = AsyncMock(return_value={
        'is_honeypot': False, 'can_buy': True, 'can_sell': True,
        'buy_tax': 0, 'sell_tax': 0,
        'status': 'unknown', 'reason': 'Provider response incomplete',
    })
    result = await HoneypotAnalyzer(service).analyze(AnalysisContext(ADDRESS))
    assert result.data['status'] == 'unknown'
    assert any('unknown' in flag for flag in result.flags)
    result.weight = 1
    risk = RiskEngine().compute_from_results([result])
    assert risk['status'] == 'unknown'
    assert risk['coverage']['honeypot'] < 1
    assert risk['coverage_reasons']['honeypot'] == 'Provider response incomplete'
    assert risk['risk_level'] == 'MEDIUM'
