"""Regression tests for core routing and incomplete provider coverage."""

import ast
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scanner.token_scanner import TokenScanner
from scanner.transaction_scanner import TransactionScanner
from utils.web3_client import UnsupportedChainError


@pytest.mark.asyncio
@pytest.mark.parametrize('method', [
    'is_contract', 'is_verified_contract', 'get_contract_creation_info',
    'get_ownership_info', 'get_bytecode', 'check_address',
])
async def test_contract_service_propagates_routing_error(mock_web3_client, method):
    from services.contract_service import ContractService

    scam_db = MagicMock(check_address=AsyncMock(return_value=[]))
    target = scam_db if method == 'check_address' else mock_web3_client
    getattr(target, method).side_effect = UnsupportedChainError('unsupported')
    with patch('services.contract_service.BSCSCAN_DELAY', 0):
        with pytest.raises(UnsupportedChainError, match='unsupported'):
            await ContractService(mock_web3_client, scam_db).fetch_contract_data('0xABC')


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['not_contract', 'is_contract', 'is_verified_contract', 'get_contract_creation_info', None])
async def test_contract_service_unavailable_verification_is_none(mock_web3_client, failure):
    from services.contract_service import ContractService

    mock_web3_client.is_verified_contract.return_value = (None, None)
    mock_web3_client.get_contract_creation_info.return_value = {'age_days': None}
    if failure == 'not_contract':
        mock_web3_client.is_contract.return_value = False
    elif failure:
        getattr(mock_web3_client, failure).side_effect = RuntimeError('unavailable')
    with patch('services.contract_service.BSCSCAN_DELAY', 0):
        result = await ContractService(
            mock_web3_client, MagicMock(check_address=AsyncMock(return_value=[])),
        ).fetch_contract_data('0xABC')
    assert result['is_verified'] is None
    assert result['contract_age_days'] is None


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['check_honeypot', 'get_tax_info', 'goplus', 'unregistered'])
async def test_honeypot_service_propagates_routing_error(mock_web3_client, method):
    from services.honeypot_service import HoneypotService

    mock_web3_client.get_supported_chain_ids.return_value = [] if method == 'unregistered' else [56]
    fallback = AsyncMock(return_value={'data': {}, 'reason': 'unavailable'})
    if method == 'goplus':
        mock_web3_client.check_honeypot.return_value = {}
        fallback.side_effect = UnsupportedChainError('unsupported')
    elif method != 'unregistered':
        getattr(mock_web3_client, method).side_effect = UnsupportedChainError('unsupported')
    with patch('services.honeypot_service.ScamDatabase.fetch_token_security', fallback):
        with pytest.raises(UnsupportedChainError):
            await HoneypotService(mock_web3_client).fetch_honeypot_data('0xABC')


@pytest.mark.asyncio
@pytest.mark.parametrize('entrypoint', ['_scan_approvals', 'get_approvals', 'get_health'])
async def test_guardian_propagates_rescue_routing_error(entrypoint):
    from services.guardian import GuardianService

    db = MagicMock(update_guardian_health=AsyncMock())
    rescue = MagicMock(scan_approvals=AsyncMock(side_effect=UnsupportedChainError('unsupported')))
    with pytest.raises(UnsupportedChainError, match='unsupported'):
        await getattr(GuardianService(db, rescue_service=rescue), entrypoint)('0xABC', 56)
    db.update_guardian_health.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('entrypoint, method', [
    ('_scan_approvals', 'get_contract_score'),
    ('_check_flagged_exposure_from_tokens', 'get_contract_score'),
    ('_check_deployer_risk_from_tokens', 'get_deployer_risk_summary'),
    ('_check_deployer_risk_from_tokens', 'is_watched_deployer'),
])
async def test_guardian_nested_routing_error_propagates(entrypoint, method):
    from services.guardian import GuardianService

    db = MagicMock(
        get_contract_score=AsyncMock(return_value=None),
        get_deployer_risk_summary=AsyncMock(return_value={'deployer_address': '0xDeployer'}),
        is_watched_deployer=AsyncMock(return_value=None),
    )
    getattr(db, method).side_effect = UnsupportedChainError('unsupported')
    rescue = MagicMock(scan_approvals=AsyncMock(return_value={'approvals': [{'spender': '0xSpender'}]}))
    argument = '0xABC' if entrypoint == '_scan_approvals' else ['0xABC']
    with pytest.raises(UnsupportedChainError, match='unsupported'):
        await getattr(GuardianService(db, rescue_service=rescue), entrypoint)(argument, 56)


@pytest.fixture
def rescue_pipeline(mock_web3_client):
    from services.rescue_service import RescueService

    wallet, token, spender = ['0x' + digit * 40 for digit in ('1', '2', '3')]
    service = RescueService(mock_web3_client, logs_rpc='https://rpc.invalid')
    response = AsyncMock()
    response.json.return_value = {'result': '0x1'}
    session = MagicMock()
    session.post.return_value.__aenter__.return_value = response
    session.get.return_value.__aenter__.return_value = response
    service._fetch_log_chunk = AsyncMock(return_value=[{
        'address': token, 'topics': ['0x0', '0x0', spender], 'data': '0x1', 'blockNumber': '0x1',
    }])
    service._verify_allowances = AsyncMock(return_value={(token, spender): 1})
    service._fetch_balances = AsyncMock(return_value={token: 1})
    service._fetch_prices = AsyncMock(return_value={})
    with patch('services.rescue_service.aiohttp.ClientSession') as factory:
        factory.return_value.__aenter__.return_value = session
        yield service, wallet, token, spender, session


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['_fetch_log_chunk', '_verify_allowances', '_fetch_balances', '_fetch_prices', 'get_token_info'])
async def test_rescue_pipeline_propagates_routing_error(rescue_pipeline, mock_web3_client, method):
    service, wallet, _, _, _ = rescue_pipeline
    target = mock_web3_client if method == 'get_token_info' else service
    getattr(target, method).side_effect = UnsupportedChainError('unsupported')
    with pytest.raises(UnsupportedChainError, match='unsupported'):
        await service.scan_approvals(wallet)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['_verify_allowances', '_fetch_balances'])
async def test_rescue_rpc_gathers_propagate_routing_error(rescue_pipeline, method):
    from services.rescue_service import RescueService

    service, wallet, token, spender, _ = rescue_pipeline
    service._eth_call = AsyncMock(side_effect=UnsupportedChainError('unsupported'))
    argument = {(token, spender): {}} if method == '_verify_allowances' else [token]
    with pytest.raises(UnsupportedChainError, match='unsupported'):
        await getattr(RescueService, method)(service, wallet, argument, 'https://rpc.invalid')


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['_fetch_log_chunk', '_eth_call', '_fetch_prices'])
async def test_rescue_rpc_catches_propagate_routing_error(rescue_pipeline, method):
    from services.rescue_service import RescueService

    service, _, token, _, session = rescue_pipeline
    session.post.side_effect = UnsupportedChainError('unsupported')
    session.get.side_effect = UnsupportedChainError('unsupported')
    args = {
        '_fetch_log_chunk': (session, 'https://rpc.invalid', '0x0', '0x0', '0x0', '0x1'),
        '_eth_call': (session, 'https://rpc.invalid', token, '0x0'),
        '_fetch_prices': ([token],),
    }
    with pytest.raises(UnsupportedChainError, match='unsupported'):
        await getattr(RescueService, method)(service, *args[method])


@pytest.mark.asyncio
async def test_rescue_configured_rpc_cannot_bypass_chain_routing():
    from services.rescue_service import RescueService
    from utils.web3_client import Web3Client

    client = Web3Client.__new__(Web3Client)
    client._adapters = {}
    service = RescueService(client, logs_rpcs={999999: 'https://rpc.invalid'})
    with patch('services.rescue_service.aiohttp.ClientSession') as session:
        with pytest.raises(UnsupportedChainError):
            await service.scan_approvals('0x' + '1' * 40, 999999)
        session.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['_fetch_log_chunk', '_verify_allowances', '_fetch_balances', 'get_token_info'])
async def test_rescue_failed_required_data_cannot_return_empty_clean_scan(rescue_pipeline, mock_web3_client, method):
    service, wallet, _, _, _ = rescue_pipeline
    target = mock_web3_client if method == 'get_token_info' else service
    getattr(target, method).side_effect = RuntimeError('provider unavailable')
    with pytest.raises(RuntimeError):
        await service.scan_approvals(wallet)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['_fetch_log_chunk', '_eth_call'])
@pytest.mark.parametrize('payload', [{'error': {'message': 'unavailable'}}, {}])
async def test_rescue_rpc_errors_are_not_zero_or_empty(rescue_pipeline, method, payload):
    from services.rescue_service import RescueService

    service, _, token, _, session = rescue_pipeline
    response = session.post.return_value.__aenter__.return_value
    response.status = 200
    response.json.return_value = payload
    args = (
        (session, 'https://rpc.invalid', '0x0', '0x0', '0x0', '0x1')
        if method == '_fetch_log_chunk' else (session, 'https://rpc.invalid', token, '0x0')
    )
    with pytest.raises(RuntimeError):
        await getattr(RescueService, method)(service, *args)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['_verify_allowances', '_fetch_balances'])
async def test_rescue_failed_rpc_batch_cannot_look_empty(rescue_pipeline, method):
    from services.rescue_service import RescueService

    service, wallet, token, spender, _ = rescue_pipeline
    service._eth_call = AsyncMock(side_effect=RuntimeError('provider unavailable'))
    argument = {(token, spender): {}} if method == '_verify_allowances' else [token]
    with pytest.raises(RuntimeError):
        await getattr(RescueService, method)(service, wallet, argument, 'https://rpc.invalid')


@pytest.mark.asyncio
async def test_rescue_missing_rpc_cannot_return_empty_clean_scan(rescue_pipeline):
    service, wallet, _, _, session = rescue_pipeline
    service._rpc_for = MagicMock(return_value='')
    with pytest.raises(RuntimeError):
        await service.scan_approvals(wallet)
    session.post.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('method, payload, expected', [
    ('_fetch_log_chunk', {'result': []}, []),
    ('_eth_call', {'result': '0x0'}, 0),
])
async def test_rescue_confirmed_empty_rpc_data_remains_empty(rescue_pipeline, method, payload, expected):
    from services.rescue_service import RescueService

    service, _, token, _, session = rescue_pipeline
    response = session.post.return_value.__aenter__.return_value
    response.status = 200
    response.json.return_value = payload
    args = (
        (session, 'https://rpc.invalid', '0x0', '0x0', '0x0', '0x1')
        if method == '_fetch_log_chunk' else (session, 'https://rpc.invalid', token, '0x0')
    )
    assert await getattr(RescueService, method)(service, *args) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("method", [
    "get_token_info", "is_verified_contract", "get_contract_creation_info",
    "can_transfer_token", "get_ownership_info", "get_liquidity_info",
    "check_honeypot", "get_tax_info",
])
async def test_token_scanner_propagates_routing_error(mock_web3_client, method):
    getattr(mock_web3_client, method).side_effect = UnsupportedChainError("unsupported")
    with pytest.raises(UnsupportedChainError, match="unsupported"):
        await TokenScanner(mock_web3_client).check_token("0xABC")


@pytest.mark.asyncio
@pytest.mark.parametrize("method", [
    "is_contract", "is_verified_contract", "get_contract_creation_info", "get_bytecode",
])
async def test_transaction_scanner_propagates_routing_error(mock_web3_client, method):
    getattr(mock_web3_client, method).side_effect = UnsupportedChainError("unsupported")
    scanner = TransactionScanner(mock_web3_client)
    scanner.scam_db.check_address = AsyncMock(return_value=[])
    with pytest.raises(UnsupportedChainError, match="unsupported"):
        await scanner.scan_address("0xABC")


@pytest.mark.asyncio
async def test_transaction_scanner_propagates_database_routing_error(mock_web3_client):
    scanner = TransactionScanner(mock_web3_client)
    scanner.scam_db.check_address = AsyncMock(side_effect=UnsupportedChainError("unsupported"))
    with pytest.raises(UnsupportedChainError, match="unsupported"):
        await scanner.scan_address("0xABC")


@pytest.mark.asyncio
@pytest.mark.parametrize("scanner_type, entrypoint", [
    (TokenScanner, "check_token"), (TransactionScanner, "scan_address"),
])
@pytest.mark.parametrize("method", ["compute_ai_risk_score", "generate_forensic_report"])
async def test_scanners_propagate_ai_routing_error(
    mock_web3_client, mock_ai_analyzer, scanner_type, entrypoint, method,
):
    getattr(mock_ai_analyzer, method).side_effect = UnsupportedChainError("unsupported")
    scanner = scanner_type(mock_web3_client, mock_ai_analyzer)
    if isinstance(scanner, TransactionScanner):
        scanner.scam_db.check_address = AsyncMock(return_value=[])
    with pytest.raises(UnsupportedChainError, match="unsupported"):
        await getattr(scanner, entrypoint)("0xABC")


@pytest.mark.asyncio
@pytest.mark.parametrize("scanner_type, entrypoint, level_key, clean_level", [
    (TokenScanner, "check_token", "safety_level", "safe"),
    (TransactionScanner, "scan_address", "risk_level", "low"),
])
@pytest.mark.parametrize("unknown", ["verification", "age", "missing_age", "verification_failure", "age_failure"])
async def test_scanners_keep_metadata_unknown(
    mock_web3_client, scanner_type, entrypoint, level_key, clean_level, unknown,
):
    if unknown == "verification":
        mock_web3_client.is_verified_contract.return_value = (None, None)
    elif unknown == "age":
        mock_web3_client.get_contract_creation_info.return_value = {"age_days": None}
    elif unknown == "missing_age":
        mock_web3_client.get_contract_creation_info.return_value = None
    elif unknown == "verification_failure":
        mock_web3_client.is_verified_contract.side_effect = RuntimeError("unavailable")
    else:
        mock_web3_client.get_contract_creation_info.side_effect = RuntimeError("unavailable")
    scanner = scanner_type(mock_web3_client)
    if isinstance(scanner, TransactionScanner):
        scanner.scam_db.check_address = AsyncMock(return_value=[])
    result = await getattr(scanner, entrypoint)("0xABC")
    assert result["status"] == "unknown"
    assert result[level_key] != clean_level
    assert result["coverage_reasons"]
    assert result["risk_score"] == 0
    if unknown.startswith("verification"):
        assert result["is_verified"] is None
        assert result["coverage"]["is_verified"] is False
        assert not any("not verified" in warning for warning in result.get("warnings", []))
    else:
        assert result["contract_age_days"] is None
        assert result["coverage"]["contract_age_days"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("scanner_type, entrypoint", [
    (TokenScanner, "check_token"), (TransactionScanner, "scan_address"),
])
async def test_scanners_preserve_confirmed_unverified_penalty(mock_web3_client, scanner_type, entrypoint):
    mock_web3_client.is_verified_contract.return_value = (False, None)
    scanner = scanner_type(mock_web3_client)
    if isinstance(scanner, TransactionScanner):
        scanner.scam_db.check_address = AsyncMock(return_value=[])
    result = await getattr(scanner, entrypoint)("0xABC")
    assert result["is_verified"] is False
    assert result["risk_score"] == 25
    assert result["coverage"]["is_verified"] is True


@pytest.mark.asyncio
async def test_unknown_token_metadata_does_not_count_as_success(mock_web3_client):
    mock_web3_client.is_verified_contract.return_value = (None, None)
    result = {}
    assert await TokenScanner(mock_web3_client)._get_contract_metadata("0xABC", result) is False


@pytest.mark.asyncio
async def test_unknown_transaction_verification_does_not_count_as_success(mock_web3_client):
    mock_web3_client.is_verified_contract.return_value = (None, None)
    result = {"checks": {}, "warnings": []}
    assert await TransactionScanner(mock_web3_client)._check_verification("0xABC", result) is False
    assert result["checks"]["verified_source"] is None


@pytest.mark.asyncio
async def test_token_honeypot_with_unknown_age_remains_confirmed(mock_web3_client):
    mock_web3_client.check_honeypot.return_value = {"is_honeypot": True}
    mock_web3_client.get_contract_creation_info.return_value = {"age_days": None}
    result = await TokenScanner(mock_web3_client).check_token("0xABC")
    assert result["is_honeypot"] is True
    assert result["safety_level"] == "danger"
    assert result["status"] == "unknown"


@pytest.mark.asyncio
async def test_partial_honeypot_status_prevents_safe_token_result(mock_web3_client):
    mock_web3_client.check_honeypot.return_value = {
        "is_honeypot": False, "status": "unknown", "reason": "Sell simulation unavailable",
    }
    result = await TokenScanner(mock_web3_client).check_token("0xABC")
    assert result["status"] == "unknown"
    assert result["safety_level"] != "safe"
    assert result["checks"]["can_sell"] is None


@pytest.mark.asyncio
async def test_unknown_age_never_reaches_ai_as_low_risk(mock_web3_client, mock_ai_analyzer):
    mock_web3_client.get_contract_creation_info.return_value = {"age_days": None}
    scanner = TransactionScanner(mock_web3_client, mock_ai_analyzer)
    scanner.scam_db.check_address = AsyncMock(return_value=[])
    observed_levels = []

    async def inspect_scan(address, result):
        observed_levels.append((result["status"], result["risk_level"]))
        return {"risk_score": 0}

    mock_ai_analyzer.compute_ai_risk_score.side_effect = inspect_scan
    await scanner.scan_address("0xABC")
    mock_ai_analyzer.compute_ai_risk_score.assert_awaited_once()
    assert observed_levels == [("unknown", "unknown")]


def _complete_non_token_results(structural):
    from core.analyzer import AnalyzerResult

    return [
        structural,
        AnalyzerResult('market', .25, 0, data={'skipped': True}),
        AnalyzerResult('behavioral', .2, 0, data={'reputation_score': 80}),
        AnalyzerResult('honeypot', .15, 0, data={'skipped': True}),
    ]


@pytest.mark.asyncio
async def test_confirmed_eoa_structural_coverage_is_complete(mock_web3_client):
    from analyzers.structural import StructuralAnalyzer
    from core.analyzer import AnalysisContext
    from core.risk_engine import RiskEngine
    from services.contract_service import ContractService

    mock_web3_client.is_contract.return_value = False
    service = ContractService(mock_web3_client, MagicMock(check_address=AsyncMock(return_value=[])))
    structural = await StructuralAnalyzer(service).analyze(AnalysisContext('0xABC', is_token=False))
    assert structural.data['is_contract'] is False
    assert structural.data['status'] == 'ok'
    for entrypoint in ('direct', 'registry'):
        if entrypoint == 'direct':
            risk = RiskEngine().compute_composite_risk(
                await service.fetch_contract_data('0xABC'),
                {'is_honeypot': False, 'can_sell': True, 'buy_tax': 0, 'sell_tax': 0},
                {'liquidity_usd': 200000, 'pair_age_hours': 100}, {'reputation_score': 80},
                is_token=False,
            )
            assert risk['coverage']['structural'] == 1
            assert risk['status'] == 'ok'
            continue
        risk = RiskEngine().compute_from_results(_complete_non_token_results(structural), is_token=False)
        assert risk['rug_probability'] == 20
        assert risk['risk_level'] == 'LOW'
        assert risk['risk_archetype'] == 'legitimate'
        assert risk['status'] == 'ok'
        assert risk['coverage']['structural'] == 1


@pytest.mark.asyncio
async def test_failed_contract_lookup_is_unknown_not_confirmed_eoa(mock_web3_client):
    from analyzers.structural import StructuralAnalyzer
    from core.analyzer import AnalysisContext
    from core.risk_engine import RiskEngine
    from services.contract_service import ContractService

    mock_web3_client.is_contract.side_effect = RuntimeError('provider unavailable')
    service = ContractService(mock_web3_client, MagicMock(check_address=AsyncMock(return_value=[])))
    data = await service.fetch_contract_data('0xABC')
    assert data['is_contract'] is None
    assert data['status'] == 'unknown'
    assert data['reason']
    structural = await StructuralAnalyzer(service).analyze(AnalysisContext('0xABC', is_token=False))
    assert structural.data['status'] == 'unknown'
    assert 'No contract bytecode at address (destroyed or EOA)' not in structural.flags
    risk = RiskEngine().compute_from_results(_complete_non_token_results(structural), is_token=False)
    assert risk['status'] == 'unknown'
    assert risk['risk_level'] != 'LOW'
    assert risk['risk_archetype'] == 'unknown'
    assert risk['coverage']['structural'] < 1
    assert risk['coverage_reasons']['structural'] == data['reason']


@pytest.mark.asyncio
async def test_failed_bytecode_scan_is_unknown_not_clean_patterns(mock_web3_client):
    from analyzers.structural import StructuralAnalyzer
    from core.analyzer import AnalysisContext
    from core.risk_engine import RiskEngine
    from services.contract_service import ContractService

    mock_web3_client.get_bytecode.side_effect = RuntimeError('provider unavailable')
    service = ContractService(mock_web3_client, MagicMock(check_address=AsyncMock(return_value=[])))
    with patch('services.contract_service.BSCSCAN_DELAY', 0):
        data = await service.fetch_contract_data('0xABC')
        structural = await StructuralAnalyzer(service).analyze(AnalysisContext('0xABC', is_token=False))
    assert data['coverage'] == {'bytecode': False}
    assert data['reason'] == 'Bytecode scan unavailable'
    assert structural.data['status'] == 'unknown'
    assert structural.data['reason'] == 'Bytecode scan unavailable'
    direct = RiskEngine().compute_composite_risk(
        data, {'is_honeypot': False, 'can_sell': True, 'buy_tax': 0, 'sell_tax': 0},
        {'liquidity_usd': 200000, 'pair_age_hours': 100}, {'reputation_score': 80}, is_token=False,
    )
    registry = RiskEngine().compute_from_results(_complete_non_token_results(structural), is_token=False)
    for risk in (direct, registry):
        assert risk['status'] == 'unknown'
        assert risk['risk_level'] != 'LOW'
        assert risk['coverage']['structural'] < 1
        assert risk['coverage_reasons']['structural'] == 'Bytecode scan unavailable'


ALLOWANCE_SELECTOR = '0xdd62ed3e'
DEAD_TOKEN = '0x' + '4' * 40


def _use_real_rpc_batches(service, token, spender, eth_call):
    service._fetch_log_chunk.return_value = [
        {'address': address, 'topics': ['0x0', '0x0', spender], 'data': '0x1', 'blockNumber': '0x1'}
        for address in (token, DEAD_TOKEN)
    ]
    del service._verify_allowances
    del service._fetch_balances
    service._eth_call = AsyncMock(side_effect=eth_call)


@pytest.mark.asyncio
async def test_rescue_empty_eth_call_result_is_none(rescue_pipeline):
    from services.rescue_service import RescueService

    service, _, token, _, session = rescue_pipeline
    response = session.post.return_value.__aenter__.return_value
    response.status = 200
    response.json.return_value = {'result': '0x'}
    assert await RescueService._eth_call(service, session, 'https://rpc.invalid', token, '0x0') is None


@pytest.mark.asyncio
async def test_rescue_empty_allowance_marks_pair_unknown_without_aborting(rescue_pipeline):
    service, wallet, token, spender, _ = rescue_pipeline
    _use_real_rpc_batches(
        service, token, spender,
        lambda session, rpc_url, to, data: None if to == DEAD_TOKEN else 1,
    )
    service._fetch_prices.return_value = {token: 1.0}
    result = await service.scan_approvals(wallet)
    assert [approval['token_address'] for approval in result['approvals']] == [token]
    assert all(approval['risk_level'] in ('HIGH', 'MEDIUM', 'LOW') for approval in result['approvals'])
    assert result['status'] == 'unknown'
    assert result['coverage'] == {'allowances': False, 'balances': True, 'prices': True}
    assert set(result['coverage_reasons']) == {'allowances'}
    assert result['total_value_at_risk_usd'] is None


@pytest.mark.asyncio
async def test_rescue_empty_balance_marks_value_unknown(rescue_pipeline):
    service, wallet, token, spender, _ = rescue_pipeline
    _use_real_rpc_batches(
        service, token, spender,
        lambda session, rpc_url, to, data: 1 if data.startswith(ALLOWANCE_SELECTOR) or to != DEAD_TOKEN else None,
    )
    service._fetch_prices.return_value = {token: 1.0, DEAD_TOKEN: 1.0}
    result = await service.scan_approvals(wallet)
    assert sorted(approval['token_address'] for approval in result['approvals']) == sorted([token, DEAD_TOKEN])
    assert result['status'] == 'unknown'
    assert result['coverage'] == {'allowances': True, 'balances': False, 'prices': True}
    assert result['total_value_at_risk_usd'] is None


@pytest.mark.asyncio
async def test_rescue_price_failure_is_not_zero_value_at_risk(rescue_pipeline):
    service, wallet, _, _, session = rescue_pipeline
    session.get.side_effect = RuntimeError('price provider unavailable')
    del service._fetch_prices
    result = await service.scan_approvals(wallet)
    assert result['total_approvals'] == 1
    assert result['status'] == 'unknown'
    assert result['coverage'] == {'allowances': True, 'balances': True, 'prices': False}
    assert result['coverage_reasons']['prices']
    assert result['total_value_at_risk_usd'] is None


@pytest.mark.asyncio
@pytest.mark.parametrize('balance, priced', [(1, True), (0, False)])
async def test_rescue_complete_scan_reports_ok_coverage(rescue_pipeline, balance, priced):
    # With a zero balance nothing is at risk, so a missing price leaves the value known.
    service, wallet, token, _, _ = rescue_pipeline
    service._fetch_balances.return_value = {token: balance}
    service._fetch_prices.return_value = {token: 2.0} if priced else {}
    result = await service.scan_approvals(wallet)
    assert result['status'] == 'ok'
    assert result['coverage'] == {'allowances': True, 'balances': True, 'prices': True}
    assert result['coverage_reasons'] == {}
    assert result['total_value_at_risk_usd'] == 0.0


def test_guardian_router_unavailable_approvals_return_503_without_provider_details():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from services.guardian import GuardianService
    from services.guardian_router import create_guardian_router

    rescue = MagicMock(scan_approvals=AsyncMock(
        side_effect=RuntimeError('Log chunk failed for https://rpc.invalid/secret-key'),
    ))
    container = MagicMock()
    container.auth_manager.validate_key = AsyncMock(return_value={'key_id': 'test-key'})
    container.guardian_service = GuardianService(MagicMock(), rescue_service=rescue)
    app = FastAPI()
    app.include_router(create_guardian_router(container), prefix='/api/guardian')
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get('/api/guardian/approvals/0x' + '1' * 40, headers={'X-API-Key': 'test-key'})
    assert response.status_code == 503
    assert response.json() == {'detail': 'Approval data unavailable'}


@pytest.mark.asyncio
async def test_transaction_scanner_confirmed_eoa_carries_complete_coverage(mock_web3_client):
    from core.extension_formatter import format_extension_alert, is_scan_incomplete

    mock_web3_client.is_contract.return_value = False
    scanner = TransactionScanner(mock_web3_client)
    scanner.scam_db.check_address = AsyncMock(return_value=[])
    result = await scanner.scan_address("0xABC")
    assert result["risk_level"] == "low"
    assert result["status"] == "ok"
    assert result["coverage"] == {"is_contract": True, "scam_database": True}
    assert result["coverage_reasons"] == {}
    assert not is_scan_incomplete(result)
    alert = format_extension_alert({**result, "rug_probability": result["risk_score"]})
    assert (alert["risk_classification"], alert["status"], alert["risk_display"]) == ("SAFE", "ok", "5%")


@pytest.mark.asyncio
async def test_rescue_all_empty_allowances_are_unknown_not_clean(rescue_pipeline):
    service, wallet, token, spender, _ = rescue_pipeline
    _use_real_rpc_batches(service, token, spender, lambda session, rpc_url, to, data: None)
    result = await service.scan_approvals(wallet)
    assert result['total_approvals'] == 0
    assert result['status'] == 'unknown'
    assert result['coverage']['allowances'] is False
    assert result['total_value_at_risk_usd'] is None


SYNTHETIC_KEY = 'SYNTHETIC-KEY-7f3a91'
LEAKY_ERROR = f'request to https://rpc.invalid/v1/{SYNTHETIC_KEY} failed'


def _assert_no_secret_logged(caplog):
    assert any(record.levelno >= logging.DEBUG for record in caplog.records)
    assert SYNTHETIC_KEY not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize('scanner_type, entrypoint, target, method', [
    *[(TokenScanner, 'check_token', 'web3', method) for method in (
        'get_token_info', 'is_verified_contract', 'can_transfer_token', 'get_ownership_info',
        'get_liquidity_info', 'check_honeypot', 'get_tax_info',
    )],
    *[(TransactionScanner, 'scan_address', 'web3', method) for method in (
        'is_verified_contract', 'get_contract_creation_info', 'get_bytecode',
    )],
    (TransactionScanner, 'scan_address', 'scam_db', 'check_address'),
    *[(scanner_type, entrypoint, 'ai', method)
      for scanner_type, entrypoint in ((TokenScanner, 'check_token'), (TransactionScanner, 'scan_address'))
      for method in ('compute_ai_risk_score', 'generate_forensic_report')],
])
async def test_scanner_provider_errors_do_not_log_secrets(
    mock_web3_client, mock_ai_analyzer, caplog, scanner_type, entrypoint, target, method,
):
    scanner = scanner_type(mock_web3_client, mock_ai_analyzer)
    if isinstance(scanner, TransactionScanner):
        scanner.scam_db.check_address = AsyncMock(return_value=[])
    targets = {'web3': mock_web3_client, 'ai': mock_ai_analyzer, 'scam_db': getattr(scanner, 'scam_db', None)}
    getattr(targets[target], method).side_effect = RuntimeError(LEAKY_ERROR)
    with caplog.at_level(logging.DEBUG):
        result = await getattr(scanner, entrypoint)('0xABC')
    _assert_no_secret_logged(caplog)
    assert SYNTHETIC_KEY not in repr(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['check_honeypot', 'get_tax_info', 'goplus'])
async def test_honeypot_service_provider_errors_do_not_log_secrets(mock_web3_client, caplog, method):
    from services.honeypot_service import HoneypotService

    mock_web3_client.get_supported_chain_ids.return_value = [56]
    fallback = AsyncMock(return_value={'data': {}, 'reason': None})
    if method == 'goplus':
        mock_web3_client.check_honeypot.return_value = {}
        fallback.side_effect = RuntimeError(LEAKY_ERROR)
    else:
        getattr(mock_web3_client, method).side_effect = RuntimeError(LEAKY_ERROR)
    with patch('services.honeypot_service.ScamDatabase.fetch_token_security', fallback):
        with caplog.at_level(logging.DEBUG):
            data = await HoneypotService(mock_web3_client).fetch_honeypot_data('0xABC')
    _assert_no_secret_logged(caplog)
    assert SYNTHETIC_KEY not in repr(data)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['get_bytecode', 'is_verified_contract'])
async def test_contract_service_provider_errors_do_not_log_secrets(mock_web3_client, caplog, method):
    from services.contract_service import ContractService

    getattr(mock_web3_client, method).side_effect = RuntimeError(LEAKY_ERROR)
    service = ContractService(mock_web3_client, MagicMock(check_address=AsyncMock(return_value=[])))
    with patch('services.contract_service.BSCSCAN_DELAY', 0), caplog.at_level(logging.DEBUG):
        data = await service.fetch_contract_data('0xABC')
    _assert_no_secret_logged(caplog)
    assert SYNTHETIC_KEY not in repr(data)


@pytest.mark.asyncio
async def test_rescue_and_guardian_provider_errors_do_not_log_secrets(rescue_pipeline, caplog):
    from services.guardian import GuardianService

    service, wallet, _, _, session = rescue_pipeline
    session.post.side_effect = RuntimeError(LEAKY_ERROR)
    with caplog.at_level(logging.DEBUG):
        health = await GuardianService(MagicMock(), rescue_service=service).get_health(wallet, 56)
    assert health['status'] == 'unknown'
    _assert_no_secret_logged(caplog)


@pytest.mark.asyncio
async def test_registry_analyzer_errors_do_not_leak_secrets(caplog):
    from core.analyzer import AnalysisContext
    from core.registry import AnalyzerRegistry
    from core.risk_engine import RiskEngine

    analyzer = MagicMock()
    analyzer.name = 'structural'
    analyzer.weight = 1
    analyzer.analyze = AsyncMock(side_effect=RuntimeError(LEAKY_ERROR))
    registry = AnalyzerRegistry()
    registry.register(analyzer)
    with caplog.at_level(logging.DEBUG):
        results = await registry.run_all(AnalysisContext('0xABC'))
    risk = RiskEngine().compute_from_results(results, is_token=False)
    _assert_no_secret_logged(caplog)
    assert results[0].error
    assert SYNTHETIC_KEY not in repr(results)
    assert SYNTHETIC_KEY not in repr(risk)


@pytest.mark.asyncio
async def test_indexer_provider_errors_do_not_log_secrets(caplog):
    from types import SimpleNamespace
    from core.indexer import DeployerIndexer

    indexer = DeployerIndexer(MagicMock(), MagicMock(), SimpleNamespace(
        telegram_bot_token=SYNTHETIC_KEY, telegram_alert_chat_id='1',
    ))

    async def failing_index(address, chain_id):
        indexer._running = False
        raise RuntimeError(LEAKY_ERROR)

    indexer._index_contract = failing_index
    indexer._running = True
    indexer.enqueue('0xABC', 56)
    with patch('aiohttp.ClientSession', side_effect=RuntimeError(LEAKY_ERROR)), caplog.at_level(logging.DEBUG):
        assert await indexer._send_watch_alert('0x' + '1' * 40, 56, '0xABC', {}) is False
        await indexer._worker()
    _assert_no_secret_logged(caplog)


@pytest.mark.asyncio
async def test_mempool_poll_errors_do_not_log_secrets(mock_web3_client, caplog):
    from services.mempool_service import MempoolMonitor

    monitor = MempoolMonitor(mock_web3_client)
    monitor._get_txpool_content = AsyncMock(side_effect=RuntimeError(LEAKY_ERROR))
    with caplog.at_level(logging.DEBUG):
        await monitor._poll_pending(56)
    _assert_no_secret_logged(caplog)


PROVIDER_PATH_MODULES = [
    'adapters/evm_base.py',
    'core/auth.py',
    'core/indexer.py',
    'core/registry.py',
    'scanner/token_scanner.py',
    'scanner/transaction_scanner.py',
    'rpc/router.py',
    'services/cache.py',
    'services/contract_service.py',
    'services/dex_service.py',
    'services/email_service.py',
    'services/ethos_service.py',
    'services/greenfield_service.py',
    'services/guardian.py',
    'services/honeypot_service.py',
    'services/injection_scanner.py',
    'services/launch_discovery.py',
    'services/mempool_service.py',
    'services/phishing_service.py',
    'services/rescue_service.py',
    'services/reputation.py',
    'services/robinhood_simulation.py',
    'services/tenderly_service.py',
    'services/token_gate_service.py',
    'services/token_sniffer_service.py',
    'services/verdict_publisher.py',
]


def _is_logger_call(node):
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name) and node.func.value.id == 'logger'
    )


def _logged_exception_lines(source):
    tree = ast.parse(source)
    lines = {call.lineno for call in ast.walk(tree) if _is_logger_call(call) and call.func.attr == 'exception'}
    for handler in ast.walk(tree):
        if not isinstance(handler, ast.ExceptHandler) or not handler.name:
            continue
        for call in filter(_is_logger_call, ast.walk(handler)):
            for value in [*call.args, *(keyword.value for keyword in call.keywords)]:
                allowed = {
                    id(inner) for node in ast.walk(value)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'type'
                    for inner in node.args
                } | {
                    id(node.value) for node in ast.walk(value)
                    if isinstance(node, ast.Attribute) and node.attr == '__traceback__'
                }
                if any(
                    isinstance(node, ast.Name) and node.id == handler.name and id(node) not in allowed
                    for node in ast.walk(value)
                ):
                    lines.add(call.lineno)
    return sorted(lines)


def test_logging_guard_flags_keywords_and_logger_exception():
    source = '''
try:
    pass
except Exception as exc:
    logger.error("failed: %s", type(exc).__name__, exc_info=True)
    logger.error("failed", exc_info=exc)
    logger.error("failed", extra={"error": exc})
    logger.exception("failed")
    logger.error("failed: %s", "".join(traceback.format_tb(exc.__traceback__)))
    logger.error("failed: %s", exc.args)
'''
    assert _logged_exception_lines(source) == [6, 7, 8, 10]


@pytest.mark.parametrize('module', PROVIDER_PATH_MODULES)
def test_provider_path_logs_record_exception_class_not_text(module):
    root = Path(__file__).resolve().parent.parent
    assert _logged_exception_lines((root / module).read_text(encoding='utf-8')) == []


@pytest.mark.asyncio
async def test_reputation_batch_lookup_does_not_leak_provider_errors(caplog):
    from services.reputation import ReputationService

    service = ReputationService(MagicMock())
    service.get_trust_score = AsyncMock(side_effect=RuntimeError(LEAKY_ERROR))
    with caplog.at_level(logging.DEBUG):
        results = await service.batch_lookup(['agent-1'])
    _assert_no_secret_logged(caplog)
    assert results == [{'agent_id': 'agent-1', 'error': 'RuntimeError'}]


@pytest.mark.parametrize('priced', [False, True])
def test_guardian_router_returns_known_approvals_with_scan_coverage(rescue_pipeline, priced):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from services.guardian import GuardianService
    from services.guardian_router import create_guardian_router

    service, wallet, token, spender, _ = rescue_pipeline
    service._verify_allowances.return_value = {(token, spender): 2 ** 128}
    service._fetch_prices.return_value = {token: 1.0} if priced else {}
    container = MagicMock()
    container.auth_manager.validate_key = AsyncMock(return_value={'key_id': 'test-key'})
    container.guardian_service = GuardianService(
        MagicMock(get_contract_score=AsyncMock(return_value=None)), rescue_service=service,
    )
    app = FastAPI()
    app.include_router(create_guardian_router(container), prefix='/api/guardian')
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get(f'/api/guardian/approvals/{wallet}', headers={'X-API-Key': 'test-key'})
    assert response.status_code == 200
    body = response.json()
    assert [approval['risk_level'] for approval in body['approvals']] == ['high']
    assert body['status'] == ('ok' if priced else 'unknown')
    assert body['coverage']['prices'] is priced
    assert ('prices' in body['coverage_reasons']) is (not priced)


@pytest.mark.asyncio
async def test_unknown_contract_lookup_is_not_a_confirmed_eoa(mock_web3_client):
    from analyzers.structural import StructuralAnalyzer
    from core.analyzer import AnalysisContext
    from services.contract_service import ContractService

    mock_web3_client.is_contract.return_value = None
    service = ContractService(mock_web3_client, MagicMock(check_address=AsyncMock(return_value=[])))
    data = await service.fetch_contract_data('0xABC')
    assert data['is_contract'] is None
    assert data['status'] == 'unknown'
    assert data['reason'] == 'Contract data unavailable'
    structural = await StructuralAnalyzer(service).analyze(AnalysisContext('0xABC', is_token=False))
    assert structural.data['status'] == 'unknown'
    assert 'No contract bytecode at address (destroyed or EOA)' not in structural.flags


@pytest.mark.asyncio
async def test_transaction_scanner_unknown_contract_lookup_is_not_low_risk(mock_web3_client):
    mock_web3_client.is_contract.return_value = None
    scanner = TransactionScanner(mock_web3_client)
    scanner.scam_db.check_address = AsyncMock(return_value=[])
    result = await scanner.scan_address("0xABC")
    assert result["is_contract"] is None
    assert result["status"] == "unknown"
    assert result["risk_level"] == "unknown"
    assert result["confidence"] != 95
    assert result["coverage"] == {"is_contract": False, "scam_database": True}
    assert result["coverage_reasons"]["is_contract"]
    assert not any("EOA" in warning for warning in result["warnings"])


@pytest.mark.asyncio
@pytest.mark.parametrize('bytecode, unavailable', [(None, True), ('', False), ('0x', False)])
async def test_missing_bytecode_is_unknown_but_empty_code_is_observed(mock_web3_client, bytecode, unavailable):
    from analyzers.structural import StructuralAnalyzer
    from core.analyzer import AnalysisContext
    from services.contract_service import ContractService

    mock_web3_client.get_bytecode.return_value = bytecode
    service = ContractService(mock_web3_client, MagicMock(check_address=AsyncMock(return_value=[])))
    with patch('services.contract_service.BSCSCAN_DELAY', 0):
        data = await service.fetch_contract_data('0xABC')
        structural = await StructuralAnalyzer(service).analyze(AnalysisContext('0xABC', is_token=False))
    if unavailable:
        assert data['coverage'] == {'bytecode': False}
        assert data['reason'] == 'Bytecode scan unavailable'
        assert structural.data['status'] == 'unknown'
    else:
        assert 'coverage' not in data
        assert structural.data['status'] == 'ok'
    assert data['bytecode_warnings'] == []


@pytest.mark.asyncio
async def test_rescue_unknown_balance_without_price_marks_prices_unknown(rescue_pipeline):
    service, wallet, token, spender, _ = rescue_pipeline
    _use_real_rpc_batches(
        service, token, spender,
        lambda session, rpc_url, to, data: 1 if data.startswith(ALLOWANCE_SELECTOR) or to != DEAD_TOKEN else None,
    )
    service._fetch_prices.return_value = {token: 1.0}
    result = await service.scan_approvals(wallet)
    assert result['coverage'] == {'allowances': True, 'balances': False, 'prices': False}
    assert set(result['coverage_reasons']) == {'balances', 'prices'}


SCAM_MATCH = {'type': 'Local Blacklist', 'reason': 'Known scam address', 'source': 'ShieldBot'}


async def _scan_without_contract_checks(mock_web3_client, is_contract, scam_lookup):
    mock_web3_client.is_contract.return_value = is_contract
    scanner = TransactionScanner(mock_web3_client)
    scanner.scam_db.check_address = scam_lookup
    return await scanner.scan_address("0xABC")


@pytest.mark.asyncio
@pytest.mark.parametrize("is_contract", [None, False])
async def test_scam_database_hit_is_flagged_without_contract_checks(mock_web3_client, is_contract):
    result = await _scan_without_contract_checks(
        mock_web3_client, is_contract, AsyncMock(return_value=[SCAM_MATCH]),
    )
    assert result["scam_matches"] == [SCAM_MATCH]
    assert result["checks"]["scam_database_clean"] is False
    assert "Found 1 scam database match(es)" in result["warnings"]
    assert result["risk_score"] == 40
    assert result["risk_level"] == "medium"
    if is_contract is None:
        assert result["status"] == "unknown"
        assert result["coverage"] == {"is_contract": False, "scam_database": True}
    else:
        assert result["status"] == "ok"
        assert result["coverage"] == {"is_contract": True, "scam_database": True}
        assert result["confidence"] == 95
    mock_web3_client.get_bytecode.assert_not_awaited()


@pytest.mark.asyncio
async def test_confirmed_eoa_without_scam_hit_is_unchanged(mock_web3_client):
    lookup = AsyncMock(return_value=[])
    result = await _scan_without_contract_checks(mock_web3_client, False, lookup)
    lookup.assert_awaited_once_with("0xABC", chain_id=56)
    assert (result["risk_level"], result["risk_score"], result["confidence"]) == ("low", 5, 95)
    assert (result["status"], result["coverage"], result["coverage_reasons"]) == (
        "ok", {"is_contract": True, "scam_database": True}, {},
    )
    assert result["warnings"] == ["This is an EOA (externally owned account), not a contract"]
    assert result["scam_matches"] == []


@pytest.mark.asyncio
async def test_confirmed_eoa_with_failed_scam_lookup_is_unknown(mock_web3_client):
    result = await _scan_without_contract_checks(
        mock_web3_client, False, AsyncMock(side_effect=RuntimeError("scam database unavailable")),
    )
    assert result["status"] == "unknown"
    assert result["risk_level"] == "unknown"
    assert result["confidence"] != 95
    assert result["coverage"] == {"is_contract": True, "scam_database": False}
    assert result["coverage_reasons"]["scam_database"]
    assert result["checks"]["scam_database_clean"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("scam_matches, expected", [([], (4, "low")), ([SCAM_MATCH], (40, "medium"))])
async def test_ai_blend_cannot_lower_scam_match_below_its_floor(mock_web3_client, mock_ai_analyzer, scam_matches, expected):
    mock_web3_client.get_contract_creation_info.return_value = {"age_days": 400}
    mock_ai_analyzer.compute_ai_risk_score.return_value = {"risk_score": 10}
    scanner = TransactionScanner(mock_web3_client, mock_ai_analyzer)
    scanner.scam_db.check_address = AsyncMock(return_value=scam_matches)
    result = await scanner.scan_address("0xABC")
    assert result["status"] == "ok"
    assert result["is_verified"] is True
    assert (result["risk_score"], result["risk_level"]) == expected
