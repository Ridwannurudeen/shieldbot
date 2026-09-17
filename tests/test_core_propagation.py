"""Regression tests for core routing and incomplete provider coverage."""

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
@pytest.mark.parametrize('entrypoint', ['_get_approval_data', 'get_approvals', 'get_health'])
async def test_guardian_propagates_rescue_routing_error(entrypoint):
    from services.guardian import GuardianService

    db = MagicMock(update_guardian_health=AsyncMock())
    rescue = MagicMock(scan_approvals=AsyncMock(side_effect=UnsupportedChainError('unsupported')))
    with pytest.raises(UnsupportedChainError, match='unsupported'):
        await getattr(GuardianService(db, rescue_service=rescue), entrypoint)('0xABC', 56)
    db.update_guardian_health.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('entrypoint, method', [
    ('_get_approval_data', 'get_contract_score'),
    ('_check_flagged_exposure_from_tokens', 'get_contract_score'),
    ('_check_deployer_risk_from_tokens', 'get_deployer'),
    ('_check_deployer_risk_from_tokens', 'get_watched_deployer'),
])
async def test_guardian_nested_routing_error_propagates(entrypoint, method):
    from services.guardian import GuardianService

    db = MagicMock(
        get_contract_score=AsyncMock(return_value=None),
        get_deployer=AsyncMock(return_value={'deployer_address': '0xDeployer'}),
        get_watched_deployer=AsyncMock(return_value=None),
    )
    getattr(db, method).side_effect = UnsupportedChainError('unsupported')
    rescue = MagicMock(scan_approvals=AsyncMock(return_value={'approvals': [{'spender': '0xSpender'}]}))
    argument = '0xABC' if entrypoint == '_get_approval_data' else ['0xABC']
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
@pytest.mark.parametrize('method', ['is_token_contract', 'can_transfer_token'])
async def test_web3_rpc_catches_propagate_routing_error(method):
    from utils.web3_client import Web3Client

    client = Web3Client.__new__(Web3Client)
    client.erc20_abi = []
    client.get_web3 = MagicMock()
    client.get_web3.return_value.eth.contract.side_effect = UnsupportedChainError('unsupported')
    with pytest.raises(UnsupportedChainError, match='unsupported'):
        await getattr(client, method)('0x' + '1' * 40)


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
