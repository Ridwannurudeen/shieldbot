"""Offline regressions for coverage-aware product consumers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine


@pytest.fixture(params=[False, True], ids=['missing-provider', 'failed-simulation'])
def incomplete_output(request):
    data = {
        'is_honeypot': None, 'can_sell': None, 'buy_tax': None, 'sell_tax': None,
        'status': 'unknown', 'simulation_failed': request.param,
    }
    output = RiskEngine().compute_from_results([
        AnalyzerResult('structural', 0.0, 0, data={'is_contract': True}),
        AnalyzerResult('honeypot', 1.0, 0, data=data),
    ])
    return output


@pytest.fixture
def consumer_api(monkeypatch, mock_web3_client):
    import api
    mock_web3_client.is_token_contract = AsyncMock(return_value=True)
    mock_web3_client.is_verified_contract.return_value = (None, 'unavailable')
    db = SimpleNamespace(
        get_contract_score=AsyncMock(return_value=None),
        get_deployer_risk_summary=AsyncMock(return_value=None),
        upsert_contract_score=AsyncMock(),
    )
    services = SimpleNamespace(
        web3_client=mock_web3_client, db=db,
        registry=SimpleNamespace(run_all=AsyncMock(return_value=[])),
        policy_engine=None, indexer=None, settings=SimpleNamespace(policy_mode='BALANCED'),
    )
    monkeypatch.setattr(api, 'container', services)
    monkeypatch.setattr(api, 'web3_client', mock_web3_client)
    monkeypatch.setattr(api, 'calldata_decoder', SimpleNamespace(
        decode=lambda _: {'selector': None}, is_whitelisted_target=lambda *args, **kwargs: None,
    ))
    monkeypatch.setattr(api, 'risk_engine', MagicMock())
    monkeypatch.setattr(api, 'tenderly_simulator', SimpleNamespace(is_enabled=lambda: False))
    monkeypatch.setattr(api, 'greenfield_service', None)
    monkeypatch.setattr(api, 'ai_analyzer', SimpleNamespace(is_available=lambda: False))
    return api, services


def assert_unknown_response(response):
    assert response['classification'] != 'SAFE'
    assert response['status'] == 'unknown'
    assert response['partial'] is True
    assert 'Unknown' in response['risk_display']
    assert '0%' not in response['verdict']
    assert response['coverage_reasons']


def test_fallback_preserves_unknowns(consumer_api, incomplete_output):
    api, _ = consumer_api
    scan = dict(incomplete_output, risk_score=0, is_honeypot=None, is_verified=None)
    response = api._build_fallback_response({}, scan, None, 56)
    assert_unknown_response(response)
    assert response['raw_checks']['is_honeypot'] is None
    assert response['raw_checks']['is_verified'] is None
    assert response['raw_checks']['ownership_renounced'] is None
    assert not any('not verified' in flag for flag in response['danger_signals'])


@pytest.mark.asyncio
async def test_fresh_response_persists_unknowns(consumer_api, incomplete_output):
    api, services = consumer_api
    api.risk_engine.compute_from_results.return_value = incomplete_output
    response = await api.firewall(
        api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40),
        SimpleNamespace(headers={}),
    )
    assert_unknown_response(response)
    assert response['shield_score']['status'] == 'unknown'
    stored = services.db.upsert_contract_score.call_args.kwargs
    metadata = stored['category_scores']['_scan_metadata']
    assert metadata['status'] == 'unknown'
    assert metadata['coverage'] == incomplete_output['coverage']
    assert services.registry.run_all.call_args.args[0].extra['is_verified'] is None


@pytest.mark.asyncio
@pytest.mark.parametrize('identification', [True, False, None, 'error'])
async def test_fresh_response_preserves_token_identification(consumer_api, incomplete_output, identification):
    api, services = consumer_api
    api.web3_client.is_token_contract.return_value = identification
    if identification == 'error':
        api.web3_client.is_token_contract.side_effect = TimeoutError('RPC unavailable')
    api.risk_engine.compute_from_results.return_value = incomplete_output
    response = await api.firewall(
        api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40),
        SimpleNamespace(headers={}),
    )
    expected = None if identification == 'error' else identification
    assert services.registry.run_all.call_args.args[0].is_token is expected
    assert api.risk_engine.compute_from_results.call_args.kwargs['is_token'] is expected
    assert_unknown_response(response)


@pytest.mark.asyncio
@pytest.mark.parametrize('identification', [True, False, None, 'error'])
async def test_legacy_firewall_only_skips_token_scan_for_confirmed_non_token(
    consumer_api, incomplete_output, monkeypatch, identification,
):
    api, services = consumer_api
    services.registry.run_all.side_effect = RuntimeError('pipeline unavailable')
    api.web3_client.is_token_contract.return_value = identification
    if identification == 'error':
        api.web3_client.is_token_contract.side_effect = TimeoutError('RPC unavailable')
    scan = dict(incomplete_output, risk_score=0)
    token_scan = AsyncMock(return_value=dict(scan))
    contract_scan = AsyncMock(return_value=dict(scan))
    monkeypatch.setattr(api, 'token_scanner', SimpleNamespace(check_token=token_scan))
    monkeypatch.setattr(api, 'tx_scanner', SimpleNamespace(scan_address=contract_scan))
    response = await api.firewall(
        api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40),
        SimpleNamespace(headers={}),
    )
    assert token_scan.await_count == int(identification is not False)
    assert contract_scan.await_count == int(identification is False)
    assert_unknown_response(response)


@pytest.mark.asyncio
@pytest.mark.parametrize('identification', [True, False, None])
async def test_bot_only_skips_token_scan_for_confirmed_non_token(identification):
    import ast
    from pathlib import Path

    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    handler = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
                   and node.name == 'handle_address')
    namespace = {
        'Update': object, 'ContextTypes': SimpleNamespace(DEFAULT_TYPE=object),
        'parse_chain_prefix': lambda text: (None, text),
        '_get_user_chain_id': lambda context: 56, 'get_chain_name': lambda chain_id: 'BSC',
        'web3_client': SimpleNamespace(is_token_contract=AsyncMock(return_value=identification)),
        'check_token': AsyncMock(), 'scan_contract': AsyncMock(),
    }
    exec(compile(ast.Module(body=[handler], type_ignores=[]), 'bot.py', 'exec'), namespace)
    status = SimpleNamespace(edit_text=AsyncMock())
    update = SimpleNamespace(message=SimpleNamespace(
        text='0x' + 'a' * 40, reply_text=AsyncMock(return_value=status),
    ))
    await namespace['handle_address'](update, SimpleNamespace(user_data={}))
    assert namespace['check_token'].await_count == int(identification is not False)
    assert namespace['scan_contract'].await_count == int(identification is False)
    if identification is None:
        assert 'Detected token' not in status.edit_text.call_args.args[0]


@pytest.mark.asyncio
@pytest.mark.parametrize('identification', [True, False, None, 'error'])
async def test_rpc_preserves_token_identification(mock_web3_client, identification):
    from rpc.proxy import RPCProxy

    mock_web3_client.is_token_contract = AsyncMock(return_value=identification)
    if identification == 'error':
        mock_web3_client.is_token_contract.side_effect = TimeoutError('RPC unavailable')
    services = SimpleNamespace(
        web3_client=mock_web3_client,
        registry=SimpleNamespace(run_all=AsyncMock(return_value=[])),
        risk_engine=MagicMock(),
    )
    services.risk_engine.compute_from_results.return_value = {
        'risk_level': 'HIGH', 'rug_probability': 95,
    }
    response = await RPCProxy(services).handle_request(56, {
        'jsonrpc': '2.0', 'id': 1, 'method': 'eth_sendTransaction',
        'params': [{'to': '0x' + 'a' * 40, 'from': '0x' + 'b' * 40}],
    })
    expected = None if identification == 'error' else identification
    assert services.registry.run_all.call_args.args[0].is_token is expected
    assert services.risk_engine.compute_from_results.call_args.kwargs['is_token'] is expected
    assert response['error']['code'] == -32003


@pytest.mark.asyncio
async def test_legacy_cache_row_is_rescanned(consumer_api, incomplete_output):
    api, services = consumer_api
    services.db.get_contract_score.return_value = {'risk_score': 0, 'risk_level': 'UNKNOWN'}
    api.risk_engine.compute_from_results.return_value = incomplete_output
    response = await api.firewall(
        api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40),
        SimpleNamespace(headers={}),
    )
    services.registry.run_all.assert_awaited_once()
    assert_unknown_response(response)


def test_cached_response_preserves_unknowns(consumer_api, incomplete_output):
    api, _ = consumer_api
    cached = {
        'risk_score': 0, 'risk_level': 'UNKNOWN',
        'category_scores': {'honeypot': None, '_scan_metadata': {
            key: incomplete_output[key] for key in ('status', 'coverage', 'coverage_reasons')
        }},
    }
    response = api._build_cached_response(cached, {}, 0)
    assert_unknown_response(response)
    assert '_scan_metadata' not in response['shield_score']['category_scores']
    assert '_scan_metadata' in cached['category_scores']


@pytest.mark.asyncio
async def test_swap_aggregates_middle_token_coverage(consumer_api, incomplete_output):
    api, services = consumer_api
    complete = dict(incomplete_output, rug_probability=10, risk_level='LOW', status='ok',
                    coverage={'honeypot': 1}, coverage_reasons={}, critical_flags=[])
    api.risk_engine.compute_from_results.side_effect = [complete, incomplete_output, complete]
    path = ['0x' + char * 40 for char in 'cde']
    req = api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40)
    response = await api._analyze_router_swap(req, req.to, req.sender, {'params': {'path': path}}, 'Router', 0)
    assert_unknown_response(response)
    assert response['risk_score'] == 10
    assert response['shield_score']['risk_level'] != 'LOW'
    summaries = response['raw_checks']['tokens_analyzed']
    assert len(summaries) == 3
    assert summaries[1]['status'] == 'unknown'
    assert summaries[1]['coverage'] == incomplete_output['coverage']
    assert services.registry.run_all.await_count == 3


@pytest.mark.asyncio
async def test_unknown_fallback_cannot_be_overruled_by_ai(consumer_api, incomplete_output, monkeypatch):
    api, services = consumer_api
    services.registry.run_all.side_effect = RuntimeError('provider unavailable')
    monkeypatch.setattr(api, 'token_scanner', SimpleNamespace(check_token=AsyncMock(return_value={
        **incomplete_output, 'risk_score': 0, 'is_honeypot': None,
    })))
    monkeypatch.setattr(api, 'ai_analyzer', SimpleNamespace(
        is_available=lambda: True,
        generate_firewall_report=AsyncMock(return_value={'classification': 'SAFE', 'verdict': 'Safe'}),
    ))
    response = await api.firewall(
        api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40),
        SimpleNamespace(headers={}),
    )
    assert_unknown_response(response)


def test_covered_cache_keeps_safe(consumer_api):
    api, _ = consumer_api
    response = api._build_cached_response({
        'risk_score': 0, 'risk_level': 'LOW',
        'category_scores': {'honeypot': 0, '_scan_metadata': {
            'status': 'ok', 'coverage': {'honeypot': 1}, 'coverage_reasons': {},
        }},
    }, {}, 0)
    assert response['classification'] == 'SAFE'
    assert response['risk_display'] == '0%'
    assert response['partial'] is False


@pytest.mark.asyncio
@pytest.mark.parametrize('surface', ['fresh', 'swap'])
async def test_failed_transaction_simulation_is_incomplete(consumer_api, surface):
    api, services = consumer_api
    api.risk_engine.compute_from_results.return_value = {
        'rug_probability': 0, 'risk_level': 'LOW', 'status': 'ok',
        'coverage': {'honeypot': 1}, 'coverage_reasons': {},
    }
    api.tenderly_simulator.is_enabled = lambda: True
    api.tenderly_simulator.simulate_transaction = AsyncMock(return_value={
        'success': False, 'revert_reason': 'simulation failed',
    })
    req = api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40)
    if surface == 'fresh':
        response = await api.firewall(req, SimpleNamespace(headers={}))
    else:
        response = await api._analyze_router_swap(req, req.to, req.sender,
            {'params': {'path': ['0x' + 'c' * 40]}}, 'Router', 0)
    assert_unknown_response(response)


@pytest.mark.asyncio
@pytest.mark.parametrize('surface', ['fresh', 'swap'])
@pytest.mark.parametrize('simulation, penalised', [
    ({'gas_used': 21000}, False),
    ({'success': None, 'gas_used': 21000}, False),
    ({'success': False, 'gas_used': 21000}, True),
], ids=['missing-success', 'none-success', 'false-success'])
async def test_only_explicit_simulation_failure_is_a_coverage_penalty(consumer_api, surface, simulation, penalised):
    api, _ = consumer_api
    api.risk_engine.compute_from_results.return_value = {
        'rug_probability': 0, 'risk_level': 'LOW', 'status': 'ok',
        'coverage': {'honeypot': 1}, 'coverage_reasons': {},
    }
    api.tenderly_simulator.is_enabled = lambda: True
    api.tenderly_simulator.simulate_transaction = AsyncMock(return_value=simulation)
    req = api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40)
    if surface == 'fresh':
        response = await api.firewall(req, SimpleNamespace(headers={}))
    else:
        response = await api._analyze_router_swap(req, req.to, req.sender,
            {'params': {'path': ['0x' + 'c' * 40]}}, 'Router', 0)
    assert ('transaction_simulation' in response['coverage']) is penalised
    assert response['status'] == ('unknown' if penalised else 'ok')


@pytest.mark.asyncio
async def test_scan_endpoint_preserves_unknown_verdict(consumer_api, incomplete_output, monkeypatch):
    api, _ = consumer_api
    monkeypatch.setattr(api, 'tx_scanner', SimpleNamespace(scan_address=AsyncMock(return_value={
        **incomplete_output, 'risk_score': 0, 'risk_level': 'low', 'verdict': 'SAFE',
    })))
    response = await api.scan(api.ScanRequest(address='0x' + 'a' * 40))
    assert_unknown_response(response)
    assert response['risk_level'] == 'UNKNOWN'


@pytest.mark.asyncio
async def test_confirmed_eoa_scan_and_firewall_fallback_render_safe(consumer_api, monkeypatch, mock_web3_client):
    from scanner.transaction_scanner import TransactionScanner
    api, _ = consumer_api
    mock_web3_client.is_contract.return_value = False
    scanner = TransactionScanner(mock_web3_client)
    scanner.scam_db.check_address = AsyncMock(return_value=[])
    monkeypatch.setattr(api, 'tx_scanner', scanner)
    response = await api.scan(api.ScanRequest(address='0x' + 'a' * 40))
    assert (response['status'], response['risk_level'], response['classification']) == ('ok', 'low', 'SAFE')
    assert (response['risk_score'], response['confidence'], response['partial']) == (5, 95, False)
    assert response['risk_display'] == '5%'
    fallback = api._build_fallback_response({}, await scanner.scan_address('0x' + 'a' * 40), None, 56)
    assert (fallback['status'], fallback['classification'], fallback['partial']) == ('ok', 'SAFE', False)
    assert fallback['verdict'] == 'SAFE — Risk score 5/100'


@pytest.mark.asyncio
async def test_unknown_explanation_avoids_ai_safe_text(consumer_api, incomplete_output):
    api, services = consumer_api
    services.advisor = SimpleNamespace(explain_scan=AsyncMock(return_value='SAFE: risk 0%'))
    response = await api.agent_explain(api.ExplainRequest(scan_result=incomplete_output),
        SimpleNamespace(client=SimpleNamespace(host='consumer-test'), headers={}))
    assert 'Unknown' in response['explanation']
    services.advisor.explain_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_chat_scan_cannot_return_safe_text(consumer_api, incomplete_output):
    api, services = consumer_api
    services.advisor = SimpleNamespace(chat=AsyncMock(return_value={
        'text': 'SAFE: risk 0%', 'scan_data': {**incomplete_output, 'risk_score': 0},
    }))
    response = await api.agent_chat(api.ChatRequest(message='scan token', user_id='test'),
        SimpleNamespace(client=SimpleNamespace(host='consumer-chat'), headers={}))
    assert 'Unknown' in response['response']
    assert 'SAFE' not in response['response']
    assert response['scan_data']['risk_display'].startswith('Unknown')


@pytest.mark.asyncio
async def test_invalid_swap_path_does_not_fall_back_to_router(consumer_api):
    api, _ = consumer_api
    api.web3_client.is_valid_address.side_effect = lambda value: len(value) == 42
    req = api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40)
    response = await api._analyze_router_swap(req, req.to, req.sender,
        {'params': {'path': ['0xinvalid']}}, 'Router', 0)
    assert response is not None
    assert_unknown_response(response)


@pytest.mark.asyncio
async def test_missing_swap_analyzers_does_not_fall_back_to_router(consumer_api):
    api, services = consumer_api
    services.registry = None
    req = api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40)
    response = await api._analyze_router_swap(req, req.to, req.sender,
        {'params': {'path': ['0x' + 'c' * 40]}}, 'Router', 0)
    assert response is not None
    assert_unknown_response(response)


@pytest.mark.asyncio
@pytest.mark.parametrize('sign_method,typed_data', [
    ('eth_signTypedData_v4', {'primaryType': 'UnknownType', 'message': {}}),
    ('eth_signTypedData_v4', {'primaryType': 'Permit', 'message': 'not-an-object', 'domain': {}}),
    ('eth_sign', None),
    ('personal_sign', {'primaryType': 'UnknownType', 'message': {}}),
    ('eth_sign', {'primaryType': 'UnknownType', 'message': {}}),
], ids=['unrecognised-typed-data', 'typed-data-parse-failure', 'blind-eth-sign',
        'personal-sign-unrecognised-typed-data', 'eth-sign-unrecognised-typed-data'])
async def test_signature_without_decoded_analysis_is_unknown(consumer_api, sign_method, typed_data):
    api, _ = consumer_api
    req = api.FirewallRequest(to='', sender='0x' + 'b' * 40, signMethod=sign_method, typedData=typed_data)
    response = await api._build_signature_only_response(req)
    assert_unknown_response(response)


@pytest.mark.asyncio
async def test_personal_sign_is_covered(consumer_api):
    api, _ = consumer_api
    req = api.FirewallRequest(to='', sender='0x' + 'b' * 40, signMethod='personal_sign')
    response = await api._build_signature_only_response(req)
    assert response['classification'] == 'SAFE'
    assert response['status'] == 'ok'
    assert response['partial'] is False
    assert response['coverage'] == {'signature': 1}
    assert response['risk_display'] == '0%'


@pytest.mark.asyncio
async def test_supported_signature_preserves_covered_safe(consumer_api):
    api, _ = consumer_api
    req = api.FirewallRequest(to='', sender='0x' + 'b' * 40,
        signMethod='eth_signTypedData_v4', typedData={
            'primaryType': 'Permit', 'message': {
                'spender': '0x000000000022d473030f116ddee9f6b43ac78ba3', 'value': '1', 'deadline': '1',
            },
        })
    response = await api._build_signature_only_response(req)
    assert response['classification'] == 'SAFE'
    assert response['status'] == 'ok'
    assert response['coverage'] == {'signature': 1}


@pytest.mark.parametrize('surface', ['compact', 'feed', 'center', 'stats', 'content', 'content-explain', 'sidepanel', 'sidepanel-message', 'history'])
@pytest.mark.parametrize('scan_state', ['missing-provider', 'failed-simulation', 'legacy', 'covered'])
def test_extension_consumer_coverage(surface, scan_state):
    import json
    from pathlib import Path
    import shutil
    import subprocess

    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required for extension JavaScript regression tests')
    script = r'''
const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const [surface, state] = JSON.parse(process.argv[1]);
const complete = state === 'covered';
const scan = {
  classification: 'SAFE', risk_score: 0, verdict: 'SAFE', plain_english: 'SAFE',
  status: complete ? 'ok' : 'unknown',
  coverage: {honeypot: complete ? 1 : 0},
  coverage_reasons: complete ? {} : {honeypot: state},
  honeypot: {is_honeypot: complete ? false : null, sell_tax: complete ? 0 : null},
};
if (state === 'legacy') {delete scan.status; delete scan.coverage;}
if (state === 'failed-simulation') {
  scan.status = 'ok';
  scan.coverage.honeypot = 0.4;
  scan.honeypot.simulation_failed = true;
}
const nodes = new Map();
const appended = [];
function element() {
  return {
    innerHTML: '', textContent: '', style: {}, dataset: {}, children: [], handlers: {},
    appendChild(child) {this.children.push(child);},
    classList: {add() {}, remove() {}}, addEventListener(event, handler) {this.handlers[event] = handler;},
  };
}
const context = {
  URLSearchParams, location: {search: ''}, Date, MAX_HISTORY: 50,
  t: key => key, _t: key => key, escapeHtml: String,
  _loadContentLang: async () => {}, removeOverlay() {}, buildCalldataSection: () => '',
  mountOverlay(overlay) {appended.push(overlay); return context.document;}, onDecision() {},
  document: {
    addEventListener() {}, createElement: element,
    getElementById(id) {if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id);},
    body: {appendChild(value) {appended.push(value);}},
  },
  messagesEl: {appendChild(value) {appended.push(value);}},
  renderMarkdown: String,
  chrome: {runtime: {sendMessage(message, callback) {callback({explanation: 'SAFE'});}}, storage: {local: {
    get(defaults, callback) {callback({scanHistory: []});},
    set(value) {context.saved = value;},
  }}},
};
vm.createContext(context);
function load(file, start, end) {
  const source = fs.readFileSync(`extension/${file}.js`, 'utf8').replace(/\r\n/g, '\n');
  const from = start ? source.indexOf(start) : 0;
  assert(from >= 0);
  const to = end ? source.indexOf(end, from) : source.length;
  assert(to > from);
  vm.runInContext(source.slice(from, to), context);
}
load('popup');
context.escapeHtml = String;
load('content', '  // One line saying why a result is Unknown', '  async function showLoadingOverlay');
load('content', '  async function showAnalysisOverlay', '  async function showErrorOverlay');
load('sidepanel', '  function renderRiskCard', '  // -------------------------------------------------------------------\n  // Suggested prompts');
load('sidepanel', '  function appendMessage', '  // -------------------------------------------------------------------\n  // Save / export');
load('background', 'function saveToHistory');
(async () => {
  let html;
  if (surface === 'compact') {
    const target = element();
    context.renderCompactHistory([scan], target);
    html = target.innerHTML;
    assert.equal(html.includes('100/100'), complete);
  } else if (surface === 'feed') {
    context.renderDashFeed([scan]);
    html = nodes.get('dash-feed').innerHTML;
    assert.equal(html.includes('>100<'), complete);
  } else if (surface === 'center') {
    context.renderDashCenter(scan);
    assert.equal(nodes.get('dash-gauge-num').textContent, complete ? 100 : '?');
    assert.equal(nodes.get('dash-cls-badge').textContent, complete ? 'classSafe' : 'classUnknown');
    assert.equal(nodes.get('dash-verdict').textContent.includes('SAFE'), complete);
  } else if (surface === 'stats') {
    context.renderDashStats([scan]);
    assert.equal(nodes.get('dash-stat-safe').textContent, complete ? '100%' : '0%');
  } else if (surface === 'content' || surface === 'content-explain') {
    await context.showAnalysisOverlay('request', scan);
    html = appended.at(-1).innerHTML;
    assert.equal(html.includes('100/100'), complete);
    assert.equal(html.includes('SAFE'), complete);
    if (surface === 'content-explain') {
      nodes.get('shieldai-explain').handlers.click();
      assert.equal(nodes.get('shieldai-explain-text').textContent.includes('SAFE'), complete);
    }
  } else if (surface === 'sidepanel') {
    context.renderRiskCard(scan);
    html = appended.at(-1).innerHTML;
    assert.equal(html.includes('>No<'), complete);
    assert.equal(html.includes('>0%<'), complete);
    assert.equal(html.includes('LOW Risk'), complete);
  } else if (surface === 'sidepanel-message') {
    context.appendMessage('assistant', 'SAFE', {scanData: scan});
    html = appended.at(-1).children[0].innerHTML;
    assert.equal(html.includes('SAFE'), complete);
  } else if (surface === 'history') {
    context.saveToHistory({}, scan);
    const stored = context.saved.scanHistory[0];
    assert.equal(stored.status, complete ? 'ok' : 'unknown');
    assert.equal(stored.classification, complete ? 'SAFE' : 'UNKNOWN');
    assert.equal(stored.risk_score, 0);
    assert.equal(JSON.stringify(stored.coverage), JSON.stringify(scan.coverage || {}));
    assert.deepEqual(stored.coverage_reasons, scan.coverage_reasons);
    assert.equal(stored.verdict.includes('SAFE'), complete);
    context.saveToHistory({}, {status: 'unknown'});
    assert.equal(context.saved.scanHistory[0].risk_score, null);
  }
  if (html && !complete) {
    assert(!html.includes('classSafe'));
    assert(!html.includes('>SAFE<'));
    assert(/unknown/i.test(html));
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
'''
    result = subprocess.run(
        [node, '-e', script, json.dumps([surface, scan_state])],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
        encoding='utf-8', check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_bot_logging_setup_keeps_httpx_request_urls_out_of_info_logs():
    import ast
    import logging
    from pathlib import Path
    from unittest.mock import patch

    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    calls = [node for node in tree.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
             and ast.unparse(node.value.func).startswith('logging.')]
    basic_config = next(node for node in calls if ast.unparse(node.value.func) == 'logging.basicConfig')
    httpx_setup = [node for node in calls if "getLogger('httpx')" in ast.unparse(node)]
    assert httpx_setup and httpx_setup[0].lineno > basic_config.lineno
    httpx_logger = logging.getLogger('httpx')
    previous = httpx_logger.level
    httpx_logger.setLevel(logging.NOTSET)
    try:
        with patch('logging.basicConfig'):
            exec(compile(ast.Module(body=calls, type_ignores=[]), 'bot.py', 'exec'), {'logging': logging})
        assert httpx_logger.level >= logging.WARNING
    finally:
        httpx_logger.setLevel(previous)


@pytest.mark.asyncio
@pytest.mark.parametrize('complete', [True, False], ids=['complete', 'incomplete'])
async def test_real_advisor_chat_keeps_text_only_for_complete_scan(consumer_api, complete):
    from agent.advisor import Advisor
    from utils.web3_client import Web3Client
    api, services = consumer_api
    honeypot = {'is_honeypot': False, 'can_sell': True, 'buy_tax': 0, 'sell_tax': 0} if complete else {
        'is_honeypot': None, 'can_sell': None, 'buy_tax': None, 'sell_tax': None, 'status': 'unknown'}
    scan = RiskEngine().compute_from_results([
        AnalyzerResult('structural', 0.5, 0, data={'is_contract': True, 'is_verified': True, 'contract_age_days': 100}),
        AnalyzerResult('honeypot', 0.5, 0, data=honeypot),
    ])
    assert (scan['status'] == 'ok') is complete
    chain_registry = Web3Client.__new__(Web3Client)
    chain_registry._adapters = {56: MagicMock()}
    tools = SimpleNamespace(
        _container=SimpleNamespace(web3_client=chain_registry),
        scan_contract=AsyncMock(return_value=scan), check_deployer=AsyncMock(return_value={}),
        check_honeypot=AsyncMock(return_value=honeypot), get_market_data=AsyncMock(return_value={}),
    )
    db = SimpleNamespace(get_chat_history=AsyncMock(return_value=[]), insert_chat_message=AsyncMock(),
        get_ai_tokens_used=AsyncMock(return_value=0), add_ai_tokens_used=AsyncMock())
    ai = SimpleNamespace(is_available=lambda: True, chat_with_usage=AsyncMock(return_value=('Advisor analysis text', 100)))
    services.advisor = Advisor(tools, db, ai, daily_token_budget=1_000_000)
    response = await api.agent_chat(api.ChatRequest(message='check 0x' + 'a' * 40, user_id='test'),
        SimpleNamespace(client=SimpleNamespace(host='advisor-' + str(complete)), headers={}))
    assert response['scan_data']['status'] == ('ok' if complete else 'unknown')
    assert response['scan_data']['coverage'] == scan['coverage']
    if complete:
        assert response['response'] == 'Advisor analysis text'
        assert not response['scan_data']['risk_display'].startswith('Unknown')
    else:
        assert response['response'] != 'Advisor analysis text'
        assert 'Unknown' in response['response']


@pytest.mark.asyncio
async def test_rescue_unreachable_rpc_answers_unknown_without_raw_error(consumer_api):
    from unittest.mock import patch
    from services.rescue_service import RescueService
    api, services = consumer_api
    services.settings.bscscan_api_key = ''
    api.web3_client._get_adapter.return_value.w3.provider.endpoint_uri = 'https://rpc.example/secret-key'
    services.rescue_service = RescueService(api.web3_client)
    session = MagicMock()
    session.post.side_effect = RuntimeError('Session is closed: https://rpc.example/secret-key')
    with patch('services.rescue_service.aiohttp.ClientSession') as factory:
        factory.return_value.__aenter__.return_value = session
        response = await api.rescue_scan('0x' + 'b' * 40, chain_id=4663)
    session.post.assert_called()
    assert response['status'] == 'unknown'
    assert response['approvals'] == []
    assert response['scanned_blocks'] is None
    assert response['coverage_reasons'] == {'allowances': "Approval data unavailable from the chain's RPC"}
    assert 'secret-key' not in str(response)


@pytest.mark.asyncio
async def test_rescue_forwards_approval_coverage(consumer_api):
    api, services = consumer_api
    services.settings.bscscan_api_key = ''
    coverage = {
        'status': 'unknown', 'coverage': {'approval_state': 0},
        'coverage_reasons': {'approval_state': 'Approval state unavailable'},
    }
    services.rescue_service = SimpleNamespace(scan_approvals=AsyncMock(return_value={
        'total_approvals': 1, 'high_risk': 0, 'medium_risk': 0, **coverage,
    }))
    response = await api.rescue_scan('0x' + 'b' * 40, chain_id=4663)
    assert {key: response[key] for key in coverage} == coverage


@pytest.mark.asyncio
@pytest.mark.parametrize('surface', ['fresh', 'swap'])
async def test_verification_lookup_failure_stays_unknown(consumer_api, surface):
    api, services = consumer_api
    api.web3_client.is_verified_contract.side_effect = RuntimeError('explorer unavailable')
    api.risk_engine.compute_from_results.return_value = {
        'rug_probability': 0, 'risk_level': 'LOW', 'status': 'ok',
        'coverage': {'honeypot': 1}, 'coverage_reasons': {},
    }
    req = api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40)
    if surface == 'fresh':
        await api.firewall(req, SimpleNamespace(headers={}))
    else:
        await api._analyze_router_swap(req, req.to, req.sender,
            {'params': {'path': ['0x' + 'c' * 40]}}, 'Router', 0)
    assert services.registry.run_all.call_args.args[0].extra['is_verified'] is None


@pytest.mark.parametrize('compact', [True, False], ids=['compact', 'dashboard'])
def test_extension_wallet_health_never_paints_unknown_green(compact):
    import json
    from pathlib import Path
    import shutil
    import subprocess

    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required for extension JavaScript regression tests')
    script = '''
const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const compact = JSON.parse(process.argv[1]);
function element() {return {innerHTML: '', textContent: '', style: {}};}
const context = {
  URLSearchParams, location: {search: ''}, t: key => key, escapeHtml: String,
  document: {addEventListener() {}, createElement: element, getElementById: element},
  chrome: {runtime: {sendMessage() {}}, storage: {local: {get() {}, set() {}}}},
};
vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/popup.js', 'utf8'), context);
const ctx = {compact, scoreNumEl: element(), statsEl: element(), approvalsEl: element(), resultEl: element()};
context.renderHealthData({
  status: 'unknown', coverage_reasons: {approval_state: 'Approval state unavailable'},
  high_risk: 0, medium_risk: 0, approvals: [{risk_level: 'unknown', token_symbol: 'TKN', spender: '0xabc'}],
}, ctx);
assert.notEqual(ctx.scoreNumEl.textContent, 100);
assert.notEqual(ctx.scoreNumEl.style.color, '#22c55e');
assert(!ctx.approvalsEl.innerHTML.includes('risk-low'));
context.renderHealthData({
  high_risk: 0, medium_risk: 0, approvals: [{risk_level: 'LOW', token_symbol: 'TKN', spender: '0xabc'}],
}, ctx);
assert.equal(ctx.scoreNumEl.textContent, 100);
assert.equal(ctx.scoreNumEl.style.color, '#22c55e');
assert(ctx.approvalsEl.innerHTML.includes('risk-low'));
'''
    result = subprocess.run(
        [node, '-e', script, json.dumps(compact)],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
        encoding='utf-8', check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('stored, chain_id', [({'selectedChainId': 8453}, 8453), ({}, 56)])
def test_extension_wallet_health_scans_the_selected_chain_and_shows_a_failed_scan_as_unknown(stored, chain_id):
    import json
    from pathlib import Path
    import shutil
    import subprocess

    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required for extension JavaScript regression tests')
    script = '''
const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const [stored, chainId] = JSON.parse(process.argv[1]);
function element() {return {innerHTML: '', textContent: '', style: {}};}
const requested = [];
const context = {
  URLSearchParams, location: {search: ''}, escapeHtml: String,
  t: (key, values) => values ? `${key}:${values.status}` : key,
  AbortController, setTimeout, clearTimeout,
  document: {addEventListener() {}, createElement: element, getElementById: element},
  chrome: {runtime: {sendMessage() {}}, storage: {local: {get(defaults, done) { done({...defaults, ...stored}); }, set() {}}}},
  fetch: async (url) => { requested.push(url); return {ok: false, status: 503, json: async () => ({})}; },
};
vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/popup.js', 'utf8'), context);
context.escapeHtml = String;
const ctx = {compact: true, scoreNumEl: element(), statsEl: element(), approvalsEl: element(),
  resultEl: element(), loadingEl: element(), errorEl: element()};
(async () => {
  await context.runHealthScan('0x' + 'a'.repeat(40), ctx);
  assert.deepEqual(requested, [`https://api.shieldbotsecurity.online/api/rescue/0x${'a'.repeat(40)}?chain_id=${chainId}`]);
  assert.notEqual(ctx.errorEl.style.display, 'block');
  assert.equal(ctx.scoreNumEl.textContent, '?');
  assert(ctx.approvalsEl.innerHTML.includes('Unknown: healthScanUnavailable:503'));
  assert.equal(ctx.resultEl.style.display, 'block');
})().catch((error) => { console.error(error); process.exit(1); });
'''
    result = subprocess.run(
        [node, '-e', script, json.dumps([stored, chain_id])],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
        encoding='utf-8', check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    root = Path(__file__).resolve().parents[1] / 'extension' / 'locales'
    for language in ('en', 'vi', 'zh'):
        messages = json.loads((root / language / 'messages.json').read_text(encoding='utf-8'))
        assert '(HTTP {status})' in messages['healthScanUnavailable'], language


@pytest.mark.parametrize('surface', ['popup-compact', 'popup-dashboard', 'sidepanel-guardian'])
def test_extension_unknown_value_at_risk_is_never_zero(surface):
    import json
    from pathlib import Path
    import shutil
    import subprocess

    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required for extension JavaScript regression tests')
    script = '''
const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const surface = JSON.parse(process.argv[1]);
function element() {return {innerHTML: '', textContent: '', style: {}};}
const context = {
  URLSearchParams, location: {search: ''}, t: key => key, escapeHtml: String,
  document: {addEventListener() {}, createElement: element, getElementById: element},
  chrome: {runtime: {sendMessage() {}}, storage: {local: {get() {}, set() {}}}},
};
vm.createContext(context);
if (surface === 'sidepanel-guardian') {
  const source = fs.readFileSync('extension/sidepanel.js', 'utf8');
  const start = source.indexOf('  function renderGuardianHealth');
  const end = source.indexOf('  function renderGuardianAlerts');
  assert(start >= 0 && end > start);
  context.guardianHealthEl = element();
  vm.runInContext(source.slice(start, end), context);
  context.renderGuardianHealth({
    health_score: 85, level: 'unknown', status: 'unknown', total_value_at_risk_usd: 0,
    coverage_reasons: {deployer_risk: 'deployer_risk data incomplete'},
    warnings: ['Could not check deployer risk'], components: {},
  });
  let html = context.guardianHealthEl.innerHTML;
  assert(!html.includes('$0'));
  assert(html.includes('Unknown'));
  assert(!html.includes('#6ee7b7'));
  context.renderGuardianHealth({
    health_score: 50, level: 'unknown', status: 'unknown', total_value_at_risk_usd: null,
    coverage_reasons: {dangerous_approvals: 'dangerous_approvals data incomplete'},
    warnings: ['Approval data incomplete: USD price unavailable for 1 token(s)'], components: {},
  });
  html = context.guardianHealthEl.innerHTML;
  assert(!html.includes('$'));
  assert(html.includes('Unknown'));
  context.renderGuardianHealth({
    health_score: 85, level: 'excellent', status: 'ok', total_value_at_risk_usd: 0, warnings: [], components: {},
  });
  html = context.guardianHealthEl.innerHTML;
  assert(html.includes('$0.00'));
  assert(html.includes('#6ee7b7'));
} else {
  vm.runInContext(fs.readFileSync('extension/popup.js', 'utf8'), context);
  context.escapeHtml = String;
  const ctx = {compact: surface === 'popup-compact', scoreNumEl: element(), statsEl: element(), approvalsEl: element(), resultEl: element()};
  for (const total of [null, 0]) {
    context.renderHealthData({
      status: 'unknown', total_value_at_risk_usd: total, coverage: {prices: false},
      coverage_reasons: {prices: 'Token price unavailable'}, high_risk: 0, medium_risk: 0,
      approvals: [{risk_level: 'LOW', token_symbol: 'TKN', spender: '0xabc', allowance: '5', value_at_risk_usd: null}],
    }, ctx);
    assert(!ctx.statsEl.innerHTML.includes('$0'));
    assert(ctx.statsEl.innerHTML.includes('Unknown'));
    assert(ctx.approvalsEl.innerHTML.includes('Token price unavailable'));
    assert(ctx.approvalsEl.innerHTML.includes(ctx.compact ? 'health-usd-risk">Unknown' : 'wh-appr-usd">Unknown'));
    assert(!ctx.approvalsEl.innerHTML.includes('$0'));
  }
  context.renderHealthData({
    status: 'ok', total_value_at_risk_usd: 0, high_risk: 0, medium_risk: 0,
    approvals: [{risk_level: 'LOW', token_symbol: 'TKN', spender: '0xabc', allowance: '5', value_at_risk_usd: 12.5}],
  }, ctx);
  assert(ctx.statsEl.innerHTML.includes('$0'));
  assert(ctx.approvalsEl.innerHTML.includes('$12.50'));
  assert(!ctx.approvalsEl.innerHTML.includes('Unknown'));
}
'''
    result = subprocess.run(
        [node, '-e', script, json.dumps(surface)],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
        encoding='utf-8', check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.asyncio
async def test_api_rescans_legacy_row_from_real_database(consumer_api, incomplete_output):
    from core.database import Database
    api, services = consumer_api
    database = Database(':memory:')
    await database.initialize()
    try:
        address = '0x' + 'a' * 40
        await database.upsert_contract_score(address, 56, 0.0, 'LOW', category_scores={'honeypot': 0})
        legacy = await database.get_contract_score(address, 56)
        assert legacy['status'] == 'unknown'
        services.db = database
        api.risk_engine.compute_from_results.return_value = incomplete_output
        response = await api.firewall(api.FirewallRequest(to=address, sender='0x' + 'b' * 40),
                                      SimpleNamespace(headers={}))
        services.registry.run_all.assert_awaited_once()
        assert response.get('cached') is not True
        stored = await database.get_contract_score(address, 56)
        assert stored['category_scores']['_scan_metadata']['status'] == 'unknown'
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_advisor_scan_failure_renders_unknown_chat(consumer_api):
    from agent.advisor import Advisor
    from utils.web3_client import Web3Client
    api, services = consumer_api
    secret = 'https://rpc.example/v2/SYNTHETIC_KEY_123'
    chain_registry = Web3Client.__new__(Web3Client)
    chain_registry._adapters = {56: MagicMock()}
    tools = SimpleNamespace(
        _container=SimpleNamespace(web3_client=chain_registry),
        scan_contract=AsyncMock(side_effect=RuntimeError(secret)), check_deployer=AsyncMock(return_value={}),
        check_honeypot=AsyncMock(return_value={}), get_market_data=AsyncMock(return_value={}),
    )
    db = SimpleNamespace(get_chat_history=AsyncMock(return_value=[]), insert_chat_message=AsyncMock(),
        get_ai_tokens_used=AsyncMock(return_value=0), add_ai_tokens_used=AsyncMock())
    ai = SimpleNamespace(is_available=lambda: True, chat_with_usage=AsyncMock(return_value=('SAFE: this token looks fine', 100)))
    services.advisor = Advisor(tools, db, ai, daily_token_budget=1_000_000)
    response = await api.agent_chat(api.ChatRequest(message='check 0x' + 'a' * 40, user_id='test'),
        SimpleNamespace(client=SimpleNamespace(host='advisor-scan-failure'), headers={}))
    assert 'Unknown' in response['response']
    assert 'SAFE' not in response['response']
    assert response['scan_data']['status'] == 'unknown'
    assert response['scan_data']['coverage_reasons']
    assert secret not in str(response)


@pytest.mark.parametrize('path', ['api.py', 'bot.py', 'agent/advisor.py', 'agent/firewall.py', 'rpc/proxy.py',
                                  'agent/hunter.py', 'agent/launch_watch.py', 'agent/sentinel.py'])
def test_exception_text_never_reaches_replies_or_logs(path):
    import ast
    from pathlib import Path

    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    leaks = []
    for handler in ast.walk(tree):
        if not isinstance(handler, ast.ExceptHandler) or not handler.name:
            continue
        handled = ast.unparse(handler.type)
        for statement in handler.body:
            for node in ast.walk(statement):
                if not (isinstance(node, ast.Name) and node.id == handler.name):
                    continue
                parent = parents[node]
                allowed = (
                    (isinstance(parent, ast.Raise) and parent.cause is node)
                    or (isinstance(parent, ast.Call) and ast.unparse(parent.func) == 'type')
                    or (isinstance(parent, ast.Attribute) and parent.attr == '__traceback__')
                    or (handled == 'HTTPException' and isinstance(parent, ast.Attribute))
                    or (handled == 'UnsupportedChainError' and isinstance(parent, ast.Call)
                        and ast.unparse(parent.func) == 'str')
                )
                if not allowed:
                    leaks.append(f'{path}:{node.lineno} {ast.unparse(parent)[:80]}')
    leaks += [f'{path}:{parents[node].lineno} exc_info' for node in ast.walk(tree)
              if isinstance(node, ast.keyword) and node.arg == 'exc_info']
    message_loggers = {'logger.exception', 'logging.exception', 'traceback.format_exc',
                       'traceback.print_exc', 'sys.exc_info'}
    leaks += [f'{path}:{node.lineno} {ast.unparse(node.func)}' for node in ast.walk(tree)
              if isinstance(node, ast.Call) and ast.unparse(node.func) in message_loggers]
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        exception_names = {
            ast.unparse(node.args[0]) for node in ast.walk(function)
            if isinstance(node, ast.Call) and ast.unparse(node.func) == 'isinstance'
            and 'Exception' in ast.unparse(node.args[1])
        } | {
            target.id for node in ast.walk(function)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func).endswith('.exception')
            for target in node.targets if isinstance(target, ast.Name)
        }
        for call in ast.walk(function):
            if not (isinstance(call, ast.Call) and ast.unparse(call.func).startswith('logger.')):
                continue
            for node in ast.walk(call):
                if (isinstance(node, ast.Name) and node.id in exception_names
                        and not (isinstance(parents[node], ast.Call) and ast.unparse(parents[node].func) == 'type')):
                    leaks.append(f'{path}:{node.lineno} {ast.unparse(call)[:80]}')
    assert leaks == []


def test_agent_firewall_pipeline_failure_logs_exception_class_only(caplog):
    import logging
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from agent.firewall import create_agent_firewall_router
    container = MagicMock()
    container.auth_manager.validate_key = AsyncMock(return_value={'key_id': 'k1', 'tier': 'free'})
    container.auth_manager.check_rate_limit = AsyncMock(return_value=True)
    container.db.get_agent_policy = AsyncMock(return_value={'policy': {}})
    container.db.get_contract_score = AsyncMock(return_value=None)
    container.cache.get_verdict = AsyncMock(return_value=None)
    container.web3_client.is_token_contract = AsyncMock(return_value=True)
    container.tenderly_simulator.is_enabled = MagicMock(return_value=False)
    container.registry.run_all = AsyncMock(side_effect=RuntimeError('https://rpc.example/v2/SYNTHETIC_KEY_123'))
    app = FastAPI()
    app.include_router(create_agent_firewall_router(container), prefix='/api/agent')
    with caplog.at_level(logging.DEBUG, logger='agent.firewall'):
        response = TestClient(app).post('/api/agent/firewall', headers={'X-API-Key': 'sb_test'}, json={
            'agent_id': 'agent:1', 'transaction': {'from': '0x' + 'b' * 40, 'to': '0x' + 'a' * 40, 'chain_id': 56},
        })
    assert response.status_code == 503
    assert 'RuntimeError' in caplog.text
    assert 'File "' in caplog.text
    assert 'SYNTHETIC_KEY_123' not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize('endpoint', ['firewall', 'scan', 'scan_injection', 'outcome', 'community_report',
                                      'agent_chat', 'agent_explain', 'background'])
async def test_api_error_logs_never_include_provider_error_text(consumer_api, monkeypatch, caplog, endpoint):
    import asyncio
    import logging
    from fastapi import HTTPException
    api, services = consumer_api
    error = RuntimeError('https://rpc.example/v2/SYNTHETIC_KEY_123')
    services.registry.run_all.side_effect = error
    services.injection_scanner = SimpleNamespace(scan=AsyncMock(side_effect=error))
    services.advisor = SimpleNamespace(chat=AsyncMock(side_effect=error), explain_scan=AsyncMock(side_effect=error))
    services.db.record_outcome = AsyncMock(side_effect=error)
    services.db.record_community_report = AsyncMock(side_effect=error)
    monkeypatch.setattr(api, 'token_scanner', SimpleNamespace(check_token=AsyncMock(side_effect=error)))
    monkeypatch.setattr(api, 'tx_scanner', SimpleNamespace(scan_address=AsyncMock(side_effect=error)))
    request = SimpleNamespace(client=SimpleNamespace(host='leak-' + endpoint), headers={},
                              json=AsyncMock(return_value={'content': 'hello'}))
    calls = {
        'firewall': lambda: api.firewall(api.FirewallRequest(to='0x' + 'a' * 40, sender='0x' + 'b' * 40), request),
        'scan': lambda: api.scan(api.ScanRequest(address='0x' + 'a' * 40)),
        'scan_injection': lambda: api.scan_injection(request),
        'outcome': lambda: api.report_outcome(api.OutcomeRequest(address='0x' + 'a' * 40, user_decision='proceed')),
        'community_report': lambda: api.community_report(api.CommunityReportRequest(
            address='0x' + 'a' * 40, report_type='scam'), request),
        'agent_chat': lambda: api.agent_chat(api.ChatRequest(message='hello', user_id='test'), request),
        'agent_explain': lambda: api.agent_explain(api.ExplainRequest(
            scan_result={'status': 'ok', 'coverage': {'honeypot': 1}}), request),
    }
    with caplog.at_level(logging.DEBUG, logger='api'):
        if endpoint == 'background':
            async def fail():
                raise error
            task = api._fire_and_forget(fail(), label='leak-test')
            await asyncio.gather(task, return_exceptions=True)
            await asyncio.sleep(0)
        else:
            with pytest.raises(HTTPException):
                await calls[endpoint]()
            assert 'RuntimeError' in caplog.text
            assert 'File "' in caplog.text
    assert caplog.records
    assert 'SYNTHETIC_KEY_123' not in caplog.text


def test_popup_styles_unknown_risk_badge_neutrally():
    import re
    from pathlib import Path

    html = Path('extension/popup.html').read_text(encoding='utf-8')
    rules = {name: body for name, body in re.findall(r'\.(risk-\w+)\s*\{([^}]*)\}', html)}
    assert 'background' in rules.get('risk-unknown', '')
    assert rules['risk-unknown'] not in (rules['risk-low'], rules['risk-medium'], rules['risk-high'])


@pytest.mark.asyncio
async def test_unknown_explanation_accepts_missing_risk_score(consumer_api):
    api, services = consumer_api
    services.advisor = SimpleNamespace(explain_scan=AsyncMock(return_value='SAFE: risk 0%'))
    response = await api.agent_explain(api.ExplainRequest(scan_result={'risk_score': None, 'status': 'unknown'}),
        SimpleNamespace(client=SimpleNamespace(host='explain-none-score'), headers={}))
    assert 'Unknown' in response['explanation']
    services.advisor.explain_scan.assert_not_awaited()
