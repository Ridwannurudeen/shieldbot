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
    response = api._build_fallback_response({}, scan, None)
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
async def test_scan_endpoint_preserves_unknown_verdict(consumer_api, incomplete_output, monkeypatch):
    api, _ = consumer_api
    monkeypatch.setattr(api, 'tx_scanner', SimpleNamespace(scan_address=AsyncMock(return_value={
        **incomplete_output, 'risk_score': 0, 'risk_level': 'low', 'verdict': 'SAFE',
    })))
    response = await api.scan(api.ScanRequest(address='0x' + 'a' * 40))
    assert_unknown_response(response)
    assert response['risk_level'] == 'UNKNOWN'


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
@pytest.mark.parametrize('typed_data', [None, {'primaryType': 'UnknownType', 'message': {}}])
async def test_signature_without_supported_analysis_is_unknown(consumer_api, typed_data):
    api, _ = consumer_api
    req = api.FirewallRequest(to='', sender='0x' + 'b' * 40,
        signMethod='personal_sign' if typed_data is None else 'eth_signTypedData_v4', typedData=typed_data)
    response = await api._build_signature_only_response(req)
    assert_unknown_response(response)


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
    assert.equal(nodes.get('dash-cls-badge').textContent, complete ? 'classSafe' : 'UNKNOWN');
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
        AnalyzerResult('structural', 0.5, 0, data={'is_contract': True}),
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
    db = SimpleNamespace(get_chat_history=AsyncMock(return_value=[]), insert_chat_message=AsyncMock())
    ai = SimpleNamespace(is_available=lambda: True, chat=AsyncMock(return_value='Advisor analysis text'))
    services.advisor = Advisor(tools, db, ai)
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
async def test_rescue_unavailable_approval_scan_returns_503_without_raw_error(consumer_api):
    from fastapi import HTTPException
    api, services = consumer_api
    services.settings.bscscan_api_key = ''
    services.rescue_service = SimpleNamespace(scan_approvals=AsyncMock(
        side_effect=RuntimeError('Session is closed: https://rpc.example/secret-key'),
    ))
    with pytest.raises(HTTPException) as exc:
        await api.rescue_scan('0x' + 'b' * 40, chain_id=4663)
    assert exc.value.status_code == 503
    assert exc.value.detail == 'Approval scan unavailable'


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
