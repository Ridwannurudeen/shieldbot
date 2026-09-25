"""Execute the extension scripts with local provider and Chrome API doubles."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest


def run_javascript(script, argument):
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required for extension JavaScript regression tests')
    result = subprocess.run(
        [node, '-e', script, '--', json.dumps(argument)],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'completed' in result.stdout, 'JavaScript assertions did not finish'


@pytest.mark.parametrize('chain_id', [None, '', 'invalid', '0x1237oops', 0, -1, True, 1.5, {}, 9007199254740992])
def test_background_unknown_chain_never_calls_api_or_stores_safe(chain_id):
    run_javascript(r'''
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
let listener, stored;
const context = vm.createContext({
  chrome: {
    runtime: {onInstalled: {addListener() {}}, onMessage: {addListener(fn) {listener = fn;}}},
    storage: {local: {get(defaults, cb) {cb(defaults);}, set(value) {stored = value;}}},
    permissions: {contains: async () => true},
  },
  URL, AbortSignal,
  fetch: async () => {throw new Error('Unknown chain must not reach API');},
});
vm.runInContext(fs.readFileSync('extension/background.js', 'utf8'), context);
(async () => {
  const response = await new Promise(resolve => listener({type: 'SHIELDAI_ANALYZE',
    tx: {to: '0x' + 'a'.repeat(40), chainId: JSON.parse(process.argv[1])}}, {}, resolve));
  assert.equal(response.error, undefined);
  assert.equal(response.result.status, 'unknown');
  assert.equal(response.result.risk_score, null);
  assert.equal(response.result.classification, 'UNKNOWN');
  assert.equal(response.result.coverage.chain, false);
  assert.ok(response.result.coverage_reasons.chain);
  assert.equal(stored.scanHistory[0].classification, 'UNKNOWN');
  assert.equal(stored.scanHistory[0].risk_score, null);
})().then(() => console.log('completed')).catch(error => {console.error(error); process.exitCode = 1;});
''', chain_id)


@pytest.mark.parametrize('chain_id', [4663, '4663', '0x1237', 56, '0x38'])
def test_background_preserves_resolved_chain(chain_id):
    run_javascript(r'''
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
let body;
const context = vm.createContext({
  chrome: {
    runtime: {onInstalled: {addListener() {}}, onMessage: {addListener() {}}},
    storage: {local: {get(defaults, cb) {cb(defaults);}}},
    permissions: {contains: async () => true},
  }, URL, AbortSignal,
  fetch: async (url, options) => {body = JSON.parse(options.body); return {ok: true, json: async () => ({status: 'ok'})};},
});
vm.runInContext(fs.readFileSync('extension/background.js', 'utf8'), context);
(async () => {
  const chainId = JSON.parse(process.argv[1]);
  await context.handleAnalyze({chainId});
  assert.equal(body.chainId, Number(chainId));
})().then(() => console.log('completed')).catch(error => {console.error(error); process.exitCode = 1;});
''', chain_id)


@pytest.mark.parametrize('scenario', [
    'omitted', 'matching', 'mismatch', 'invalid-explicit', 'unavailable', 'invalid-provider',
    'timeout', 'changed-before', 'changed-during', 'changed-back', 'changed-during-query',
    'changed-without-event', 'failed-recheck', 'independent-providers', 'sign-transaction',
    'signature:personal_sign', 'signature:eth_sign', 'signature:eth_signTypedData_v3',
    'signature:eth_signTypedData_v4', 'signature-offline:personal_sign', 'signature-offline:eth_signTypedData_v4',
])
def test_injected_transaction_is_bound_to_provider_chain(scenario):
    run_javascript(r'''
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const {webcrypto} = require('crypto');
const scenario = JSON.parse(process.argv[1]);
const handlers = new Map(), intercepted = [], sent = [], providerEvents = new Map();
let chain = '0x1237', queries = 0, requestNumber = 0;
const provider = {
  on(name, fn) {providerEvents.set(name, fn);},
  async request(args) {
    if (args.method !== 'eth_chainId') {sent.push(args); return 'sent';}
    queries++;
    if (scenario === 'unavailable' || scenario.startsWith('signature-offline:') ||
        (scenario === 'failed-recheck' && queries > 1)) throw new Error('offline');
    if (scenario === 'invalid-provider') return '0x1237oops';
    if (scenario === 'timeout') return new Promise(() => {});
    if (scenario === 'changed-during-query' && queries === 1) {
      change('0x38');
      return '0x1237';
    }
    return chain;
  },
};
function change(value) {chain = value; providerEvents.get('chainChanged')?.(value);}
async function proofFor(message) {
  const encoder = new TextEncoder();
  const key = await webcrypto.subtle.importKey('raw', encoder.encode('test'), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const mac = await webcrypto.subtle.sign('HMAC', key, encoder.encode(message));
  return new Uint8Array(mac);
}
// A top-level https document without an opener.
const window = {
  ethereum: provider, location: {protocol: 'https:'}, frameElement: null, opener: null,
  addEventListener(name, fn) {if (!handlers.has(name)) handlers.set(name, new Set()); handlers.get(name).add(fn);},
  removeEventListener(name, fn) {handlers.get(name)?.delete(fn);},
  dispatchEvent(event) {for (const fn of [...(handlers.get(event.type) || [])]) fn(event);},
  postMessage(message) {
    if (message.type !== 'SHIELDAI_TX_INTERCEPT') return;
    intercepted.push(message.tx);
    if (scenario === 'changed-during' || scenario === 'changed-back') change('0x38');
    if (scenario === 'changed-back') change('0x1237');
    if (scenario === 'changed-without-event') chain = '0x38';
    proofFor(`${message.requestId}:proceed`).then(proof => window.dispatchEvent({type: 'message', source: window,
      isTrusted: true, data: {type: 'SHIELDAI_TX_VERDICT', requestId: message.requestId, action: 'proceed', proof}}));
  },
};
const context = vm.createContext({
  window, console: {log() {}, warn() {}}, document: new EventTarget(), CustomEvent, TextEncoder, structuredClone,
  setInterval() { return 0; }, clearInterval() {},
  crypto: {randomUUID: () => String(++requestNumber), subtle: webcrypto.subtle}, Event: class {constructor(type) {this.type = type;}},
  setTimeout(fn, delay) {if (scenario === 'timeout' && delay < 60000) queueMicrotask(fn); return 1;},
  clearTimeout() {}, queueMicrotask, MutationObserver: class { observe() {} },
});
vm.runInContext(fs.readFileSync('extension/inject.js', 'utf8'), context);
// content.js hands inject.js the channel token at document_start.
context.document.dispatchEvent(new CustomEvent('shieldai:channel', {detail: 'test', cancelable: true}));
(async () => {
  // A signature is analysed on the wallet's chain, read once, but not bound to it: it goes to the
  // wallet as sent. When the chain cannot be read it cannot be analysed, and is rejected.
  if (scenario.startsWith('signature')) {
    const method = scenario.split(':')[1];
    const pending = provider.request({method, params: ['0x' + 'a'.repeat(40), '{}']});
    if (scenario.startsWith('signature-offline:')) {
      await assert.rejects(pending, /chain/i);
      assert.equal(sent.length, 0);
      assert.equal(intercepted[0].chainId, null);
    } else {
      assert.equal(await pending, 'sent');
      assert.equal(intercepted[0].chainId, 4663);
      assert.equal(sent[0].chainId, undefined);
    }
    assert.equal(intercepted[0].signMethod, method);
    assert.equal(queries, 1);
    return;
  }
  if (scenario === 'changed-before') change('0x38');
  const tx = {to: '0x' + 'a'.repeat(40), from: '0x' + 'b'.repeat(40)};
  if (scenario === 'matching') tx.chainId = '0x1237';
  if (scenario === 'mismatch') tx.chainId = '0x38';
  if (scenario === 'invalid-explicit') tx.chainId = 'garbage';
  const blocked = ['mismatch', 'invalid-explicit', 'unavailable', 'invalid-provider', 'timeout',
    'changed-during', 'changed-back', 'changed-during-query', 'changed-without-event', 'failed-recheck'].includes(scenario);
  const pending = provider.request({method: scenario === 'sign-transaction' ? 'eth_signTransaction' : 'eth_sendTransaction', params: [tx]});
  if (blocked) {
    await assert.rejects(pending, /chain|network/i);
    assert.equal(sent.length, 0);
    if (['mismatch', 'invalid-explicit', 'unavailable', 'invalid-provider', 'timeout', 'changed-during-query'].includes(scenario)) {
      assert.equal(intercepted[0].chainId, null);
    }
  } else {
    assert.equal(await pending, 'sent');
    assert.equal(intercepted[0].chainId, scenario === 'changed-before' ? 56 : 4663);
    assert.equal(tx.chainId, scenario === 'matching' ? '0x1237' : undefined);
    assert.ok(queries >= 2);
    if (scenario === 'independent-providers') {
      const second = {on() {}, async request(args) {return args.method === 'eth_chainId' ? '0x1' : 'second';}};
      window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {detail: {provider: second, info: {name: 'second'}}}));
      assert.equal(await second.request({method: 'eth_sendTransaction', params: [tx]}), 'second');
      assert.equal(intercepted[1].chainId, 1);
      assert.equal(await provider.request({method: 'eth_sendTransaction', params: [tx]}), 'sent');
      assert.equal(intercepted[2].chainId, 4663);
    }
  }
})().then(() => console.log('completed')).catch(error => {console.error(error); process.exitCode = 1;});
''', scenario)


def test_popup_names_robinhood_chain():
    run_javascript(r'''
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const context = vm.createContext({location: {search: ''}, URLSearchParams,
  document: {addEventListener() {}, createElement() {return {set textContent(value) {this.innerHTML = value;}};}}});
vm.runInContext(fs.readFileSync('extension/popup.js', 'utf8'), context);
const list = {};
context.renderDeployerAlerts([{chain_id: 4663}], list);
assert.ok(list.innerHTML.includes('Robinhood'));
assert.ok(!list.innerHTML.includes('Chain 4663'));
console.log('completed');
''', None)
