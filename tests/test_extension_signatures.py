"""Signature requests, sign-in messages, delegations, look-alike recipients and the decision rules
added around them, run in the harnesses of test_extension_overlay_behaviour.

Every checked signing method is analysed by the API like a transaction, and what the overlay can
see for itself (a raw eth_sign, typed data it cannot read) only raises the API's verdict.
"""

import pytest

from tests.test_extension_overlay_behaviour import CONTENT_HARNESS, FRAME_HARNESS, run_node

# background.js in a vm with a Chrome double: `respond(message, sender)` runs its message
# listener, `bodies` holds each JSON body it posted and `answer` decides the API's reply.
BACKGROUND_HARNESS = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
let listener;
const bodies = [], local = {}, session = {};
let answer = async () => ({ok: true, json: async () => ({status: 'ok', classification: 'SAFE', risk_score: 0, coverage: {signature: 1}})});
const area = store => ({
  get(keys, cb) {
    const defaults = typeof keys === 'string' ? {[keys]: undefined} : keys || {};
    const found = {...defaults, ...store};
    const value = typeof keys === 'string' ? {[keys]: store[keys]} : found;
    return cb ? cb(value) : Promise.resolve(value);
  },
  set(value, cb) { Object.assign(store, value); return cb ? cb() : Promise.resolve(); },
});
const context = vm.createContext({
  chrome: {
    runtime: {onInstalled: {addListener() {}}, onMessage: {addListener(fn) { listener = fn; }}},
    storage: {local: area(local), session: area(session)},
    permissions: {contains: async () => true},
  },
  URL, AbortSignal, console: {warn() {}, error() {}, log() {}},
  fetch: async (url, options) => {
    if (options && options.body) bodies.push(JSON.parse(options.body));
    return answer(url, options);
  },
});
vm.runInContext(fs.readFileSync('extension/background.js', 'utf8'), context);
const respond = (message, sender = {origin: 'https://dapp.example'}) =>
  new Promise(resolve => listener(message, sender, resolve));
"""


@pytest.mark.parametrize(
    "method",
    ["personal_sign", "eth_signTypedData_v4", "eth_signTypedData_v3", "eth_signTypedData_v1"],
)
def test_signature_requests_are_analysed_by_the_api(method):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  const method = JSON.parse(process.argv[1]);
  const typed = {types: {Permit: []}, primaryType: 'Permit', domain: {name: 'Token'}, message: {spender: '0x' + 'e'.repeat(40)}};
  const tx = method === 'personal_sign' ? {signMethod: method, data: '0x68656c6c6f', chainId: 56}
    : method === 'eth_signTypedData_v1' ? {signMethod: method, typedData: [{type: 'string', name: 'Message', value: 'Hi'}], chainId: 56}
    : {signMethod: method, typedData: typed, chainId: 56};
  analyze = async () => ({result: scan({classification: 'CAUTION', risk_score: 40, danger_signals: ['Permit: unlimited token approval']})});
  await intercept('request', tx, method);
  assert.equal(analyses.length, 1, 'the signature was not sent for analysis');
  assert.equal(analyses[0].signMethod, method);
  const html = overlay().innerHTML;
  assert(overlay().querySelector('.shieldai-badge').className.includes('shieldai-badge-caution'), html);
  assert(html.includes('CAUTION'), html);
  assert(html.includes('Permit: unlimited token approval'), 'the API danger signals are not shown');
  // What would be signed is still shown.
  assert(html.includes(method === 'personal_sign' ? 'hello' : method === 'eth_signTypedData_v1' ? '<td>Message</td>' : 'Token'), html);
  userClick(byId('shieldai-proceed'));
  await flush();
  await assertVerdicts([['request', 'proceed']]);
""",
        method,
    )


@pytest.mark.parametrize("policy", ["STRICT", "BALANCED"])
def test_a_signature_the_api_could_not_check_is_unknown_never_safe(policy):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  storage.policyMode = JSON.parse(process.argv[1]);
  analyze = async () => ({error: 'API error 503: unavailable'});
  await intercept('request', {signMethod: 'personal_sign', data: '0x68656c6c6f', chainId: 56}, 'personal_sign');
  const html = overlay().innerHTML;
  assert.deepEqual(overlay().querySelector('.shieldai-badge').className.split(/\s+/), ['shieldai-badge', 'shieldai-badge-unknown']);
  assert(html.includes('UNKNOWN') && !html.includes('>SAFE<'), html);
  assert(html.includes('Why: Could not reach the ShieldAI API: API error 503: unavailable'), html);
  assert(html.includes('hello'), 'the message is no longer shown');
  const strict = storage.policyMode === 'STRICT';
  assert.equal(html.includes('id="shieldai-proceed"'), !strict);
  assert.equal(html.includes('Strict mode is on'), strict);
""",
        policy,
    )


@pytest.mark.parametrize("policy", ["STRICT", "BALANCED"])
@pytest.mark.parametrize("outcome", ["SAFE", "CAUTION", "UNKNOWN", "BLOCK_RECOMMENDED"])
def test_strict_mode_removes_sign_anyway_on_unknown_and_block_signature_verdicts(policy, outcome):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  const [policy, outcome] = JSON.parse(process.argv[1]);
  storage.policyMode = policy;
  analyze = async () => ({result: scan(outcome === 'UNKNOWN'
    ? {status: 'unknown', coverage: {signature: 0}, coverage_reasons: {signature: 'Spender facts unknown'}}
    : {classification: outcome, risk_score: {SAFE: 0, CAUTION: 40, BLOCK_RECOMMENDED: 90}[outcome]})});
  const typed = {primaryType: 'Mail', domain: {name: 'Mail'}, message: {contents: 'hi'}};
  await intercept('request', {signMethod: 'eth_signTypedData_v4', typedData: typed, chainId: 56}, 'eth_signTypedData_v4');
  const html = overlay().innerHTML;
  const removed = policy === 'STRICT' && ['UNKNOWN', 'BLOCK_RECOMMENDED'].includes(outcome);
  assert.equal(html.includes('id="shieldai-proceed"'), !removed, html);
  assert.equal(html.includes('Strict mode is on'), removed);
  if (outcome === 'UNKNOWN') assert(html.includes('Why: Spender facts unknown'), html);
""",
        [policy, outcome],
    )


@pytest.mark.parametrize("outcome", ["SAFE", "error"])
def test_eth_sign_is_always_block_recommended_and_says_why(outcome):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  analyze = async () => JSON.parse(process.argv[1]) === 'error' ? {error: 'timeout'} : {result: scan({})};
  await intercept('request', {signMethod: 'eth_sign', data: '0x' + 'ab'.repeat(32), chainId: 56}, 'eth_sign');
  assert.equal(analyses.length, 1);
  const html = overlay().innerHTML;
  assert(overlay().querySelector('.shieldai-badge').className.includes('shieldai-badge-block'), html);
  assert(html.includes('BLOCK RECOMMENDED'), html);
  assert(html.includes('RAW HASH SIGNATURE'), html);
  assert(html.includes('can be a transaction'), 'no plain explanation that eth_sign can sign a transaction');
""",
        outcome,
    )


def test_background_sends_signatures_without_their_message_bodies():
    run_node(
        BACKGROUND_HARNESS
        + r"""
(async () => {
  const from = '0x' + 'b'.repeat(40);
  const typed = {types: {Mail: []}, primaryType: 'Mail', domain: {name: 'Mail', chainId: 56}, message: {contents: 'hi'}};
  for (const tx of [
    {signMethod: 'personal_sign', from, data: '0x68656c6c6f', chainId: 56},
    {signMethod: 'eth_sign', from, data: '0x' + 'ab'.repeat(32), chainId: 56},
    {signMethod: 'eth_signTypedData_v4', from, data: '0x', typedData: typed, chainId: 56},
    {signMethod: 'eth_signTypedData_v1', from, data: '0x', typedData: [{type: 'string', name: 'Message', value: 'Hi'}], chainId: 56},
  ]) {
    const response = await respond({type: 'SHIELDAI_ANALYZE', tx});
    assert.equal(response.error, undefined);
  }
  assert.equal(bodies.length, 4, 'a signature did not reach the API');
  for (const body of bodies) {
    assert.equal(body.to, '');
    assert.equal(body.from, from);
    assert.equal(body.chainId, 56);
    // Neither a message nor a hash to sign leaves the browser; the API does not read them.
    assert.equal(body.data, '0x');
  }
  assert.deepEqual(bodies.map(body => body.signMethod),
    ['personal_sign', 'eth_sign', 'eth_signTypedData_v4', 'eth_signTypedData_v1']);
  assert.deepEqual(bodies[2].typedData, typed);
  // MetaMask's legacy list of fields is not EIP-712 typed data; the API reads its absence as unknown.
  assert.equal('typedData' in bodies[3], false);
"""
    )


def test_a_signature_without_a_wallet_chain_is_not_sent_to_the_api():
    run_node(
        BACKGROUND_HARNESS
        + r"""
(async () => {
  const response = await respond({type: 'SHIELDAI_ANALYZE', tx: {signMethod: 'personal_sign', data: '0x00', chainId: null}});
  assert.equal(bodies.length, 0);
  assert.equal(response.result.status, 'unknown');
  assert.equal(response.result.classification, 'UNKNOWN');
  assert.equal(response.result.coverage.chain, false);
"""
    )


def test_a_signature_is_analysed_on_the_wallet_chain_and_forwarded_as_sent():
    run_node(
        FRAME_HARNESS.replace("JSON.parse(process.argv[1]);", "['top', 'content-first', false];", 1)
        + r"""
(async () => {
  const analysed = [];
  const send = chrome.runtime.sendMessage;
  chrome.runtime.sendMessage = async message => {
    if (message.type === 'SHIELDAI_ANALYZE') analysed.push(message.tx);
    return send(message);
  };
  const params = ['0x68656c6c6f', '0x' + 'b'.repeat(40)];
  const pending = provider.request({method: 'personal_sign', params});
  const proceed = await proceedButton();
  assert.equal(analysed.length, 1);
  assert.equal(analysed[0].chainId, 56, 'the signature was not analysed on the wallet chain');
  assert.equal(sent.length, 0);
  proceed.dispatch('click', {isTrusted: true});
  assert.equal(await pending, 'sent');
  assert.deepEqual(plain(sent[0].params), params);
  assert.equal('chainId' in sent[0], false, 'a chain was added to a signature request');
"""
    )
