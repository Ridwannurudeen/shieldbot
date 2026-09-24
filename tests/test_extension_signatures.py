"""Signature requests, sign-in messages, delegations, look-alike recipients and the decision rules
added around them, run in the harnesses of test_extension_overlay_behaviour.

Every checked signing method is analysed by the API like a transaction, and what the overlay can
see for itself (a raw eth_sign, typed data it cannot read) only raises the API's verdict.
"""

import pytest

from tests.test_extension_overlay_behaviour import (
    CONTENT_HARNESS,
    FRAME_HARNESS,
    INJECT_HARNESS,
    run_node,
)

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


# background.js's answer when the wallet chain cannot be read or does not match the request.
UNKNOWN_CHAIN = r"""
const unknownChain = {status: 'unknown', partial: true, classification: 'UNKNOWN', risk_level: 'UNKNOWN',
  risk_score: null, coverage: {chain: false},
  coverage_reasons: {chain: 'Wallet chain unavailable, invalid, or mismatched; the request was not analyzed.'}};
"""


@pytest.mark.parametrize("policy", ["STRICT", "BALANCED"])
@pytest.mark.parametrize("kind", ["transaction", "signature", "batch-call-on-another-chain"])
def test_an_unknown_or_unsupported_chain_leaves_only_block(policy, kind):
    run_node(
        CONTENT_HARNESS
        + UNKNOWN_CHAIN
        + r"""
(async () => {
  const [policy, kind] = JSON.parse(process.argv[1]);
  storage.policyMode = policy;
  analyze = async () => ({result: unknownChain});
  if (kind === 'transaction') await intercept('request', {to: '0x' + 'a'.repeat(40), chainId: null});
  if (kind === 'signature') await intercept('request', {signMethod: 'personal_sign', data: '0x68656c6c6f', chainId: null}, 'personal_sign');
  if (kind === 'batch-call-on-another-chain') {
    await intercept('request', {unknownStructure: true, wrongChain: true}, 'wallet_sendCalls');
  }
  const html = overlay().innerHTML;
  assert(!html.includes('id="shieldai-proceed"'), 'a Proceed that can only be rejected was offered');
  assert(html.includes('could not confirm which network'), html);
  if (kind !== 'batch-call-on-another-chain') assert(html.includes('Why: Wallet chain unavailable'), html);
  userClick(byId('shieldai-block'));
  await flush();
  await assertVerdicts([['request', 'block']]);
""",
        [policy, kind],
    )


def test_a_batch_call_on_another_chain_is_marked_for_the_overlay():
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  const calls = [{to: '0x' + 'a'.repeat(40)}, {to: '0x' + 'c'.repeat(40), chainId: '0x1'}];
  provider.request({method: 'wallet_sendCalls', params: [{version: '2.0.0', chainId: '0x38', calls}]}).catch(() => {});
  await flush();
  const {tx} = posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').at(-1);
  assert.equal(tx.unknownStructure, true);
  assert.equal(tx.wrongChain, true);
  // A request that cannot be read at all is not about the chain.
  provider.request({method: 'eth_sendTransaction', params: ['not an object']}).catch(() => {});
  await flush();
  const unreadable = posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').at(-1).tx;
  assert.equal(unreadable.unknownStructure, true);
  assert.equal(unreadable.wrongChain, undefined);
"""
    )


def test_an_unsupported_chain_is_answered_as_an_unknown_chain():
    run_node(
        BACKGROUND_HARNESS
        + r"""
(async () => {
  answer = async () => ({ok: false, status: 400,
    text: async () => JSON.stringify({detail: 'Unsupported chain ID 324. Supported chain IDs: 1, 56'})});
  const response = await respond({type: 'SHIELDAI_ANALYZE', tx: {to: '0x' + 'a'.repeat(40), chainId: 324}});
  assert.equal(response.error, undefined);
  assert.equal(response.result.status, 'unknown');
  assert.equal(response.result.classification, 'UNKNOWN');
  assert.equal(response.result.coverage.chain, false);
  assert.match(response.result.coverage_reasons.chain, /Unsupported chain ID 324/);
  // Any other refusal is still an error, shown as Analysis Unavailable.
  answer = async () => ({ok: false, status: 400, text: async () => JSON.stringify({detail: "Invalid 'to' address"})});
  const other = await respond({type: 'SHIELDAI_ANALYZE', tx: {to: 'nope', chainId: 56}});
  assert.match(other.error, /API error 400/);
"""
    )


@pytest.mark.parametrize("outcome", ["SAFE", "CAUTION", "UNKNOWN", "BLOCK_RECOMMENDED"])
def test_the_explain_button_is_not_offered_on_a_safe_verdict(outcome):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  const outcome = JSON.parse(process.argv[1]);
  analyze = async () => ({result: scan(outcome === 'UNKNOWN'
    ? {status: 'unknown', coverage: {honeypot: 0}, coverage_reasons: {honeypot: 'No provider'}}
    : {classification: outcome, risk_score: {SAFE: 0, CAUTION: 40, BLOCK_RECOMMENDED: 90}[outcome]})});
  await intercept('request');
  assert.equal(overlay().innerHTML.includes('id="shieldai-explain"'), outcome !== 'SAFE');
""",
        outcome,
    )


# A service worker that Chrome stopped and started again: a new background.js over the same
# chrome.storage.session, which lasts for the browser session.
PHISHING_WORKERS = r"""
const lookups = [];
function startWorker() {
  let onMessage;
  const worker = vm.createContext({
    chrome: {
      runtime: {onInstalled: {addListener() {}}, onMessage: {addListener(fn) { onMessage = fn; }}},
      storage: {local: area(local), session: area(session)},
    },
    URL, AbortSignal, console: {warn() {}, error() {}, log() {}},
    fetch: async url => { lookups.push(url); return answer(url); },
  });
  vm.runInContext(fs.readFileSync('extension/background.js', 'utf8'), worker);
  return url => new Promise(resolve => onMessage({type: 'SHIELDAI_CHECK_PHISHING', url}, {}, resolve));
}
const verdict = isPhishing => async () => ({ok: true, json: async () => ({is_phishing: isPhishing, url: 'https://drainer.example/claim?id=7', sources: ['goplus']})});
"""


def test_a_phishing_verdict_outlives_a_service_worker_restart():
    run_node(
        BACKGROUND_HARNESS
        + PHISHING_WORKERS
        + r"""
(async () => {
  answer = verdict(true);
  const check = startWorker();
  assert.equal((await check('https://Drainer.example/claim?id=7')).result.is_phishing, true);
  assert.equal(lookups.length, 1);
  // Only the host and the verdict are kept: no path, query or other field of the answer.
  assert.deepEqual(Object.keys(session.phishingCache), ['drainer.example']);
  assert.deepEqual(Object.keys(session.phishingCache['drainer.example']).sort(), ['expiresAt', 'is_phishing']);
  assert(!JSON.stringify(session).includes('claim'));
  const restarted = startWorker();
  assert.equal((await restarted('https://drainer.example/other')).result.is_phishing, true);
  assert.equal(lookups.length, 1, 'the restarted worker asked the API again');
  // An hour later the verdict has expired and is asked for again.
  session.phishingCache['drainer.example'].expiresAt = Date.now() - 1;
  await startWorker()('https://drainer.example/');
  assert.equal(lookups.length, 2);
"""
    )


@pytest.mark.parametrize("failure", ["http-error", "no-verdict", "network-error"])
def test_a_failed_phishing_check_is_never_kept_as_a_verdict(failure):
    run_node(
        BACKGROUND_HARNESS
        + PHISHING_WORKERS
        + r"""
(async () => {
  const failure = JSON.parse(process.argv[1]);
  answer = {
    'http-error': async () => ({ok: false, status: 503, json: async () => ({})}),
    'no-verdict': verdict(null),
    'network-error': async () => { throw new Error('offline'); },
  }[failure];
  const check = startWorker();
  const {result} = await check('https://site.example/');
  assert.equal(result.is_phishing, null);
  assert.equal((session.phishingCache || {})['site.example'], undefined, 'a failed check was kept');
  answer = verdict(false);
  assert.equal((await startWorker()('https://site.example/')).result.is_phishing, false);
  assert.equal(lookups.length, 2, 'the failed check was not asked again');
""",
        failure,
    )
