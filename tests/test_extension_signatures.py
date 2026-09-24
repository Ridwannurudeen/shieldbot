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
  URL, AbortSignal, TextDecoder, console: {warn() {}, error() {}, log() {}},
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


# A Sign-In with Ethereum message as EIP-4361 lays it out, for a domain and URI.
SIWE = r"""
const siwe = ({domain = 'dapp.example', uri = 'https://dapp.example/login', statement = 'Sign in to the app.',
  tail = '\nResources:\n- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/'} = {}) =>
  `${domain} wants you to sign in with your Ethereum account:\n0x${'1234567890'.repeat(4)}\n\n` +
  (statement === null ? '' : `${statement}\n`) +
  `\nURI: ${uri}\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2021-09-30T16:25:24Z${tail}`;
const hex = text => '0x' + Buffer.from(text, 'utf8').toString('hex');
const signIn = (text, extra = {}) => ({type: 'SHIELDAI_ANALYZE', tx: {signMethod: 'personal_sign', data: text, chainId: 1, ...extra}});
"""


@pytest.mark.parametrize(
    "message",
    ["hex", "plain-text", "no-statement", "no-resources", "port-443", "optional-fields", "did-uri"],
)
def test_a_sign_in_message_for_the_requesting_page_goes_to_the_api(message):
    run_node(
        BACKGROUND_HARNESS
        + SIWE
        + r"""
(async () => {
  const text = {
    hex: siwe(),
    'plain-text': siwe(),
    'no-statement': siwe({statement: null}),
    'no-resources': siwe({tail: ''}),
    'port-443': siwe({domain: 'DApp.Example:443'}),
    'optional-fields': siwe({tail: '\nExpiration Time: 2031-09-30T16:25:24.000Z\nNot Before: 2021-09-30T16:25:24+02:00\nRequest ID: some-id@1\nResources:'}),
    'did-uri': siwe({uri: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'}),
  }[JSON.parse(process.argv[1])];
  const response = await respond(signIn(JSON.parse(process.argv[1]) === 'hex' ? hex(text) : text));
  assert.equal(bodies.length, 1, 'the sign-in message was not analysed by the API');
  assert.equal(response.result.classification, 'SAFE');
  assert.equal(response.result.status, 'ok');
  assert.notEqual((response.result.siwe || {}).state, 'mismatch');
""",
        message,
    )


@pytest.mark.parametrize("field", ["domain", "uri", "userinfo", "subdomain", "encoded-hex"])
def test_a_sign_in_message_for_another_site_is_block_recommended(field):
    run_node(
        BACKGROUND_HARNESS
        + SIWE
        + r"""
(async () => {
  const field = JSON.parse(process.argv[1]);
  const text = {
    domain: siwe({domain: 'wallet-login.example'}),
    uri: siwe({uri: 'https://wallet-login.example/login'}),
    userinfo: siwe({domain: 'wallet-login.example@dapp.example'}),
    subdomain: siwe({domain: 'app.dapp.example', uri: 'https://app.dapp.example/'}),
    'encoded-hex': siwe({domain: 'wallet-login.example'}),
  }[field];
  // The page claims to be the site in the message; only the frame's origin, which the browser
  // gives the extension, counts.
  const response = await respond(signIn(field === 'encoded-hex' ? hex(text) : text, {origin: 'https://wallet-login.example'}));
  assert.equal(bodies.length, 0, 'the API was asked although the verdict cannot change');
  const {result} = response;
  assert.equal(result.classification, 'BLOCK_RECOMMENDED');
  assert.equal(result.siwe.state, 'mismatch');
  assert.equal(result.siwe.origin, 'dapp.example');
  assert.equal(result.siwe.domain, {domain: 'wallet-login.example', uri: 'wallet-login.example',
    userinfo: 'wallet-login.example@dapp.example', subdomain: 'app.dapp.example', 'encoded-hex': 'wallet-login.example'}[field]);
""",
        field,
    )


@pytest.mark.parametrize(
    "variant",
    [
        "two-blank-lines",
        "version-2",
        "short-nonce",
        "bad-issued-at",
        "trailing-newline",
        "crlf",
        "unknown-field",
        "relative-uri",
        "statement-on-two-lines",
        "short-address",
        "not-first-line",
    ],
)
def test_a_message_that_looks_like_sign_in_but_is_not_eip_4361_is_unknown(variant):
    run_node(
        BACKGROUND_HARNESS
        + SIWE
        + r"""
(async () => {
  const text = {
    'two-blank-lines': siwe({statement: null}).replace('\n\n\nURI', '\n\nURI'),
    'version-2': siwe().replace('Version: 1', 'Version: 2'),
    'short-nonce': siwe().replace('Nonce: 32891756', 'Nonce: 1234'),
    'bad-issued-at': siwe().replace('2021-09-30T16:25:24Z', 'yesterday'),
    'trailing-newline': siwe() + '\n',
    crlf: siwe().replace(/\n/g, '\r\n'),
    'unknown-field': siwe({tail: '\nSession: 7'}),
    'relative-uri': siwe({uri: '/login'}),
    'statement-on-two-lines': siwe({statement: 'Sign in\nplease.'}),
    'short-address': siwe().replace('0x' + '1234567890'.repeat(4), '0x1234'),
    'not-first-line': 'Hello!\n' + siwe({domain: 'wallet-login.example'}),
  }[JSON.parse(process.argv[1])];
  const {result} = await respond(signIn(text));
  assert.equal(bodies.length, 1, 'the signature was not analysed by the API');
  assert.equal(result.status, 'unknown');
  assert.notEqual(result.classification, 'SAFE');
  assert.equal(result.siwe.state, 'unreadable');
  assert.equal(result.coverage.siwe, 0);
  assert.match(result.coverage_reasons.siwe, /EIP-4361/);
""",
        variant,
    )


def test_a_personal_sign_message_that_is_not_a_sign_in_is_left_to_the_api():
    run_node(
        BACKGROUND_HARNESS
        + SIWE
        + r"""
(async () => {
  for (const data of [hex('hello'), 'hello', '0xff00ff']) {
    const {result} = await respond(signIn(data));
    assert.equal(result.classification, 'SAFE');
    assert.equal(result.siwe, undefined);
  }
  assert.equal(bodies.length, 3);
"""
    )


@pytest.mark.parametrize("policy", ["STRICT", "BALANCED"])
def test_the_overlay_names_both_domains_of_a_sign_in_mismatch(policy):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  storage.policyMode = JSON.parse(process.argv[1]);
  analyze = async () => ({result: {status: 'ok', partial: false, classification: 'BLOCK_RECOMMENDED', risk_score: 100,
    coverage: {siwe: 1}, coverage_reasons: {}, siwe: {state: 'mismatch', domain: 'wallet-login.example', origin: 'dapp.example'}}});
  await intercept('request', {signMethod: 'personal_sign', data: '0x00', chainId: 1}, 'personal_sign');
  const html = overlay().innerHTML;
  assert(overlay().querySelector('.shieldai-badge').className.includes('shieldai-badge-block'), html);
  assert(html.includes('This sign-in message is for wallet-login.example, but the page asking you to sign it is dapp.example'), html);
  assert.equal(html.includes('id="shieldai-proceed"'), storage.policyMode !== 'STRICT');
""",
        policy,
    )


# A Block Recommended overlay in Balanced mode, a transaction's or a signature's, and the ways to
# press and let go of its Proceed or Sign Anyway button.
HOLD = r"""
async function blockOverlay(kind) {
  const block = {classification: 'BLOCK_RECOMMENDED', risk_score: 95};
  analyze = async () => ({result: scan(block)});
  if (kind === 'signature') {
    await intercept('request', {signMethod: 'eth_signTypedData_v4', chainId: 1,
      typedData: {primaryType: 'Mail', domain: {name: 'Mail'}, message: {contents: 'hi'}}}, 'eth_signTypedData_v4');
  } else {
    await intercept('request');
  }
  return byId('shieldai-proceed');
}
const press = (button, how) => how === 'pointer'
  ? button.dispatch('pointerdown', {isTrusted: true})
  : button.dispatch('keydown', {key: how, isTrusted: true});
const release = (button, how) => how === 'pointer'
  ? button.dispatch('pointerup', {isTrusted: true})
  : button.dispatch('keyup', {key: how, isTrusted: true});
// The verdict of a completed hold, whose proof is made after the hold's timer: waited for, not
// assumed to be there after one flush, which a loaded machine can overrun.
async function heldVerdict() {
  for (let i = 0; i < 10 && verdicts().length === 0; i++) await flush();
}
"""


@pytest.mark.parametrize("kind", ["transaction", "signature"])
@pytest.mark.parametrize("how", ["pointer", "Enter", " "])
def test_proceed_on_block_recommended_needs_a_hold(kind, how):
    run_node(
        CONTENT_HARNESS
        + HOLD
        + r"""
(async () => {
  const [kind, how] = JSON.parse(process.argv[1]);
  const proceed = await blockOverlay(kind);
  const html = overlay().innerHTML;
  assert(html.includes(kind === 'signature' ? 'Hold to Sign Anyway' : 'Hold to Proceed Anyway'), html);
  // The hold is explained to assistive technology and on screen.
  const note = byId(proceed.attrs['aria-describedby']);
  assert(note && html.includes('for 1.5 seconds'), html);
  // A click, however real, is not a hold.
  userClick(proceed);
  await flush();
  assert.deepEqual(verdicts(), []);
  // Letting go early cancels, and the fill empties.
  press(proceed, how);
  assert(proceed.classList.contains('shieldai-holding'), 'no progress is shown while held');
  release(proceed, how);
  assert(!proceed.classList.contains('shieldai-holding'));
  await flush();
  assert.deepEqual(verdicts(), [], 'an early release proceeded');
  // A synthetic press is ignored.
  proceed.dispatch(how === 'pointer' ? 'pointerdown' : 'keydown', {key: how, isTrusted: false});
  await flush();
  assert.deepEqual(verdicts(), []);
  // Held to the end, it proceeds.
  press(proceed, how);
  await heldVerdict();
  await assertVerdicts([['request', 'proceed']]);
""",
        [kind, how],
    )


@pytest.mark.parametrize("cover", ["covered-throughout", "covered-and-uncovered-during-the-hold"])
def test_a_hold_counts_only_while_the_dialog_stays_visible(cover):
    run_node(
        CONTENT_HARNESS
        + HOLD
        + r"""
(async () => {
  const cover = JSON.parse(process.argv[1]);
  const proceed = await blockOverlay('transaction');
  press(proceed, 'pointer');
  reportVisibility(false);
  if (cover === 'covered-and-uncovered-during-the-hold') {
    clock += 10;
    reportVisibility(true);
  }
  await flush();
  assert.deepEqual(verdicts(), [], 'a hold the page covered proceeded');
  assert(byId('shieldai-covered').textContent.includes('covering or altering'));
  // Pressed again while the dialog is visible, the hold counts.
  reportVisibility(true);
  press(proceed, 'pointer');
  await heldVerdict();
  await assertVerdicts([['request', 'proceed']]);
""",
        cover,
    )


@pytest.mark.parametrize("outcome", ["CAUTION", "HIGH_RISK", "UNKNOWN"])
def test_only_block_recommended_asks_for_a_hold(outcome):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  const outcome = JSON.parse(process.argv[1]);
  analyze = async () => ({result: scan(outcome === 'UNKNOWN'
    ? {status: 'unknown', coverage: {honeypot: 0}, coverage_reasons: {honeypot: 'No provider'}}
    : {classification: outcome, risk_score: 60})});
  await intercept('request');
  assert(!overlay().innerHTML.includes('Hold to'), overlay().innerHTML);
  userClick(byId('shieldai-proceed'));
  await flush();
  await assertVerdicts([['request', 'proceed']]);
""",
        outcome,
    )


# A recipient the user sent to, and addresses that share its first and last four hex characters.
LOOKALIKE = r"""
const past = '0xabcd' + '1'.repeat(32) + 'ef01';
const poisoned = '0xabcd' + '9'.repeat(32) + 'ef01';
const transfer = to => '0xa9059cbb' + '0'.repeat(24) + to.slice(2) + '0'.repeat(63) + '1';
const lookalikeShown = () => overlay().innerHTML.includes('looks like an address you have sent to before');
"""


@pytest.mark.parametrize("kind", ["native", "erc20-transfer", "api-unreachable"])
def test_a_recipient_that_looks_like_a_past_one_is_warned_about(kind):
    run_node(
        CONTENT_HARNESS
        + LOOKALIKE
        + r"""
(async () => {
  const kind = JSON.parse(process.argv[1]);
  storage.sentRecipients = [past];
  analyze = async () => kind === 'api-unreachable' ? {error: 'timeout'} : {result: scan({})};
  const tx = kind === 'erc20-transfer'
    ? {to: '0x' + 'c'.repeat(40), data: transfer(poisoned), chainId: 56}
    : {to: poisoned.toUpperCase().replace('0X', '0x'), data: '0x', chainId: 56};
  await intercept('request', tx);
  const html = overlay().innerHTML;
  assert(lookalikeShown(), html);
  // Both addresses in full, the middle of each marked.
  for (const address of [poisoned, past]) {
    assert(html.includes(`${address.slice(0, 6)}<mark class="shieldai-diff">${address.slice(6, -4)}</mark>${address.slice(-4)}`), html);
  }
  if (kind !== 'api-unreachable') {
    // A SAFE verdict is not shown next to the warning.
    assert(overlay().querySelector('.shieldai-badge').className.includes('shieldai-badge-high'), html);
    assert(!/shieldai-verdict">\s*SAFE/.test(html), html);
  }
""",
        kind,
    )


@pytest.mark.parametrize(
    "recipient",
    ["the-same-address", "another-start", "another-end", "a-contract-call", "no-history"],
)
def test_no_lookalike_warning_without_a_lookalike(recipient):
    run_node(
        CONTENT_HARNESS
        + LOOKALIKE
        + r"""
(async () => {
  const recipient = JSON.parse(process.argv[1]);
  storage.sentRecipients = recipient === 'no-history' ? [] : [past];
  analyze = async () => ({result: scan({})});
  const to = {
    'the-same-address': past, 'another-start': '0xabce' + '9'.repeat(32) + 'ef01',
    'another-end': '0xabcd' + '9'.repeat(32) + 'ef02', 'a-contract-call': poisoned, 'no-history': poisoned,
  }[recipient];
  // An approve to the look-alike is not a send to it.
  const data = recipient === 'a-contract-call' ? '0x095ea7b3' + '0'.repeat(24) + poisoned.slice(2) + '0'.repeat(64) : '0x';
  await intercept('request', {to, data, chainId: 56});
  assert(!lookalikeShown(), overlay().innerHTML);
""",
        recipient,
    )


@pytest.mark.parametrize("decision", ["proceed", "block", "signature"])
def test_only_a_recipient_the_user_proceeded_with_is_remembered(decision):
    run_node(
        CONTENT_HARNESS
        + LOOKALIKE
        + r"""
(async () => {
  const decision = JSON.parse(process.argv[1]);
  // A full history keeps its newest hundred.
  storage.sentRecipients = Array.from({length: 100}, (_, i) => '0x' + i.toString(16).padStart(40, '0'));
  analyze = async () => ({result: scan({})});
  if (decision === 'signature') {
    await intercept('request', {signMethod: 'personal_sign', data: '0x00', to: past, chainId: 56}, 'personal_sign');
  } else {
    await intercept('request', {to: '0x' + 'c'.repeat(40), data: transfer(past), chainId: 56});
  }
  userClick(byId(decision === 'block' ? 'shieldai-block' : 'shieldai-proceed'));
  await flush();
  const kept = decision === 'proceed';
  assert.equal(storage.sentRecipients[0] === past, kept);
  assert.equal(storage.sentRecipients.length, 100);
  if (kept) assert.equal(storage.sentRecipients.at(-1), '0x' + (98).toString(16).padStart(40, '0'));
""",
        decision,
    )


def test_a_lookalike_of_a_real_send_is_warned_about_end_to_end():
    run_node(
        FRAME_HARNESS.replace("JSON.parse(process.argv[1]);", "['top', 'content-first', false];", 1)
        + LOOKALIKE.replace(
            "const lookalikeShown = () => overlay().innerHTML",
            "const lookalikeShown = () => overlayRoot().getElementById('shieldai-overlay').innerHTML",
        )
        + r"""
(async () => {
  // The page asks for a send, the user proceeds, and the wallet gets it.
  const first = provider.request({method: 'eth_sendTransaction', params: [{to: past, value: '0x1'}]});
  (await proceedButton()).dispatch('click', {isTrusted: true});
  assert.equal(await first, 'sent');
  assert.deepEqual(plain(storage.sentRecipients), [past]);
  // A later send to an address made to look like it is warned about.
  const second = provider.request({method: 'eth_sendTransaction', params: [{to: poisoned, value: '0x1'}]});
  second.catch(() => {});
  await proceedButton();
  assert(lookalikeShown(), 'no warning for a look-alike of a past recipient');
  // A page cannot add to the history: a request it only shows or that the user blocks is not kept.
  overlayRoot().getElementById('shieldai-block').dispatch('click', {isTrusted: true});
  await assert.rejects(second, /blocked/);
  assert.deepEqual(plain(storage.sentRecipients), [past]);
"""
    )
