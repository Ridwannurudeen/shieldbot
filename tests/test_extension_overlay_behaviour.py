"""Run the extension's page scripts against small DOM and Chrome doubles.

inject.js runs in the page's JavaScript world and holds the dApp's request; content.js runs in the
extension's isolated world and shows the overlay. They share a secret once at document_start and
afterwards exchange window messages that carry HMAC proofs, never the secret. These tests drive both
through those messages and check that a page script cannot read the secret, forge a message, or
make the user's decision for them.
"""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parent.parent

# A DOM double: elements parse the tags out of the innerHTML string they are given, which is all
# content.js needs to find its buttons and its modal. attachShadow keeps the root on the host as
# `shadow` so the tests can look inside a closed root; content.js itself never reads it.
FAKE_DOM = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const {webcrypto} = require('crypto');
const posted = [];
// Page-side mutation observers: every removal notifies them, as a childList change would.
const observers = new Set();
class FakeMutationObserver {
  constructor(callback) { this.callback = callback; }
  observe() { observers.add(this); }
  disconnect() { observers.delete(this); }
}
class El {
  constructor(tag, root, index) {
    this.tagName = tag.toUpperCase(); this.attrs = {}; this.listeners = {}; this.style = {};
    this.children = []; this.parent = null; this.html = ''; this.root = root; this.index = index;
    this.id = ''; this.className = ''; this.disabled = false; this.hidden = false; this.textContent = '';
    this.scope = null;
  }
  set innerHTML(value) { this.html = value; this.parsed = null; }
  get innerHTML() { return this.html; }
  set textContent(value) {
    this.text = String(value);
    this.html = this.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  get textContent() { return this.text; }
  setAttribute(name, value) { this.attrs[name] = String(value); }
  getAttribute(name) { return name in this.attrs ? this.attrs[name] : null; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  dispatch(type, event = {}) {
    event.preventDefault ||= () => { event.defaultPrevented = true; };
    for (const fn of this.listeners[type] || []) fn(event);
    return event;
  }
  click() { return this.dispatch('click', {isTrusted: false}); }
  focus() {
    const scope = (this.root || this).scope;
    if (scope) { scope.activeElement = this; document.activeElement = scope.host; }
    else document.activeElement = this;
  }
  appendChild(child) { child.parent = this; this.children.push(child); return child; }
  insertBefore(child) { child.parent = this; this.children.unshift(child); return child; }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this);
    this.parent = null;
    for (const observer of [...observers]) queueMicrotask(() => observer.callback([]));
  }
  get isConnected() {
    for (let node = this; node; node = node.parent) if (node === body || node === html) return true;
    return false;
  }
  attachShadow({mode}) {
    const host = this;
    this.shadow = {
      host, mode, children: [], activeElement: null,
      appendChild(child) { child.parent = this; child.scope = this; this.children.push(child); return child; },
      getElementById(id) {
        for (const el of this.children) {
          if (el.id === id) return el;
          const found = el.descendants().find(child => child.id === id);
          if (found) return found;
        }
        return null;
      },
    };
    return this.shadow;
  }
  descendants() {
    if (this.root) return this.root.descendants().slice(this.index + 1);
    if (!this.parsed) {
      this.parsed = [...this.html.matchAll(/<(\w+)([^>]*)>/g)].map((match, index) => {
        const el = new El(match[1], this, index);
        for (const attr of match[2].matchAll(/([\w-]+)="([^"]*)"/g)) el.attrs[attr[1]] = attr[2];
        el.id = el.attrs.id || ''; el.className = el.attrs.class || '';
        return el;
      });
    }
    return this.parsed;
  }
  querySelectorAll(selector) {
    const all = this.descendants();
    if (selector.startsWith('.')) return all.filter(el => el.className.split(/\s+/).includes(selector.slice(1)));
    const tag = selector.split(':')[0].toUpperCase();
    return all.filter(el => el.tagName === tag && !(selector.includes(':not([disabled])') && el.disabled));
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  contains(el) { return el === this || this.descendants().includes(el); }
}
const body = new El('body'), head = new El('head'), html = new El('html');
const document = Object.assign(new EventTarget(), {
  body, head, documentElement: html, activeElement: body,
  createElement: tag => new El(tag),
  // Light DOM only, like the real one: nothing inside a shadow root is found.
  getElementById(id) {
    return [...body.children, ...html.children].find(el => el.id === id) || null;
  },
});
const windowListeners = {};
const window = {
  addEventListener(type, fn) { (windowListeners[type] ||= []).push(fn); },
  removeEventListener(type, fn) { windowListeners[type] = (windowListeners[type] || []).filter(f => f !== fn); },
  postMessage(data) { posted.push(data); },
  location: {href: 'https://dapp.example/', hostname: 'dapp.example'},
  history: {length: 1},
};
window.top = window;
function deliver(data) { for (const fn of [...(windowListeners.message || [])]) fn({source: window, data}); }
const flush = () => new Promise(resolve => setTimeout(resolve, 60));
// Taken now, so the tests' own proofs stay right after a test replaces page built-ins.
const hImport = webcrypto.subtle.importKey.bind(webcrypto.subtle), hSign = webcrypto.subtle.sign.bind(webcrypto.subtle);
const hEncode = TextEncoder.prototype.encode.bind(new TextEncoder());
async function proofFor(token, message) {
  const key = await hImport('raw', hEncode(token), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  return new Uint8Array(await hSign('HMAC', key, hEncode(message)));
}
const bytes = value => Array.from(value || []);
const plain = value => JSON.parse(JSON.stringify(value));
"""

CONTENT_HARNESS = (
    FAKE_DOM
    + r"""
const storage = {language: 'en'};
const analyses = [];
let analyze = async () => ({error: 'API error 503: unavailable'});
let phishing = false, phishingChecks = 0;
let clock = 1000000;
let fetchDelays = [];
const chrome = {
  storage: {local: {get(defaults, cb) { cb({...defaults, ...storage}); }}},
  runtime: {
    getURL: path => 'chrome-extension://id/' + path,
    async sendMessage(message) {
      if (message.type === 'SHIELDAI_ANALYZE') { analyses.push(message.tx); return analyze(message.tx); }
      phishingChecks++;
      return {result: {is_phishing: phishing}};
    },
  },
};
const context = vm.createContext({
  window, document, chrome, crypto: webcrypto, TextEncoder, TextDecoder, CustomEvent, setTimeout, clearTimeout,
  console, Date: {now: () => clock}, MutationObserver: FakeMutationObserver,
  fetch: async url => {
    const delay = fetchDelays.shift();
    if (delay) await new Promise(resolve => setTimeout(resolve, delay));
    return {json: async () => JSON.parse(fs.readFileSync(url.replace('chrome-extension://id/', 'extension/'), 'utf8'))};
  },
});
vm.runInContext(fs.readFileSync('extension/content.js', 'utf8'), context);
// Play inject.js's side of the document_start handoff: it starts after content.js and asks.
let token = null;
document.addEventListener('shieldai:channel', event => { token = event.detail; event.preventDefault(); });
document.dispatchEvent(new CustomEvent('shieldai:channel-request'));
function overlayRoot() { const host = body.children.find(el => el.shadow); return host ? host.shadow : null; }
function overlay() { const root = overlayRoot(); return root ? root.getElementById('shieldai-overlay') : null; }
function byId(id) { return overlayRoot().getElementById(id); }
function userClick(el) { el.dispatch('click', {isTrusted: true}); }
function userKey(key, extra = {}) { return overlay().dispatch('keydown', {key, isTrusted: true, ...extra}); }
function verdicts() {
  return posted.filter(message => message.type === 'SHIELDAI_TX_VERDICT')
    .map(({requestId, action, proof}) => ({requestId, action, proof: bytes(proof)}));
}
async function assertVerdicts(expected) {
  const actual = verdicts();
  assert.deepEqual(actual.map(({requestId, action}) => [requestId, action]), expected);
  for (const {requestId, action, proof} of actual) {
    assert.deepEqual(proof, bytes(await proofFor(token, `${requestId}:${action}`)));
  }
}
async function intercept(requestId, tx = {to: '0x' + 'a'.repeat(40), chainId: 56}, method = 'eth_sendTransaction') {
  deliver({type: 'SHIELDAI_TX_INTERCEPT', requestId, method, tx, proof: await proofFor(token, `${requestId}:intercept`)});
  await flush();
}
const scan = (fields) => ({
  status: 'ok', partial: false, classification: 'SAFE', risk_score: 0, coverage: {honeypot: 1},
  coverage_reasons: {}, verdict: 'SAFE', plain_english: 'SAFE', transaction_impact: {}, ...fields,
});
"""
)


def run_node(script, argument=None):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for extension JavaScript regression tests")
    result = subprocess.run(
        [
            node,
            "-e",
            script
            + "\n})().then(() => console.log('completed')).catch(error => {console.error(error); process.exitCode = 1;});",
            "--",
            json.dumps(argument),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "completed" in result.stdout, result.stdout + result.stderr


def test_token_is_handed_over_once_at_document_start():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  assert.match(token, /^[0-9a-f-]{32,36}$/);
  let second = null;
  document.addEventListener('shieldai:channel', event => { second = event.detail; });
  document.dispatchEvent(new CustomEvent('shieldai:channel-request'));
  assert.equal(second, null, 'content.js answered a second request, which a page script could send');
"""
    )


def test_content_script_uses_the_default_api_when_storage_has_no_url():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  analyze = async () => ({result: scan({})});
  await intercept('first');
  assert.equal(analyses.length, 1, 'the transaction was not sent for analysis');
  assert(!overlay().innerHTML.includes('Setup Required'));
"""
    )


def test_overlay_lives_in_a_closed_shadow_root_and_the_page_head_stays_clean():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  analyze = async () => ({result: scan({})});
  await intercept('request');
  const hosts = body.children.filter(el => el.shadow);
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].shadow.mode, 'closed');
  assert.equal(document.getElementById('shieldai-proceed'), null, 'overlay content is reachable from the page');
  assert.deepEqual(head.children, [], 'content.js added a script or stylesheet to the page head');
  const link = hosts[0].shadow.children.find(el => el.tagName === 'LINK');
  assert.equal(link.href, 'chrome-extension://id/overlay.css');
"""
    )


@pytest.mark.parametrize("kind", ["analysis", "signature", "error"])
def test_synthetic_input_cannot_decide_for_the_user(kind):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  const kind = JSON.parse(process.argv[1]);
  analyze = async () => kind === 'error' ? {error: 'timeout'} : {result: scan({})};
  if (kind === 'signature') {
    await intercept('request', {signMethod: 'personal_sign', data: '0x68656c6c6f'}, 'personal_sign');
  } else {
    await intercept('request');
  }
  byId('shieldai-proceed').click();
  byId('shieldai-block').click();
  overlay().dispatch('keydown', {key: 'Escape', isTrusted: false});
  await flush();
  assert.deepEqual(verdicts(), [], 'a synthetic event decided the request');
  assert(overlay(), 'a synthetic event closed the overlay');
  userClick(byId('shieldai-proceed'));
  await flush();
  await assertVerdicts([['request', 'proceed']]);
""",
        kind,
    )


def test_messages_after_the_handoff_never_carry_the_token():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  analyze = async () => ({result: scan({})});
  await intercept('first');
  userClick(byId('shieldai-proceed'));
  await flush();
  await intercept('second');
  await intercept('third');
  userKey('Escape');
  storage.enabled = false;
  await intercept('fourth');
  await flush();
  await assertVerdicts([['first', 'proceed'], ['second', 'block'], ['third', 'block'], ['fourth', 'proceed']]);
  assert(posted.length >= 7);
  for (const message of posted) {
    assert(!JSON.stringify(message).includes(token), `the token was posted: ${JSON.stringify(message)}`);
    assert(!('_ct' in message));
  }
"""
    )


@pytest.mark.parametrize(
    "forgery", ["no-proof", "token-as-proof", "shown-proof", "other-request-proof"]
)
def test_forged_and_replayed_intercepts_are_ignored(forgery):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  const forgery = JSON.parse(process.argv[1]);
  analyze = async () => ({result: scan({})});
  const proofs = {
    'no-proof': undefined,
    'token-as-proof': token,
    'shown-proof': await proofFor(token, 'fake:shown'),
    'other-request-proof': await proofFor(token, 'other:intercept'),
  };
  deliver({type: 'SHIELDAI_TX_INTERCEPT', requestId: 'fake', method: 'personal_sign',
    tx: {signMethod: 'personal_sign', data: '0x00'}, proof: proofs[forgery]});
  await flush();
  assert.equal(overlay(), null, 'the page opened an overlay');
  assert.equal(analyses.length, 0);

  const real = {to: '0x' + 'd'.repeat(40), data: '0x095ea7b3', chainId: 56};
  await intercept('real', real);
  const replay = posted.length;
  deliver({type: 'SHIELDAI_TX_INTERCEPT', requestId: 'real', method: 'eth_sendTransaction',
    tx: {to: '0x' + 'e'.repeat(40), chainId: 56}, proof: await proofFor(token, 'real:intercept')});
  await flush();
  assert.equal(analyses.length, 1, 'a replayed request id was analysed again');
  assert.deepEqual(plain(analyses[0]), real);
  assert.equal(posted.length, replay, 'a replayed request id changed what was shown');
""",
        forgery,
    )


@pytest.mark.parametrize("policy", ["STRICT", "BALANCED"])
@pytest.mark.parametrize("outcome", ["error", "BLOCK_RECOMMENDED", "CAUTION", "UNKNOWN"])
def test_strict_mode_removes_proceed_on_errors_block_and_unknown_verdicts(policy, outcome):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  const [policy, outcome] = JSON.parse(process.argv[1]);
  storage.policyMode = policy;
  analyze = async () => outcome === 'error' ? {error: 'API error 429: Too many requests'} : {result: scan(
    outcome === 'UNKNOWN' ? {status: 'unknown', coverage: {honeypot: 0}, coverage_reasons: {honeypot: 'No provider'}}
      : {classification: outcome, risk_score: outcome === 'CAUTION' ? 40 : 90})};
  await intercept('request');
  const html = overlay().innerHTML;
  const removed = policy === 'STRICT' && outcome !== 'CAUTION';
  assert.equal(html.includes('id="shieldai-proceed"'), !removed);
  assert.equal(html.includes('Strict mode is on'), removed);
  userClick(byId('shieldai-block'));
  await flush();
  await assertVerdicts([['request', 'block']]);
""",
        [policy, outcome],
    )


@pytest.mark.parametrize("kind", ["analysis", "error", "signature"])
def test_overlay_is_a_modal_dialog_that_keeps_focus_and_rejects_on_escape(kind):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  const kind = JSON.parse(process.argv[1]);
  analyze = async () => kind === 'error' ? {error: 'timeout'} : {result: scan({})};
  if (kind === 'signature') {
    await intercept('request', {signMethod: 'personal_sign', data: '0x68656c6c6f'}, 'personal_sign');
  } else {
    await intercept('request');
  }
  const root = overlayRoot();
  const modal = overlay().querySelector('.shieldai-modal');
  assert.equal(modal.attrs.role, 'dialog');
  assert.equal(modal.attrs['aria-modal'], 'true');
  assert.equal(root.getElementById(modal.attrs['aria-labelledby']).tagName, 'H2');
  assert.equal(root.activeElement, modal, 'focus did not move into the dialog');
  const buttons = modal.querySelectorAll('button');
  const seen = new Set();
  for (let i = 0; i < buttons.length + 1; i++) {
    assert(userKey('Tab').defaultPrevented);
    assert(buttons.includes(root.activeElement), 'Tab left the dialog');
    seen.add(root.activeElement);
  }
  assert.equal(seen.size, buttons.length, 'Tab did not reach every button');
  userKey('Tab', {shiftKey: true});
  assert(buttons.includes(root.activeElement));
  assert.equal(verdicts().length, 0);
  userKey('Escape');
  await flush();
  await assertVerdicts([['request', 'block']]);
  assert.equal(overlay(), null);
""",
        kind,
    )


def test_focus_that_leaves_the_overlay_returns_to_the_dialog():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  analyze = async () => ({result: scan({})});
  await intercept('request');
  const root = overlayRoot();
  const modal = overlay().querySelector('.shieldai-modal');
  const explain = byId('shieldai-explain');
  explain.focus();
  explain.click();
  assert(explain.disabled, 'the explain button should disable itself');
  overlay().dispatch('focusout', {target: explain, relatedTarget: null});
  assert.equal(root.activeElement, modal, 'focus was lost when the focused button was disabled');
  const block = byId('shieldai-block');
  block.focus();
  overlay().dispatch('focusout', {target: explain, relatedTarget: block});
  assert.equal(root.activeElement, block, 'focus moving inside the dialog must stay where it went');
"""
    )


def test_shown_signal_proves_the_request_without_revealing_the_token():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  analyze = async () => ({result: scan({})});
  await intercept('request');
  const shown = posted.filter(message => message.type === 'SHIELDAI_TX_SHOWN');
  assert.equal(shown.length, 1);
  assert.equal(shown[0].requestId, 'request');
  assert.deepEqual(bytes(shown[0].proof), bytes(await proofFor(token, 'request:shown')));
  assert.equal(verdicts().length, 0, 'a verdict was sent before the user decided');
"""
    )


def test_replaced_overlay_rejects_the_request_it_was_showing():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  analyze = async () => ({result: scan({})});
  await intercept('first');
  await intercept('second');
  await assertVerdicts([['first', 'block']]);
  userClick(byId('shieldai-proceed'));
  await flush();
  await assertVerdicts([['first', 'block'], ['second', 'proceed']]);
"""
    )


def test_loading_overlay_cannot_replace_a_quick_result():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  // The loading screen's language file arrives after the error screen's.
  fetchDelays = [40, 0];
  analyze = async () => ({error: 'API error 400: Unsupported chain'});
  await intercept('request');
  await flush();
  assert(overlay().innerHTML.includes('ANALYSIS UNAVAILABLE'), 'the loading screen replaced the result');
  assert.deepEqual(verdicts(), [], 'the request was rejected without the user deciding');
"""
    )


def test_late_result_shows_a_timed_out_screen_and_rejects():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  analyze = async () => { clock += 51000; return {result: scan({})}; };
  await intercept('request');
  const html = overlay().innerHTML;
  assert(html.includes('Timed out'), html);
  assert(!html.includes('id="shieldai-proceed"'));
  await assertVerdicts([['request', 'block']]);
  assert.equal(posted.filter(message => message.type === 'SHIELDAI_TX_SHOWN').length, 0);
  userClick(byId('shieldai-close'));
  assert.equal(overlay(), null);
  await flush();
  assert.equal(verdicts().length, 1);
"""
    )


@pytest.mark.parametrize(
    "state",
    ["unknown-reason", "unknown-no-reason", "covered-safe", "covered-caution", "incomplete-high"],
)
def test_unknown_result_has_its_own_badge_and_reason(state):
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  const state = JSON.parse(process.argv[1]);
  const results = {
    'unknown-reason': scan({status: 'unknown', coverage: {structural: 0}, coverage_reasons: {structural: 'Contract age unavailable'}}),
    'unknown-no-reason': scan({status: 'unknown', coverage: {}, coverage_reasons: {}}),
    'covered-safe': scan({}),
    'covered-caution': scan({classification: 'CAUTION', risk_score: 40}),
    'incomplete-high': scan({status: 'unknown', classification: 'HIGH_RISK', risk_score: 60, coverage_reasons: {honeypot: 'No provider'}}),
  };
  analyze = async () => ({result: results[state]});
  await intercept('request');
  const badge = overlay().querySelector('.shieldai-badge');
  const classes = badge.className.split(/\s+/);
  const why = overlay().querySelector('.shieldai-unknown-why');
  const html = overlay().innerHTML;
  if (state.startsWith('unknown')) {
    assert.deepEqual(classes, ['shieldai-badge', 'shieldai-badge-unknown']);
    assert(html.includes('>UNKNOWN<') || /UNKNOWN\s*<\/div>/.test(html));
    assert(!html.includes('SAFE') && !html.includes('CAUTION'));
    assert(why, 'no reason line');
    const reason = state === 'unknown-reason' ? 'Contract age unavailable' : 'Some checks did not complete.';
    assert(html.includes('Why: ' + reason));
    assert(html.includes('<td>Granting Access</td><td>Unknown</td>'), 'a missing grant must not read None');
  } else if (state === 'incomplete-high') {
    assert(classes.includes('shieldai-badge-high'));
    assert(html.includes('Why: No provider'));
  } else {
    assert(!classes.includes('shieldai-badge-unknown'));
    assert(classes.includes(state === 'covered-safe' ? 'shieldai-badge-safe' : 'shieldai-badge-caution'));
    assert.equal(why, null);
  }
  assert.equal(badge.attrs.style, undefined, 'badge colour must come from the stylesheet');
""",
        state,
    )


def test_phishing_banner_is_shielded_and_needs_a_real_click():
    run_node(
        CONTENT_HARNESS.replace("let phishing = false,", "let phishing = true,")
        + r"""
(async () => {
  await flush();
  const host = html.children.find(el => el.shadow);
  assert(host, 'no banner');
  assert.equal(host.shadow.mode, 'closed');
  assert.equal(document.getElementById('shieldai-dismiss'), null);
  const dismiss = host.shadow.getElementById('shieldai-dismiss');
  dismiss.click();
  assert(html.children.includes(host), 'a synthetic click dismissed the warning');
  userClick(dismiss);
  assert(!html.children.includes(host));
"""
    )


def test_content_script_runs_once_and_injects_nothing_into_the_page():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  let created = [];
  const createElement = document.createElement;
  document.createElement = tag => { created.push(tag); return createElement(tag); };
  vm.runInContext(fs.readFileSync('extension/content.js', 'utf8'), context);
  assert.deepEqual(created, [], 'a second run of the content script did work again');
  assert.deepEqual(head.children, []);
"""
    )


INJECT_HARNESS = (
    FAKE_DOM
    + r"""
const timers = new Map();
let nextTimer = 0, sent = [], logged = [];
const provider = {
  on() {},
  async request(args) { if (args.method === 'eth_chainId') return '0x38'; sent.push(args); return 'sent'; },
};
window.ethereum = provider;
window.dispatchEvent = () => {};
const context = vm.createContext({
  window, document, crypto: {subtle: webcrypto.subtle, randomUUID: webcrypto.randomUUID.bind(webcrypto)},
  TextEncoder, CustomEvent, structuredClone, queueMicrotask,
  Event: class { constructor(type) { this.type = type; } },
  console: new Proxy({}, {get: (_, name) => (...args) => logged.push([name, ...args])}),
  setTimeout(fn, delay) { const id = ++nextTimer; timers.set(id, {fn, delay}); return id; },
  clearTimeout(id) { timers.delete(id); }, setInterval() { return 0; }, clearInterval() {},
});
vm.runInContext(fs.readFileSync('extension/inject.js', 'utf8'), context);
// Play content.js's side of the handoff: here inject.js started first and is listening.
const accepted = !document.dispatchEvent(new CustomEvent('shieldai:channel', {detail: 'channel-token', cancelable: true}));
function fireFailClosedTimer() {
  for (const [id, timer] of timers) if (timer.delay === 60000) { timers.delete(id); timer.fn(); return true; }
  return false;
}
async function startRequest() {
  const pending = provider.request({method: 'eth_sendTransaction', params: [{to: '0x' + 'a'.repeat(40)}]});
  pending.catch(() => {});
  await flush();
  const intercept = posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').at(-1);
  return {pending, requestId: intercept.requestId, intercept};
}
const proof = (requestId, purpose) => proofFor('channel-token', `${requestId}:${purpose}`);
"""
)


@pytest.mark.parametrize(
    "shown",
    ["none", "valid", "token-as-proof", "intercept-proof", "wrong-request", "missing-proof"],
)
def test_fail_closed_timer_stops_only_for_an_authentic_shown_signal(shown):
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  const shown = JSON.parse(process.argv[1]);
  const {pending, requestId, intercept} = await startRequest();
  const proofs = {
    valid: await proof(requestId, 'shown'),
    'token-as-proof': 'channel-token',
    'intercept-proof': intercept.proof,
    'wrong-request': await proof('another-request', 'shown'),
  };
  if (shown !== 'none') deliver({type: 'SHIELDAI_TX_SHOWN', requestId, proof: proofs[shown]});
  await flush();
  const stopped = !fireFailClosedTimer();
  assert.equal(stopped, shown === 'valid');
  if (shown === 'valid') {
    deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed', proof: await proof(requestId, 'proceed')});
    assert.equal(await pending, 'sent');
  } else {
    await assert.rejects(pending, /blocked/);
    assert.equal(sent.length, 0);
  }
""",
        shown,
    )


@pytest.mark.parametrize(
    "forgery",
    [
        "no-proof",
        "old-token-field",
        "token-as-proof",
        "block-proof-as-proceed",
        "shown-proof-as-proceed",
        "intercept-proof-as-proceed",
        "shown-action",
        "other-request-proof",
    ],
)
def test_forged_verdicts_are_ignored(forgery):
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  const forgery = JSON.parse(process.argv[1]);
  const {pending, requestId, intercept} = await startRequest();
  const forged = {
    'no-proof': {action: 'proceed'},
    'old-token-field': {action: 'proceed', _ct: 'channel-token'},
    'token-as-proof': {action: 'proceed', proof: 'channel-token'},
    'block-proof-as-proceed': {action: 'proceed', proof: await proof(requestId, 'block')},
    'shown-proof-as-proceed': {action: 'proceed', proof: await proof(requestId, 'shown')},
    'intercept-proof-as-proceed': {action: 'proceed', proof: intercept.proof},
    'shown-action': {action: 'shown', proof: await proof(requestId, 'shown')},
    'other-request-proof': {action: 'proceed', proof: await proof('other', 'proceed')},
  }[forgery];
  deliver({type: 'SHIELDAI_TX_VERDICT', requestId, ...forged});
  await flush();
  assert.equal(sent.length, 0, 'a forged verdict sent the transaction');
  deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'block', proof: await proof(requestId, 'block')});
  await assert.rejects(pending, /blocked/);
  assert.equal(sent.length, 0);
""",
        forgery,
    )


def test_verdict_after_the_timeout_is_ignored():
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  const {pending, requestId} = await startRequest();
  fireFailClosedTimer();
  deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed', proof: await proof(requestId, 'proceed')});
  await flush();
  await assert.rejects(pending, /blocked/);
  assert.equal(sent.length, 0);
"""
    )


def test_inject_takes_the_token_once_and_never_posts_it():
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  assert(accepted, 'inject.js did not take the offered token');
  // A later offer, which only a page script could make, is not taken.
  assert(document.dispatchEvent(new CustomEvent('shieldai:channel', {detail: 'page-token', cancelable: true})));
  const {pending, requestId, intercept} = await startRequest();
  assert.deepEqual(bytes(intercept.proof), bytes(await proof(requestId, 'intercept')));
  deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed',
    proof: await proofFor('page-token', `${requestId}:proceed`)});
  await flush();
  assert.equal(sent.length, 0, 'a verdict made with a page-chosen token was accepted');
  deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed', proof: await proof(requestId, 'proceed')});
  assert.equal(await pending, 'sent');
  assert(!JSON.stringify(posted).includes('channel-token'));
"""
    )


def test_inject_fails_closed_at_once_without_the_channel():
    run_node(
        INJECT_HARNESS.replace(
            "const accepted = !document.dispatchEvent(",
            "const accepted = false && !document.dispatchEvent(",
        )
        + r"""
(async () => {
  const pending = provider.request({method: 'eth_sendTransaction', params: [{to: '0x' + 'a'.repeat(40)}]});
  await assert.rejects(pending, /blocked/);
  assert.equal(posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').length, 0);
  assert.equal(sent.length, 0);
"""
    )


def test_inject_leaves_no_page_readable_marker_and_logs_nothing():
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  const markers = [...Object.keys(window), ...Object.keys(provider)].filter(key => /shield/i.test(key));
  assert.deepEqual(markers, []);
  for (const fn of windowListeners['eip6963:announceProvider']) {
    fn(new CustomEvent('eip6963:announceProvider', {detail: {provider, info: {name: 'same'}}}));
  }
  const {pending, requestId} = await startRequest();
  assert.equal(posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').length, 1,
    'the provider was wrapped twice');
  deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed', proof: await proof(requestId, 'proceed')});
  assert.equal(await pending, 'sent');
  assert.deepEqual(logged, []);
"""
    )


# Built-ins a page script could replace in its own world before the first wallet call.
PATCHES = {
    "set-has": "Set.prototype.has = () => false;",
    "weakset-has": "WeakSet.prototype.has = () => true;",
    "weakset-add": "WeakSet.prototype.add = function () { return this; };",
    "define-property": "Object.defineProperty = (target) => target;",
    "object-prototype-accessor": "Object.prototype.get = function () { return undefined; };",
    "function-bind": "Function.prototype.bind = function () { return async () => 'forwarded'; };",
    "subtle-sign": "crypto.subtle.sign = async () => new Uint8Array(32).buffer;",
    "subtle-import-key": "crypto.subtle.importKey = async () => null;",
    "text-encoder": "TextEncoder.prototype.encode = () => new Uint8Array(0);",
    "uint8array": "Uint8Array = function () { return new Array(32).fill(0); };",
    "random-uuid": "crypto.randomUUID = () => 'predictable';",
    "post-message": "window.postMessage = () => {};",
    "add-event-listener": "window.addEventListener = () => {};",
    "set-timeout": "setTimeout = () => 0;",
    "clear-timeout": "clearTimeout = () => {};",
    "array-from": "Array.from = () => [];",
    "number-to-string": "Number.prototype.toString = () => '0';",
    "pad-start": "String.prototype.padStart = () => '00';",
    "structured-clone": "structuredClone = (value) => value;",
    "custom-event-detail": "Object.defineProperty(CustomEvent.prototype, 'detail', {get() { return null; }});",
    "promise-then": (
        "const then = Promise.prototype.then;"
        "Promise.prototype.then = function (ok, fail) {"
        "  return then.call(this, typeof ok === 'function' ? (value) => ok(value && value.byteLength === 32 ? new Uint8Array(32).buffer : value) : ok, fail);"
        "};"
    ),
    "promise-constructor-and-then": (
        "const then = Promise.prototype.then;"
        "Promise.prototype.then = function (ok, fail) {"
        "  return then.call(this, typeof ok === 'function' ? (value) => ok(value && value.byteLength === 32 ? new Uint8Array(32).buffer : value) : ok, fail);"
        "};"
        "Promise.prototype.constructor = function Page(executor) { return new Promise(executor); };"
    ),
}


@pytest.mark.parametrize("patch", sorted(PATCHES))
def test_replaced_built_ins_cannot_let_a_request_skip_the_decision(patch):
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  vm.runInContext(JSON.parse(process.argv[1]), context);
  // A provider that arrives after the patch must still be wrapped.
  const late = {on() {}, async request(args) { if (args.method === 'eth_chainId') return '0x38'; sent.push(args); return 'sent'; }};
  for (const fn of windowListeners['eip6963:announceProvider']) {
    fn(new CustomEvent('eip6963:announceProvider', {detail: {provider: late, info: {name: 'late'}}}));
  }
  for (const target of [provider, late]) {
    const before = sent.length;
    const pending = target.request({method: 'eth_sendTransaction', params: [{to: '0x' + 'a'.repeat(40)}]});
    pending.catch(() => {});
    await flush();
    assert.equal(sent.length, before, 'the request reached the wallet before any decision');
    const intercept = posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').at(-1);
    assert(intercept, 'the request was not sent for a decision');
    const requestId = intercept.requestId;
    assert.notEqual(requestId, 'predictable');
    for (const forged of [new Uint8Array(32), intercept.proof, await proof(requestId, 'block')]) {
      deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed', proof: forged});
    }
    await flush();
    assert.equal(sent.length, before, 'a forged verdict sent the transaction');
    deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed', proof: await proof(requestId, 'proceed')});
    await flush();
    assert.equal(sent.length, before + 1, 'the real decision no longer works');
  }
""",
        PATCHES[patch],
    )


def test_fail_closed_timer_survives_replaced_timers():
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  vm.runInContext('setTimeout = () => 0; clearTimeout = () => {};', context);
  const {pending} = await startRequest();
  assert(fireFailClosedTimer(), 'the fail-closed timer was not armed');
  await assert.rejects(pending, /blocked/);
  assert.equal(sent.length, 0);
"""
    )


def test_the_wallet_gets_the_request_that_was_analysed():
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  let reads = 0;
  const benign = '0x' + 'b'.repeat(40), drainer = '0x' + 'd'.repeat(40);
  const tx = {get to() { return reads++ === 0 ? benign : drainer; }};
  const pending = provider.request({method: 'eth_sendTransaction', params: [tx]});
  pending.catch(() => {});
  await flush();
  const intercept = posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').at(-1);
  assert.equal(intercept.tx.to, benign);
  deliver({type: 'SHIELDAI_TX_VERDICT', requestId: intercept.requestId, action: 'proceed',
    proof: await proof(intercept.requestId, 'proceed')});
  await flush();
  assert.equal(sent.length, 1);
  assert.equal(sent[0].params[0].to, benign, 'the wallet was handed a different transaction');
"""
    )


def test_replaced_json_parse_cannot_change_the_typed_data_shown():
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  vm.runInContext("JSON.parse = () => ({primaryType: 'Harmless', message: {}});", context);
  const typed = JSON.stringify({primaryType: 'Permit', domain: {}, message: {spender: '0x' + 'e'.repeat(40)}});
  const pending = provider.request({method: 'eth_signTypedData_v4', params: ['0x' + 'b'.repeat(40), typed]});
  pending.catch(() => {});
  await flush();
  const intercept = posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').at(-1);
  assert.equal(intercept.tx.typedData.primaryType, 'Permit');
"""
    )


def test_a_provider_set_later_is_wrapped_before_the_page_can_use_it():
    run_node(
        INJECT_HARNESS.replace("window.ethereum = provider;\n", "")
        + r"""
(async () => {
  const original = provider.request;
  window.ethereum = provider;
  // No timer has run yet: the setter itself wrapped the provider.
  assert.notEqual(window.ethereum.request, original);
  const pending = window.ethereum.request({method: 'eth_sendTransaction', params: [{to: '0x' + 'a'.repeat(40)}]});
  pending.catch(() => {});
  await flush();
  assert.equal(sent.length, 0);
  assert.equal(posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').length, 1);
"""
    )


@pytest.mark.parametrize(
    "reason,stored,expected",
    [
        ("update", {}, "https://api.shieldbotsecurity.online"),
        ("update", {"apiUrl": "https://self-hosted.example"}, "https://self-hosted.example"),
        ("install", {}, "https://api.shieldbotsecurity.online"),
        ("chrome_update", {}, None),
    ],
)
def test_install_and_update_fill_a_missing_api_url_only(reason, stored, expected):
    run_node(
        r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
(async () => {
  const [reason, stored, expected] = JSON.parse(process.argv[1]);
  let installed; const opened = [], store = {...stored};
  const context = vm.createContext({
    chrome: {
      runtime: {onInstalled: {addListener(fn) { installed = fn; }}, onMessage: {addListener() {}}, getURL: path => path},
      storage: {local: {get(defaults, cb) { cb({...defaults, ...store}); }, set(value) { Object.assign(store, value); }}},
      tabs: {create(options) { opened.push(options.url); }},
    },
    URL, AbortSignal,
  });
  vm.runInContext(fs.readFileSync('extension/background.js', 'utf8'), context);
  installed({reason});
  assert.equal(store.apiUrl, expected === null ? undefined : expected);
  assert.deepEqual(opened, reason === 'install' ? ['welcome.html'] : []);
""",
        [reason, stored, None if expected is None else expected],
    )
