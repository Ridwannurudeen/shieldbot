"""Run the extension's page scripts against small DOM and Chrome doubles.

inject.js runs in the page and holds the dApp's request; content.js runs in the extension's isolated
world and shows the overlay. These tests drive both through the window messages they exchange.
"""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parent.parent

# A DOM double: elements parse the tags out of the innerHTML string they are given, which is all
# content.js needs to find its buttons and its modal.
FAKE_DOM = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const {webcrypto} = require('crypto');
const posted = [], documentListeners = {};
class El {
  constructor(tag, root, index) {
    this.tagName = tag.toUpperCase(); this.attrs = {}; this.listeners = {}; this.style = {};
    this.children = []; this.parent = null; this.html = ''; this.root = root; this.index = index;
    this.id = ''; this.className = ''; this.disabled = false; this.hidden = false; this.textContent = '';
  }
  set innerHTML(value) { this.html = value; this.parsed = null; }
  set textContent(value) {
    this.text = String(value);
    this.html = this.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  get textContent() { return this.text; }
  get innerHTML() { return this.html; }
  setAttribute(name, value) { this.attrs[name] = String(value); }
  getAttribute(name) { return name in this.attrs ? this.attrs[name] : null; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  dispatch(type, event = {}) {
    event.preventDefault ||= () => { event.defaultPrevented = true; };
    for (const fn of this.listeners[type] || []) fn(event);
    return event;
  }
  click() { this.dispatch('click'); }
  focus() { document.activeElement = this; }
  appendChild(child) { child.parent = this; this.children.push(child); return child; }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this);
    this.parent = null;
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
const body = new El('body'), head = new El('head');
const document = {
  body, head, documentElement: new El('html'), activeElement: body,
  createElement: tag => new El(tag),
  getElementById(id) {
    for (const el of body.children) {
      if (el.id === id) return el;
      const found = el.descendants().find(child => child.id === id);
      if (found) return found;
    }
    return null;
  },
  addEventListener(type, fn) { (documentListeners[type] ||= []).push(fn); },
};
const windowListeners = {};
const window = {
  addEventListener(type, fn) { (windowListeners[type] ||= []).push(fn); },
  removeEventListener(type, fn) { windowListeners[type] = (windowListeners[type] || []).filter(f => f !== fn); },
  postMessage(data) { posted.push(data); },
  location: {href: 'https://dapp.example/', hostname: 'dapp.example'},
  history: {length: 1},
};
function deliver(data) { for (const fn of [...(windowListeners.message || [])]) fn({source: window, data}); }
const flush = () => new Promise(resolve => setTimeout(resolve, 50));
async function proofFor(token, requestId) {
  const encoder = new TextEncoder();
  const key = await webcrypto.subtle.importKey('raw', encoder.encode(token), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const mac = await webcrypto.subtle.sign('HMAC', key, encoder.encode(requestId));
  return Array.from(new Uint8Array(mac), b => b.toString(16).padStart(2, '0')).join('');
}
"""

CONTENT_HARNESS = (
    FAKE_DOM
    + r"""
const storage = {language: 'en'};
const analyses = [];
let analyze = async () => ({error: 'API error 503: unavailable'});
const chrome = {
  storage: {local: {get(defaults, cb) { cb({...defaults, ...storage}); }}},
  runtime: {
    getURL: path => path,
    async sendMessage(message) {
      if (message.type === 'SHIELDAI_ANALYZE') { analyses.push(message.tx); return analyze(message.tx); }
      return {result: {is_phishing: false}};
    },
  },
};
const context = vm.createContext({
  window, document, chrome, crypto: webcrypto, TextEncoder, TextDecoder, setTimeout, clearTimeout, console,
  fetch: async path => ({json: async () => JSON.parse(fs.readFileSync('extension/' + path, 'utf8'))}),
});
vm.runInContext(fs.readFileSync('extension/content.js', 'utf8'), context);
document.head.children[0].onload();
const token = posted.find(message => message.type === '__SHIELDAI_INIT__')._ct;
function overlay() { return document.getElementById('shieldai-overlay'); }
function verdicts() {
  return JSON.parse(JSON.stringify(posted.filter(message => message.type === 'SHIELDAI_TX_VERDICT')));
}
async function intercept(requestId, tx = {to: '0x' + 'a'.repeat(40), chainId: 56}) {
  deliver({type: 'SHIELDAI_TX_INTERCEPT', requestId, method: 'eth_sendTransaction', tx});
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


@pytest.mark.parametrize("policy", ["STRICT", "BALANCED"])
@pytest.mark.parametrize("outcome", ["error", "BLOCK_RECOMMENDED", "CAUTION", "UNKNOWN"])
def test_strict_mode_removes_proceed_on_errors_and_block_verdicts(policy, outcome):
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
  const removed = policy === 'STRICT' && ['error', 'BLOCK_RECOMMENDED'].includes(outcome);
  assert.equal(html.includes('id="shieldai-proceed"'), !removed);
  assert.equal(html.includes('Strict mode is on'), removed);
  assert(html.includes('id="shieldai-block"'));
  document.getElementById('shieldai-block').click();
  assert.equal(verdicts().at(-1).action, 'block');
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
    deliver({type: 'SHIELDAI_TX_INTERCEPT', requestId: 'request', method: 'personal_sign',
      tx: {signMethod: 'personal_sign', data: '0x68656c6c6f'}});
    await flush();
  } else {
    await intercept('request');
  }
  const modal = overlay().querySelector('.shieldai-modal');
  assert.equal(modal.attrs.role, 'dialog');
  assert.equal(modal.attrs['aria-modal'], 'true');
  assert.equal(document.getElementById(modal.attrs['aria-labelledby']).tagName, 'H2');
  assert.equal(document.activeElement, modal, 'focus did not move into the dialog');
  const buttons = modal.querySelectorAll('button');
  const seen = new Set();
  for (let i = 0; i < buttons.length + 1; i++) {
    assert(overlay().dispatch('keydown', {key: 'Tab'}).defaultPrevented);
    assert(buttons.includes(document.activeElement), 'Tab left the dialog');
    seen.add(document.activeElement);
  }
  assert.equal(seen.size, buttons.length, 'Tab did not reach every button');
  overlay().dispatch('keydown', {key: 'Tab', shiftKey: true});
  assert(buttons.includes(document.activeElement));
  assert.equal(verdicts().length, 0);
  overlay().dispatch('keydown', {key: 'Escape'});
  assert.deepEqual(verdicts(), [{type: 'SHIELDAI_TX_VERDICT', requestId: 'request', action: 'block', _ct: token}]);
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
  const modal = overlay().querySelector('.shieldai-modal');
  const explain = document.getElementById('shieldai-explain');
  explain.focus();
  explain.click();
  assert(explain.disabled, 'the explain button should disable itself');
  overlay().dispatch('focusout', {target: explain, relatedTarget: null});
  assert.equal(document.activeElement, modal, 'focus was lost when the focused button was disabled');
  const block = document.getElementById('shieldai-block');
  block.focus();
  overlay().dispatch('focusout', {target: explain, relatedTarget: block});
  assert.equal(document.activeElement, block, 'focus moving inside the dialog must stay where it went');
"""
    )


def test_shown_signal_proves_the_channel_without_revealing_its_token():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  analyze = async () => ({result: scan({})});
  await intercept('request');
  const shown = posted.filter(message => message.type === 'SHIELDAI_TX_SHOWN');
  assert.equal(shown.length, 1);
  assert.equal(shown[0].requestId, 'request');
  assert.equal(shown[0].proof, await proofFor(token, 'request'));
  assert(!JSON.stringify(shown[0]).includes(token), 'the channel token leaked to the page');
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
  assert.deepEqual(verdicts(), [{type: 'SHIELDAI_TX_VERDICT', requestId: 'first', action: 'block', _ct: token}]);
  document.getElementById('shieldai-proceed').click();
  assert.deepEqual(verdicts().at(-1), {type: 'SHIELDAI_TX_VERDICT', requestId: 'second', action: 'proceed', _ct: token});
  assert.equal(verdicts().length, 2);
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
  window, performance: {clearResourceTimings() {}}, crypto: webcrypto, TextEncoder, queueMicrotask,
  Event: class { constructor(type) { this.type = type; } }, Promise, Array, Uint8Array,
  console: new Proxy({}, {get: (_, name) => (...args) => logged.push([name, ...args])}),
  setTimeout(fn, delay) { const id = ++nextTimer; timers.set(id, {fn, delay}); return id; },
  clearTimeout(id) { timers.delete(id); },
});
vm.runInContext(fs.readFileSync('extension/inject.js', 'utf8'), context);
deliver({type: '__SHIELDAI_INIT__', _ct: 'channel-token'});
function fireFailClosedTimer() {
  for (const [id, timer] of timers) if (timer.delay === 60000) { timers.delete(id); timer.fn(); return true; }
  return false;
}
async function startRequest() {
  const pending = provider.request({method: 'eth_sendTransaction', params: [{to: '0x' + 'a'.repeat(40)}]});
  pending.catch(() => {});
  await flush();
  const intercept = posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').at(-1);
  return {pending, requestId: intercept.requestId};
}
"""
)


@pytest.mark.parametrize(
    "shown", ["none", "valid", "token-as-proof", "wrong-request", "missing-proof"]
)
def test_fail_closed_timer_stops_only_for_an_authentic_shown_signal(shown):
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  const shown = JSON.parse(process.argv[1]);
  const {pending, requestId} = await startRequest();
  const proofs = {
    valid: await proofFor('channel-token', requestId),
    'token-as-proof': 'channel-token',
    'wrong-request': await proofFor('channel-token', 'another-request'),
  };
  if (shown !== 'none') deliver({type: 'SHIELDAI_TX_SHOWN', requestId, proof: proofs[shown]});
  await flush();
  const stopped = !fireFailClosedTimer();
  assert.equal(stopped, shown === 'valid');
  if (shown === 'valid') {
    deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed', _ct: 'channel-token'});
    assert.equal(await pending, 'sent');
  } else {
    await assert.rejects(pending, /blocked/);
    assert.equal(sent.length, 0);
  }
""",
        shown,
    )


def test_verdict_after_the_timeout_is_ignored_and_forged_verdicts_still_fail():
    run_node(
        INJECT_HARNESS
        + r"""
(async () => {
  const {pending, requestId} = await startRequest();
  deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed', _ct: 'forged'});
  fireFailClosedTimer();
  deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed', _ct: 'channel-token'});
  await assert.rejects(pending, /blocked/);
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
  for (const fn of windowListeners['eip6963:announceProvider']) fn({detail: {provider, info: {name: 'same'}}});
  const {pending, requestId} = await startRequest();
  assert.equal(posted.filter(message => message.type === 'SHIELDAI_TX_INTERCEPT').length, 1,
    'the provider was wrapped twice');
  deliver({type: 'SHIELDAI_TX_VERDICT', requestId, action: 'proceed', _ct: 'channel-token'});
  assert.equal(await pending, 'sent');
  assert.deepEqual(logged, []);
"""
    )


def test_content_script_injects_the_page_script_once():
    run_node(
        CONTENT_HARNESS
        + r"""
(async () => {
  let injected = 0;
  const createElement = document.createElement;
  document.createElement = tag => { if (tag === 'script') injected++; return createElement(tag); };
  vm.runInContext(fs.readFileSync('extension/content.js', 'utf8'), context);
  assert.equal(injected, 0, 'a second run of the content script injected the page script again');
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
