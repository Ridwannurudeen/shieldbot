"""Render the built dashboard against mocked API replies and read what it shows.

dashboard/index.html is the page production serves. These tests run its scripts in Node against a
small DOM double and a fetch that answers each API path with a fixed reply, then read the page's
text. They pin that a source the API reports as unavailable reads as unavailable, never as zero
and never as "no threats". Tests that pass steps also click and press keys, which the double
dispatches through the tree the way a browser does, so React's handlers and the page's own
listeners run.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUILT = ROOT / "dashboard" / "index.html"

# Enough DOM for React DOM and Recharts to mount: element trees, text nodes and listeners. Charts
# get a zero-size box, so Recharts renders no SVG. Reduced motion is on, so counts render their
# final value at once. Once the header leaves CONNECTING, the test's steps run and their result is
# printed as JSON. Like a browser, focus() does nothing on an element inside an inert subtree.
HARNESS = r"""
const fs = require('fs'), vm = require('vm');
const [file, replies] = [process.argv[1], JSON.parse(process.argv[2])];
class Node {
  constructor(doc) { this.ownerDocument = doc; this.childNodes = []; this.parentNode = null; }
  get firstChild() { return this.childNodes[0] || null; }
  get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
  get nextSibling() {
    const siblings = this.parentNode ? this.parentNode.childNodes : [];
    return siblings[siblings.indexOf(this) + 1] || null;
  }
  appendChild(child) { return this.insertBefore(child, null); }
  insertBefore(child, ref) {
    if (child.parentNode) child.parentNode.removeChild(child);
    const index = ref ? this.childNodes.indexOf(ref) : -1;
    this.childNodes.splice(index < 0 ? this.childNodes.length : index, 0, child);
    child.parentNode = this;
    return child;
  }
  removeChild(child) { this.childNodes = this.childNodes.filter(c => c !== child); child.parentNode = null; return child; }
  addEventListener(type, fn, options) {
    (this.listeners ||= []).push({type, fn, capture: options === true || Boolean(options && options.capture)});
  }
  removeEventListener(type, fn, options) {
    const capture = options === true || Boolean(options && options.capture);
    this.listeners = (this.listeners || []).filter(l => !(l.type === type && l.fn === fn && l.capture === capture));
  }
  contains(node) {
    for (; node; node = node.parentNode) if (node === this) return true;
    return false;
  }
  get textContent() { return this.childNodes.map(c => c.textContent).join(''); }
  set textContent(value) {
    this.childNodes = [];
    if (value !== '') this.appendChild(this.ownerDocument.createTextNode(String(value)));
  }
}
class Text extends Node {
  constructor(doc, value) { super(doc); this.nodeType = 3; this.nodeName = '#text'; this.nodeValue = value; }
  get textContent() { return this.nodeValue; }
  set textContent(value) { this.nodeValue = value; }
}
class Element extends Node {
  constructor(doc, tag, ns) {
    super(doc);
    this.nodeType = 1; this.tagName = this.nodeName = tag.toUpperCase();
    this.namespaceURI = ns || 'http://www.w3.org/1999/xhtml';
    this.attributes = {}; this.style = {setProperty: (k, v) => { this.style[k] = v; }};
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
  getAttribute(name) { return name in this.attributes ? this.attributes[name] : null; }
  hasAttribute(name) { return name in this.attributes; }
  getBoundingClientRect() { return {width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0}; }
  focus() {
    for (let node = this; node; node = node.parentNode) if (node.inert) return;
    this.ownerDocument.activeElement = this;
  }
  blur() {}
  // Only the selectors the page uses: tag names, each optionally with :not([attribute]), comma-separated.
  querySelectorAll(selector) {
    const tests = selector.split(',').map(part => {
      const [, tag, without] = part.trim().match(/^(\w+)(?::not\(\[(\w+)\]\))?$/);
      return el => el.tagName === tag.toUpperCase() && !(without && el.hasAttribute(without));
    });
    return descendants(this).filter(el => tests.some(test => test(el)));
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
const descendants = node => node.childNodes.flatMap(c => (c.nodeType === 1 ? [c, ...descendants(c)] : []));
class Document extends Node {
  constructor() {
    super(null);
    this.ownerDocument = this; this.nodeType = 9; this.nodeName = '#document';
    this.documentElement = this.appendChild(this.createElement('html'));
    this.body = this.documentElement.appendChild(this.createElement('body'));
    this.root = this.body.appendChild(this.createElement('div'));
    this.activeElement = this.body;
    // React checks for the input event with 'oninput' in document; without it, it falls back to an
    // old-IE polyfill that fails on key presses.
    this.oninput = null;
  }
  createElement(tag) { return new Element(this, tag); }
  createElementNS(ns, tag) { return new Element(this, tag, ns); }
  createTextNode(value) { return new Text(this, value); }
  getElementById(id) { return id === 'root' ? this.root : null; }
}
const document = new Document();
const requests = [];
async function fetch(url, options) {
  requests.push([url, options]);
  const path = url.slice('http://dashboard.test'.length);
  const key = Object.keys(replies).find(prefix => path.startsWith(prefix));
  const [status, body] = key ? replies[key] : [404, {detail: 'Not Found'}];
  return {ok: status >= 200 && status < 300, status, json: async () => body};
}
const context = vm.createContext({
  document, fetch, console, setTimeout, clearTimeout, setInterval, clearInterval, setImmediate, clearImmediate,
  MessageChannel, queueMicrotask, navigator: {userAgent: 'node'}, location: {origin: 'http://dashboard.test'},
  requestAnimationFrame: fn => setTimeout(() => fn(Date.now()), 16), cancelAnimationFrame: id => clearTimeout(id),
  matchMedia: query => ({matches: query === '(prefers-reduced-motion: reduce)'}),
  getComputedStyle: () => ({}), HTMLIFrameElement: class {},
  ResizeObserver: class { observe() {} unobserve() {} disconnect() {} },
});
context.window = context.self = context;
const html = fs.readFileSync(file, 'utf8');
for (const [, script] of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) vm.runInContext(script, context);
// What a test's steps can use: find elements anywhere in the document, click them, press keys and
// read the requests the page sent.
const find = test => descendants(document).find(test) || null;
const byLabel = prefix => find(el => (el.getAttribute('aria-label') || '').startsWith(prefix));
const byRole = role => find(el => el.getAttribute('role') === role);
const byText = text => find(el => el.tagName === 'BUTTON' && el.textContent === text);
const tick = () => new Promise(resolve => setTimeout(resolve, 50));
function dispatch(target, type, extra) {
  const event = {
    type, target, bubbles: true, cancelable: true, defaultPrevented: false, timeStamp: Date.now(), ...extra,
    preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; },
  };
  const path = [];
  for (let node = target; node; node = node.parentNode) path.push(node);
  for (const [node, capture] of [...[...path].reverse().map(n => [n, true]), ...path.map(n => [n, false])]) {
    if (event.stopped) break;
    event.currentTarget = node;
    for (const l of node.listeners || []) if (l.type === type && l.capture === capture) l.fn.call(node, event);
  }
}
async function click(el) { dispatch(el, 'click', {button: 0}); await tick(); }
async function press(key) { dispatch(document.activeElement, 'keydown', {key}); await tick(); }
const started = Date.now();
(function settle() {
  const text = document.root.textContent;
  if ((text === '' || text.includes('CONNECTING')) && Date.now() - started < 10000) return setTimeout(settle, 20);
  setTimeout(() => steps().then(
    result => { console.log(JSON.stringify(result)); process.exit(0); },
    error => { console.error(error); process.exit(1); },
  ), 100);
})();
"""
TEXT = "return document.root.textContent;"

WORKERS_NOTE = (
    "Background work runs in the separate workers process (BACKGROUND_WORKERS=external), and this API "
    "process holds none of its in-memory state: the mempool counters and the launch watch's run state "
    "are null here, not zero. The Unknown ledger here counts this process's own lookups only."
)
MEMPOOL_REASON = (
    "The mempool monitor runs in the separate workers process (BACKGROUND_WORKERS=external); "
    "this API process does not hold its alerts or counters."
)
MEMPOOL_FIELDS = (
    "transactions_monitored",
    "sandwiches_caught",
    "suspicious_approvals",
    "chains_protected",
)
STATS = {
    "transactions_monitored": 1200,
    "contracts_scanned": 10,
    "threats_detected": 0,
    "transactions_blocked": 1,
    "contracts_scanned_24h": 4,
    "threats_detected_24h": 0,
    "transactions_blocked_24h": 0,
    "sandwiches_caught": 3,
    "suspicious_approvals": 40,
    "chains_protected": 2,
    "mempool_chains_observable": [1, 56],
    "mempool_chains_unobservable": [],
    "mempool_counting_since": 1_790_000_000,
}
CONTRACT = {
    "type": "high_risk_contract",
    "address": "0x" + "ab" * 20,
    "chain_id": 56,
    "risk_score": 90,
    "risk_level": "HIGH",
    "flags": ["High sell tax"],
    "detected_at": 1_790_000_000,
}
# A sell-side sandwich: the victim sells a token for WETH, so target_token (what the victim buys) is WETH.
SANDWICH = {
    "type": "mempool_sandwich_attack",
    "alert_type": "sandwich_attack",
    "severity": "HIGH",
    "description": "Sandwich attack detected on 0xaaaaaaaa... — attacker 0x11111111... front-ran victim "
    "0x22222222... buying 0xaaaaaaaa... with 0xbbbbbbbb... at a higher gas price, then reversed the trade",
    "victim_tx": "0x" + "b1" * 32,
    "attacker_tx": "0x" + "a1" * 32,
    "attacker_addr": "0x" + "11" * 20,
    "target_token": "0x" + "aa" * 20,
    "chain_id": 1,
    "created_at": 1_790_000_000,
}
# An approval to a known-bad spender: target_token is the approved token contract.
APPROVAL = {
    "type": "mempool_suspicious_approval",
    "alert_type": "suspicious_approval",
    "severity": "HIGH",
    "description": "Token approval pending to a confirmed scam address (ShieldBot blacklist) — 0x22222222... "
    "approving 0x33333333... for unlimited tokens on contract 0xcccccccc...",
    "victim_tx": "0x" + "b2" * 32,
    "attacker_tx": None,
    "attacker_addr": "0x" + "33" * 20,
    "target_token": "0x" + "cc" * 20,
    "chain_id": 56,
    "created_at": 1_790_000_000,
}


NO_ATTESTATIONS = {"available": False, "attestations": [], "summary": {}}
ATTESTOR = "0x" + "ee" * 20
ATTESTATIONS = {
    "available": True,
    "attestor": ATTESTOR,
    "explorer": f"https://base.easscan.org/address/{ATTESTOR}",
    "attestations": [],
    "summary": {"total_recent": 0, "by_risk": {}, "by_source_chain": {}, "attestor": ATTESTOR},
}
ATTESTATION = {
    "uid": "0x" + "ab" * 32,
    "risk_label": "DANGER",
    "scan_type": "token",
    "scanned_address": "0x" + "ab" * 20,
    "source_chain_id": 56,
    "timestamp": 1_790_000_000,
}


def short(addr):
    return addr[:6] + "…" + addr[-4:]


def render(
    stats=STATS,
    contracts=(),
    mempool_reply=None,
    campaigns_reply=(200, {"campaigns": []}),
    report_reply=(200, {"status": "recorded"}),
    attestations_reply=(200, NO_ATTESTATIONS),
    steps=TEXT,
):
    node = shutil.which("node")
    if node is None:
        # CI must run these; a developer machine without Node skips them.
        if os.environ.get("CI"):
            pytest.fail("Node.js is required for dashboard rendering tests in CI")
        pytest.skip("Node.js is required for dashboard rendering tests")
    replies = {
        "/api/stats": [200, stats],
        "/api/threats/feed?source=contracts": [
            200,
            {"threats": list(contracts), "count": len(contracts)},
        ],
        "/api/threats/feed?source=mempool": [200, mempool_reply or {"threats": [], "count": 0}],
        "/api/campaigns/top": list(campaigns_reply),
        "/api/base/attestations": list(attestations_reply),
        "/api/report": list(report_reply),
    }
    script = f"{HARNESS}\nasync function steps() {{\n{steps}\n}}\n"
    result = subprocess.run(
        [node, "-e", script, str(BUILT), json.dumps(replies)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_mempool_counts_the_api_cannot_read_show_unavailable_not_zero():
    stats = {**STATS, **dict.fromkeys(MEMPOOL_FIELDS), "mempool_counting_since": None}
    stats.update(mempool_chains_observable=None, mempool_chains_unobservable=None)
    text = render({**stats, "background_workers_note": WORKERS_NOTE})
    for label in (
        "Transactions Monitored",
        "Sandwich Attacks Caught",
        "Suspicious Approvals",
        "Mempool Chains Watched",
    ):
        assert f"Unavailable{label}" in text, label
        assert f"0{label}" not in text, label
    assert "10Contracts Scanned" in text
    assert "0Contract Threatson record" in text
    assert "the mempool monitor runs in a separate process" in text


def test_with_a_workers_note_other_null_counts_keep_the_dash():
    stats = {**STATS, **dict.fromkeys(MEMPOOL_FIELDS), "mempool_counting_since": None}
    stats.update(contracts_scanned=None, transactions_blocked_24h=None, background_workers_note=WORKERS_NOTE)
    text = render(stats)
    assert "UnavailableTransactions Monitored" in text
    assert "—Contracts Scanned" in text
    assert "UnavailableContracts Scanned" not in text
    assert "—Transactions Blockedlast 24 h" in text
    assert "Unavailable: the mempool monitor runs in a separate process" in text
    assert "A dash means that source is not reporting right now." in text


def test_null_counts_without_a_workers_note_keep_the_dash():
    text = render({**STATS, "transactions_monitored": None, "mempool_counting_since": None})
    assert "—Transactions Monitored" in text
    assert "Unavailable" not in text
    assert "A dash means that source is not reporting right now." in text


def test_an_unavailable_mempool_feed_shows_its_reason_not_no_threats():
    reply = {"threats": [], "count": 0, "chain_id": None, "mempool_unavailable": MEMPOOL_REASON}
    text = render(mempool_reply=reply)
    assert f"Mempool alerts unavailable: {MEMPOOL_REASON}" in text
    assert "No threats detected" not in text


UNAVAILABLE_MEMPOOL = {"threats": [], "count": 0, "chain_id": None, "mempool_unavailable": MEMPOOL_REASON}


@pytest.mark.parametrize(
    "workers_note, mempool_reply, campaigns_reply, label",
    [
        # The mempool runs in the workers process on purpose: a steady state, not a failure.
        (True, UNAVAILABLE_MEMPOOL, (200, {"campaigns": []}), "CONTRACTS ONLY"),
        # A fetch that fails is still partial data, with or without the workers note.
        (True, UNAVAILABLE_MEMPOOL, (503, {"detail": "down"}), "PARTIAL DATA"),
        (False, None, (503, {"detail": "down"}), "PARTIAL DATA"),
        # Without the note, an unavailable mempool is a missing source.
        (False, UNAVAILABLE_MEMPOOL, (200, {"campaigns": []}), "PARTIAL DATA"),
        (False, None, (200, {"campaigns": []}), "LIVE"),
    ],
)
def test_header_health_label(workers_note, mempool_reply, campaigns_reply, label):
    stats = {**STATS, "background_workers_note": WORKERS_NOTE} if workers_note else STATS
    text = render(stats, mempool_reply=mempool_reply, campaigns_reply=campaigns_reply)
    labels = [name for name in ("LIVE", "PARTIAL DATA", "OFFLINE", "CONTRACTS ONLY") if name in text]
    assert labels == [label]


def test_contract_detections_still_show_beside_an_unavailable_mempool_feed():
    reply = {"threats": [], "count": 0, "chain_id": None, "mempool_unavailable": MEMPOOL_REASON}
    text = render(contracts=[CONTRACT], mempool_reply=reply)
    assert f"Mempool alerts unavailable: {MEMPOOL_REASON}" in text
    assert "High Risk Contract" in text
    assert "High sell tax" in text


def test_a_mempool_feed_without_the_field_reads_as_today():
    text = render()
    assert "Mempool alerts unavailable" not in text
    assert "No threats detected. Monitoring active." in text
    assert "LIVE" in text


# Opens the first row's Flag dialog from the keyboard focus and submits it.
FLAG_AND_SUBMIT = """
  const flag = byLabel('Flag ');
  flag.focus();
  await click(flag);
  await click(byText('Submit Report'));
  const dialog = byRole('dialog'), alert = byRole('alert'), toast = byRole('status');
  return {
    dialog: Boolean(dialog),
    alert: alert && alert.textContent,
    alertInDialog: Boolean(dialog && alert && dialog.contains(alert)),
    toast: toast && toast.textContent,
  };
"""


@pytest.mark.parametrize(
    "status, message",
    [(500, "Report not sent (HTTP 500)."), (429, "Too many reports. Try again in a minute.")],
)
def test_a_failed_report_says_so_inside_the_open_dialog(status, message):
    result = render(contracts=[CONTRACT], report_reply=(status, {"detail": "no"}), steps=FLAG_AND_SUBMIT)
    assert result == {"dialog": True, "alert": message, "alertInDialog": True, "toast": None}


def test_a_sent_report_closes_the_dialog_and_toasts_on_the_body():
    steps = FLAG_AND_SUBMIT.replace(
        "toast: toast && toast.textContent,",
        "toast: toast && toast.textContent, toastOnBody: Boolean(toast) && toast.parentNode === document.body,",
    )
    result = render(contracts=[CONTRACT], steps=steps)
    assert result == {
        "dialog": False,
        "alert": None,
        "alertInDialog": False,
        "toast": "Report sent. Thank you.",
        "toastOnBody": True,
    }


def test_the_page_behind_the_open_dialog_is_inert_and_escape_hands_focus_back():
    steps = """
      const flag = byLabel('Flag ');
      flag.focus();
      await click(flag);
      const open = {inert: document.root.inert === true, focus: document.activeElement.getAttribute('aria-label')};
      await press('Escape');
      return {
        open,
        closed: {dialog: Boolean(byRole('dialog')), inert: document.root.inert === true, focusBack: document.activeElement === flag},
      };
    """
    result = render(contracts=[CONTRACT], steps=steps)
    assert result == {
        "open": {"inert": True, "focus": "Why is this a false positive?"},
        "closed": {"dialog": False, "inert": False, "focusBack": True},
    }


# Reads the first row's address controls, opens its Flag dialog and submits it.
ROW_AND_REPORT = """
  const investigate = byLabel('Investigate '), copy = byLabel('Copy '), flag = byLabel('Flag ');
  const text = document.root.textContent;
  flag.focus();
  await click(flag);
  const dialog = byRole('dialog').textContent;
  await click(byText('Submit Report'));
  const [, options] = requests.find(([url]) => url.endsWith('/api/report'));
  return {
    text, dialog, href: investigate.getAttribute('href'),
    copy: copy.getAttribute('aria-label'), flag: flag.getAttribute('aria-label'),
    report: JSON.parse(options.body),
  };
"""


@pytest.mark.parametrize(
    "alert, explorer",
    [(SANDWICH, "https://etherscan.io"), (APPROVAL, "https://bscscan.com")],
    ids=["sell-side sandwich", "suspicious approval"],
)
def test_a_mempool_alert_row_is_its_attacker_and_notes_the_token(alert, explorer):
    attacker, token = alert["attacker_addr"], alert["target_token"]
    result = render(mempool_reply={"threats": [alert], "count": 1}, steps=ROW_AND_REPORT)
    assert f"Attacker {short(attacker)}" in result["text"]
    assert f"Target token {short(token)}" in result["text"]
    assert result["href"] == f"{explorer}/address/{attacker}"
    assert result["copy"] == f"Copy {short(attacker)} to the clipboard"
    assert result["flag"] == f"Flag {short(attacker)} as a false positive"
    assert f"Attacker Address{attacker}" in result["dialog"]
    assert token not in result["dialog"]
    assert result["report"] == {
        "address": attacker,
        "chainId": alert["chain_id"],
        "report_type": "false_positive",
        "reason": None,
    }


def test_a_contract_row_is_its_contract():
    result = render(contracts=[CONTRACT], steps=ROW_AND_REPORT)
    assert "Attacker" not in result["text"]
    assert "Target token" not in result["text"]
    assert result["href"] == f"https://bscscan.com/address/{CONTRACT['address']}"
    assert f"Address{CONTRACT['address']}" in result["dialog"]
    assert "Attacker Address" not in result["dialog"]
    assert result["report"]["address"] == CONTRACT["address"]


RETIRED_LINE = "Retired on 26 Sep 2026: no new attestations are written; past ones stay on chain."


def test_a_retired_attestor_reads_as_history():
    text = render(attestations_reply=(200, {**ATTESTATIONS, "retired_on": "2026-09-26"}))
    assert RETIRED_LINE in text
    assert "No attestations on record." in text
    assert "No attestations yet." not in text


def test_a_retired_attestor_still_lists_its_past_attestations():
    reply = {**ATTESTATIONS, "attestations": [ATTESTATION], "retired_on": "2026-09-26"}
    text = render(attestations_reply=(200, reply))
    assert RETIRED_LINE in text
    assert "DANGER" in text
    assert "EAS ↗" in text
    assert "No attestations" not in text


def test_an_attestor_that_is_not_retired_reads_as_today():
    text = render(attestations_reply=(200, ATTESTATIONS))
    assert "Retired on" not in text
    assert "No attestations yet." in text
