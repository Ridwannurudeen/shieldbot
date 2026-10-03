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
from urllib.parse import quote

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
// Every interval the page sets, so a test can fire one timer's callback and read what it requests.
const timers = [];
async function fetch(url, options) {
  requests.push([url, options]);
  const path = url.slice('http://dashboard.test'.length);
  const key = Object.keys(replies).find(prefix => path.startsWith(prefix));
  const [status, body] = key ? replies[key] : [404, {detail: 'Not Found'}];
  return {ok: status >= 200 && status < 300, status, json: async () => body};
}
const context = vm.createContext({
  document, fetch, console, setTimeout, clearTimeout, setImmediate, clearImmediate,
  setInterval: (fn, ms) => { timers.push({fn, ms}); return setInterval(fn, ms); }, clearInterval,
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
LAUNCH_TOKEN = "0x" + "ab" * 20
NO_LAUNCHES = {
    "launches": [],
    "count": 0,
    "chain_id": 4663,
    "next_cursor": None,
    "scanned_share": {"window_hours": 24, "launches": 0, "scanned": 0},
}
BLOCKED_LAUNCH = {
    "chain_id": 4663,
    "token_address": LAUNCH_TOKEN,
    "launchpad": "Uniswap v4",
    "source": "uniswap_v4",
    "pool_id": "0x" + "cd" * 32,
    "tx_hash": "0x" + "ef" * 32,
    "block_number": 78_782_354,
    "block_timestamp": 1_790_999_800,
    "discovered_at": 1_790_999_850.5,
    "scan": {
        "outcome": "blocked",
        "status": "unknown",
        "risk_level": "HIGH",
        "risk_score": 80,
        "coverage": {"structural": 1.0, "honeypot": 0.8},
        "coverage_reasons": {"honeypot": "sell reverted"},
        "flags": ["Contract not verified", "Honeypot detected", "Cannot sell token"],
        "scanned_at": 1_790_999_866,
    },
    "impostor_check": {"status": "none", "symbol": None, "list_size": 195, "rules": 4},
    "verdict_url": f"/api/verdict/4663/{LAUNCH_TOKEN}",
}
LAUNCH_STATS = {
    **STATS,
    "launch_discovery": {
        "chain_id": 4663,
        "cursor": 78_700_000,
        "last_sweep_at": 1_790_999_900.0,
        "last_discovered_block": 78_782_354,
        "confirmed_head": 78_782_400,
        "confirmed_head_at": 1_790_999_901.0,
        "lag_blocks": 82_400,
        "scanned_share": {"window_hours": 24, "launches": 5190, "scanned": 1876},
    },
    "evidence_documents": {"4663": 19728, "56": 12},
    "registry_records_confirmed": 1367,
}
REGISTRY = "0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138"
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
    launches_reply=(200, NO_LAUNCHES),
    older_reply=None,
    fast_down=False,
    steps=TEXT,
):
    node = shutil.which("node")
    if node is None:
        # CI must run these; a developer machine without Node skips them.
        if os.environ.get("CI"):
            pytest.fail("Node.js is required for dashboard rendering tests in CI")
        pytest.skip("Node.js is required for dashboard rendering tests")
    # With fast_down, every source on the 20-second cycle answers 503.
    replies = {
        "/api/stats": [503 if fast_down else 200, stats],
        "/api/threats/feed?source=contracts": [
            503 if fast_down else 200,
            {"threats": list(contracts), "count": len(contracts)},
        ],
        "/api/threats/feed?source=mempool": [503 if fast_down else 200, mempool_reply or {"threats": [], "count": 0}],
        "/api/campaigns/top": list(campaigns_reply),
        "/api/base/attestations": [503, {"detail": "down"}] if fast_down else list(attestations_reply),
    }
    # The harness answers the first prefix that matches, so a page asked for with a cursor is keyed first.
    if older_reply is not None:
        replies["/api/launches/4663?outcome=blocked&limit=20&cursor="] = list(older_reply)
    replies["/api/launches/4663?outcome=blocked"] = list(launches_reply)
    replies["/api/report"] = list(report_reply)
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


DOWN = (503, {"detail": "down"})


@pytest.mark.parametrize(
    "campaigns_reply, launches_reply, label",
    [
        # Every fast source failed: one slow source still answering is partial data, not offline.
        ((200, {"campaigns": []}), DOWN, "PARTIAL DATA"),
        (DOWN, (200, NO_LAUNCHES), "PARTIAL DATA"),
        (DOWN, DOWN, "OFFLINE"),
    ],
    ids=["campaigns answer", "launches answer", "nothing answers"],
)
def test_the_page_is_offline_only_when_the_slow_sources_fail_too(campaigns_reply, launches_reply, label):
    text = render(campaigns_reply=campaigns_reply, launches_reply=launches_reply, fast_down=True)
    labels = [name for name in ("LIVE", "PARTIAL DATA", "OFFLINE", "CONTRACTS ONLY") if name in text]
    assert labels == [label]


def test_a_failed_campaigns_fetch_reads_as_unavailable_not_as_no_campaigns():
    text = render(campaigns_reply=DOWN)
    assert "Campaign data unavailable." in text
    assert "No campaigns detected." not in text
    assert "PARTIAL DATA" in text


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


def test_the_robinhood_panel_lists_a_blocked_launch_with_its_verdict_link():
    steps = """
      const verdict = byLabel('Open the verdict for '), investigate = byLabel('Investigate ');
      const registry = find(el => el.tagName === 'A' && el.textContent === 'Registry contract ↗');
      return {text: document.root.textContent, verdict: verdict.getAttribute('href'),
              explorer: investigate.getAttribute('href'), registry: registry.getAttribute('href')};
    """
    reply = {**NO_LAUNCHES, "launches": [BLOCKED_LAUNCH], "count": 1}
    result = render(LAUNCH_STATS, launches_reply=(200, reply), steps=steps)
    text = result["text"]
    assert "Robinhood Chain" in text
    assert "blocked" in text and "Risk 80 · HIGH" in text and "partial scan" in text
    assert "Contract not verified, Honeypot detected, Cannot sell token" in text
    assert "No match among official Robinhood Chain tokens" in text
    assert "Uniswap v4" in text
    assert short(LAUNCH_TOKEN) in text
    assert result["verdict"] == f"http://dashboard.test/api/verdict/4663/{LAUNCH_TOKEN}"
    assert result["explorer"] == f"https://robinhoodchain.blockscout.com/address/{LAUNCH_TOKEN}"
    assert "5,190Launches Discoveredlast 24 h" in text
    assert "1,876Launches Scannedlast 24 h" in text
    assert "82,400Discovery Lagblocks behind the confirmed headhead read " in text
    assert "19,728Evidence Documentsstored verdicts · all time" in text
    assert "1,367Registry Recordsconfirmed on-chainRegistry contract ↗" in text
    assert result["registry"] == f"https://robinhoodchain.blockscout.com/address/{REGISTRY}"
    assert "The only blocked launch on record." in text
    assert "LIVE" in text


def test_a_blocked_launch_without_evidence_or_a_check_still_renders():
    launch = {
        **BLOCKED_LAUNCH,
        "scan": {**BLOCKED_LAUNCH["scan"], "risk_level": None, "flags": [], "coverage": None},
        "impostor_check": None,
    }
    reply = {**NO_LAUNCHES, "launches": [launch], "count": 1}
    text = render(launches_reply=(200, reply))
    assert "Risk 80" in text and "HIGH" not in text
    assert "Not checked against official tokens" in text
    assert "LIVE" in text


def test_launch_counts_the_stats_reply_lacks_show_a_dash_not_zero():
    text = render()
    for label in ("Launches Discovered", "Launches Scanned", "Discovery Lag", "Evidence Documents", "Registry Records"):
        assert f"—{label}" in text, label
        assert f"0{label}" not in text, label
    assert "No blocked launches on record." in text
    assert "Provider answers unavailable." in text


def test_an_unavailable_launch_feed_says_so_and_is_partial_data():
    text = render(launches_reply=(503, {"detail": "down"}))
    assert "Robinhood Chain launches unavailable." in text
    assert "No blocked launches" not in text
    assert "PARTIAL DATA" in text and "LIVE" not in text


# Launches with distinct tokens, newest block first, as the feed orders them.
def _blocked(index):
    token = "0x" + f"{index:040x}"
    return {
        **BLOCKED_LAUNCH,
        "token_address": token,
        "block_number": BLOCKED_LAUNCH["block_number"] - index,
        "verdict_url": f"/api/verdict/4663/{token}",
    }


SEVEN = [_blocked(index) for index in range(1, 8)]
CURSOR = f"{SEVEN[-1]['block_number']}:{SEVEN[-1]['token_address']}"


def _shown(text):
    return [index for index in range(1, 10) if short("0x" + f"{index:040x}") in text]


@pytest.mark.parametrize(
    "launches_reply, link",
    [
        (
            (200, {**NO_LAUNCHES, "launches": [BLOCKED_LAUNCH], "count": 1}),
            "See the 1 blocked launch in the Robinhood Chain panel ↑",
        ),
        ((200, {**NO_LAUNCHES, "launches": SEVEN, "count": 7}), "See the 7 blocked launches in the Robinhood Chain panel ↑"),
        ((200, NO_LAUNCHES), "Open the Robinhood Chain launches panel ↑"),
        ((503, {"detail": "down"}), "Open the Robinhood Chain launches panel ↑"),
    ],
    ids=["one loaded", "seven loaded", "none on record", "unavailable"],
)
def test_the_robinhood_chip_links_to_the_panel_when_the_feed_has_no_firewall_detections_there(launches_reply, link):
    steps = """
      await click(byText('Robinhood'));
      const anchors = descendants(document).filter(el => el.tagName === 'A' && el.getAttribute('href') === '#robinhood-chain');
      const target = find(el => el.getAttribute('id') === 'robinhood-chain');
      return {text: document.root.textContent, anchors: anchors.map(el => el.textContent),
              target: target && target.tagName, title: target && target.querySelector('h2').textContent};
    """
    result = render(contracts=[CONTRACT], launches_reply=launches_reply, steps=steps)
    assert "0 threats" in result["text"]
    assert "No extension or agent firewall detections on Robinhood Chain in the current window." in result["text"]
    assert result["anchors"] == ["Robinhood Chain panel", link]
    assert result["target"] == "SECTION"
    assert result["title"] == "Robinhood Chain"
    assert "No threats on this chain in the current window." not in result["text"]
    assert "panel above" not in result["text"]


SHOW_MORE = """
  const before = document.root.textContent;
  await click(byText('Show 2 more'));
  const after = document.root.textContent;
  return {before, after, older: Boolean(byText('Load older blocked launches'))};
"""


def test_the_panel_shows_five_launches_until_the_reader_asks_for_the_rest():
    reply = {**NO_LAUNCHES, "launches": SEVEN, "count": 7}
    result = render(launches_reply=(200, reply), steps=SHOW_MORE)
    assert _shown(result["before"]) == [1, 2, 3, 4, 5]
    assert "Showing 5 of all 7 blocked launches on record." in result["before"]
    assert "Load older" not in result["before"]
    assert _shown(result["after"]) == [1, 2, 3, 4, 5, 6, 7]
    assert "Showing 7 of all 7 blocked launches on record." in result["after"]
    assert "Show the newest 5 only" in result["after"]
    assert result["older"] is False


# Shows the whole loaded page, asks for the page after it, then fires the five-minute refresh.
LOAD_OLDER = """
  await click(byText('Show 2 more'));
  const before = document.root.textContent;
  await click(byText('Load older blocked launches'));
  const after = document.root.textContent;
  const older = requests.map(([url]) => url).filter(url => url.includes('cursor='));
  const alert = byRole('alert');
  const mark = requests.length;
  timers.find(t => t.ms === 300000).fn();
  await tick();
  return {before, after, older, alert: alert && alert.textContent, refresh: requests.slice(mark).map(([url]) => url),
          refreshed: document.root.textContent, alertAfterRefresh: Boolean(byRole('alert'))};
"""


def test_an_older_page_loads_by_cursor_and_a_refresh_keeps_it():
    first = {**NO_LAUNCHES, "launches": SEVEN, "count": 7, "next_cursor": CURSOR}
    older = {**NO_LAUNCHES, "launches": [_blocked(8), _blocked(9)], "count": 2}
    result = render(launches_reply=(200, first), older_reply=(200, older), steps=LOAD_OLDER)
    assert "Showing 7 of the 7 loaded; more blocked launches are on record." in result["before"]
    assert result["older"] == [
        f"http://dashboard.test/api/launches/4663?outcome=blocked&limit=20&cursor={quote(CURSOR, safe='')}"
    ]
    assert _shown(result["after"]) == list(range(1, 10))
    assert "Showing 9 of all 9 blocked launches on record." in result["after"]
    assert result["refresh"] == [
        "http://dashboard.test/api/launches/4663?outcome=blocked&limit=20",
        "http://dashboard.test/api/campaigns/top?limit=10",
    ]
    assert _shown(result["refreshed"]) == list(range(1, 10))
    assert "Showing 9 of all 9 blocked launches on record." in result["refreshed"]
    assert result["alert"] is None
    assert result["alertAfterRefresh"] is False


def test_a_failed_older_page_keeps_the_loaded_launches_and_says_so():
    first = {**NO_LAUNCHES, "launches": SEVEN, "count": 7, "next_cursor": CURSOR}
    result = render(launches_reply=(200, first), older_reply=(503, {"detail": "down"}), steps=LOAD_OLDER)
    assert result["alert"] == "Older launches not loaded (HTTP 503)."
    assert _shown(result["after"]) == list(range(1, 8))
    assert "Robinhood Chain launches unavailable." not in result["refreshed"]
    # The next refresh that succeeds clears the notice.
    assert result["alertAfterRefresh"] is False
    assert "LIVE" in result["refreshed"]


LEDGER = {
    "counting_since": 1_790_000_000,
    "by_provider": {
        "rpc": {"answered": 275, "unknown": 0, "failed": 0},
        "sourcify": {"answered": 9, "unknown": 43, "failed": 0},
        "blockscout": {"answered": 39, "unknown": 0, "failed": 16},
    },
    "by_chain": {"4663": {"answered": 323, "unknown": 43, "failed": 16}},
}


def test_provider_answers_list_each_provider_by_lookups_and_each_chain():
    text = render({**STATS, "unknown_ledger": LEDGER})
    assert "ProviderAnsweredUnknownFailed" in text
    assert "rpc27500" in text
    assert "blockscout39016" in text
    assert "sourcify9430" in text
    assert text.index("rpc27500") < text.index("blockscout39016") < text.index("sourcify9430")
    assert "By chain: Robinhood 323 answered · 43 unknown · 16 failed." in text
    assert "reports what it could not check as unknown, never as safe." in text
    assert "This API process counts its own lookups only" not in text


def test_provider_answers_with_a_workers_note_say_whose_lookups_they_count():
    text = render({**STATS, "unknown_ledger": LEDGER, "background_workers_note": WORKERS_NOTE})
    assert "This API process counts its own lookups only; the hunter and the launch watch count in the workers process." in text


def test_provider_answers_with_no_lookups_say_so_not_zero():
    ledger = {"counting_since": 1_790_000_000, "by_provider": {}, "by_chain": {}}
    text = render({**STATS, "unknown_ledger": ledger})
    assert "No provider lookups since " in text
    assert "By chain" not in text


def test_sections_lead_with_robinhood_chain_and_end_with_history():
    steps = "return descendants(document).filter(el => el.tagName === 'H2').map(el => el.textContent);"
    assert render(attestations_reply=(200, ATTESTATIONS), steps=steps) == [
        "Robinhood Chain",
        "Provider Answers",
        "Firewall Scans",
        "Mempool Monitor",
        "Live Threat Feed",
        "Feed Analytics",
        "Top Campaigns",
        "Base EAS Attestations",
    ]


def test_the_last_day_contracts_scanned_tile_names_its_sources():
    text = render()
    assert "10Contracts Scannedall time · extension and agent firewalls" in text
    assert "4Contracts Scannedlast 24 h · extension and agent firewalls" in text
    assert "Both contracts scanned counts cover the extension and agent firewalls only" in text


def test_the_launches_panel_polls_on_its_own_slow_cycle():
    steps = """
      const slow = timers.find(t => t.ms === 300000), fast = timers.find(t => t.ms === 20000);
      const before = requests.length;
      slow.fn();
      await tick();
      const slowUrls = requests.slice(before).map(([url]) => url);
      const mid = requests.length;
      fast.fn();
      await tick();
      const fastUrls = requests.slice(mid).map(([url]) => url);
      return {intervals: timers.map(t => t.ms).sort((a, b) => a - b), slowUrls, fastUrls, text: document.root.textContent};
    """
    result = render(steps=steps)
    assert result["intervals"] == [20000, 300000]
    assert result["slowUrls"] == [
        "http://dashboard.test/api/launches/4663?outcome=blocked&limit=20",
        "http://dashboard.test/api/campaigns/top?limit=10",
    ]
    assert len(result["fastUrls"]) == 4
    assert not [url for url in result["fastUrls"] if "/api/launches" in url or "/api/campaigns" in url]
    assert result["text"].count("This list refreshes every 5 minutes.") == 2
    assert "refreshes every 20 seconds, launches and campaigns every 5 minutes" in result["text"]
    assert "No campaigns detected.Deployers with the most contracts on record. This list refreshes every 5 minutes." in result["text"]
