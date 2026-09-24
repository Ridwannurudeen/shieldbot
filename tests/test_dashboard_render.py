"""Render the built dashboard against mocked API replies and read what it shows.

dashboard/index.html is the page production serves. These tests run its scripts in Node against a
small DOM double and a fetch that answers each API path with a fixed reply, then read the page's
text. They pin that a source the API reports as unavailable reads as unavailable, never as zero
and never as "no threats".
"""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUILT = ROOT / "dashboard" / "index.html"

# Enough DOM for React DOM and Recharts to mount: element trees, text nodes and no-op listeners.
# Charts get a zero-size box, so Recharts renders no SVG. Reduced motion is on, so counts render
# their final value at once. The page's text is printed once the header shows the first fetch's health.
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
  addEventListener() {}
  removeEventListener() {}
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
  getBoundingClientRect() { return {width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0}; }
  focus() { this.ownerDocument.activeElement = this; }
  blur() {}
}
class Document extends Node {
  constructor() {
    super(null);
    this.ownerDocument = this; this.nodeType = 9; this.nodeName = '#document';
    this.body = this.appendChild(this.createElement('body'));
    this.root = this.body.appendChild(this.createElement('div'));
    this.activeElement = this.body;
  }
  createElement(tag) { return new Element(this, tag); }
  createElementNS(ns, tag) { return new Element(this, tag, ns); }
  createTextNode(value) { return new Text(this, value); }
  getElementById(id) { return id === 'root' ? this.root : null; }
}
const document = new Document();
async function fetch(url) {
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
const started = Date.now();
(function settle() {
  const fetched = ['LIVE', 'PARTIAL DATA', 'OFFLINE'].some(label => document.root.textContent.includes(label));
  if (!fetched && Date.now() - started < 10000) return setTimeout(settle, 20);
  setTimeout(() => { console.log(JSON.stringify(document.root.textContent)); process.exit(0); }, 100);
})();
"""

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


def render(stats=STATS, contracts=(), mempool_reply=None):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for dashboard rendering tests")
    replies = {
        "/api/stats": [200, stats],
        "/api/threats/feed?source=contracts": [
            200,
            {"threats": list(contracts), "count": len(contracts)},
        ],
        "/api/threats/feed?source=mempool": [200, mempool_reply or {"threats": [], "count": 0}],
        "/api/campaigns/top": [200, {"campaigns": []}],
        "/api/base/attestations": [200, {"available": False, "attestations": [], "summary": {}}],
    }
    result = subprocess.run(
        [node, "-e", HARNESS, str(BUILT), json.dumps(replies)],
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

