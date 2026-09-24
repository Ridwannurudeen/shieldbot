"""The popup must not claim protection it has not checked, and must work from the keyboard."""

from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / "extension"

POPUP_HARNESS = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const nodes = new Map();
function element(id) {
  return {
    id, innerHTML: '', textContent: '', className: '', value: '', style: {}, dataset: {}, attrs: {}, listeners: {},
    checked: false, tabIndex: 0,
    classList: {items: new Set(), add(c) { this.items.add(c); }, remove(c) { this.items.delete(c); }},
    setAttribute(name, value) { this.attrs[name] = String(value); },
    getAttribute(name) { return name in this.attrs ? this.attrs[name] : null; },
    addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); },
    dispatch(type, event = {}) { event.preventDefault ||= () => {}; for (const fn of this.listeners[type] || []) fn(event); },
    click() { this.dispatch('click'); },
    focus() { document.activeElement = this; },
  };
}
const byId = id => { if (!nodes.has(id)) nodes.set(id, element(id)); return nodes.get(id); };
const tabs = ['settings', 'history', 'health', 'feed'].map((name, index) => {
  const tab = element('tab-' + name + '-button');
  tab.dataset.tab = name;
  tab.setAttribute('aria-selected', String(index === 0));
  tab.tabIndex = index === 0 ? 0 : -1;
  return tab;
});
const panels = tabs.map(tab => byId('tab-' + tab.dataset.tab));
const versions = [element('version'), element('dash-version')];
let ready;
const document = {
  activeElement: null,
  addEventListener(type, fn) { if (type === 'DOMContentLoaded') ready = fn; },
  createElement() { return {set textContent(value) { this.innerHTML = String(value); }}; },
  getElementById: byId,
  querySelector: () => null,
  querySelectorAll(selector) {
    if (selector === '.tab') return tabs;
    if (selector === '.tab-content') return panels;
    if (selector === '.version, .dh-version') return versions;
    return [];
  },
  body: {classList: {add() {}}},
};
const context = vm.createContext({
  document, location: {search: ''}, URLSearchParams, URL, setTimeout, clearTimeout,
  t: key => key, initI18n: async () => {}, applyTranslations() {}, getCurrentLang: () => 'en',
  chrome: {
    runtime: {getManifest: () => JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8')),
      sendMessage() {}, getURL: path => path},
    storage: {local: {get(defaults, cb) { cb(defaults); }, set() {}}},
    permissions: {contains: async () => true},
    tabs: {create() {}},
  },
  fetch: async () => ({ok: true, json: async () => ({})}),
});
vm.runInContext(fs.readFileSync('extension/popup.js', 'utf8'), context);
const unknownScan = {
  status: 'unknown', classification: 'SAFE', risk_score: 0, coverage: {structural: 0},
  coverage_reasons: {structural: 'Contract age unavailable'}, to: '0x' + 'a'.repeat(40), timestamp: Date.now(),
};
(async () => {
"""


def run_popup(script, argument=None):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for extension JavaScript regression tests")
    result = subprocess.run(
        [
            node,
            "-e",
            POPUP_HARNESS + script + "\n})().then(() => console.log('completed'))"
            ".catch(error => {console.error(error); process.exitCode = 1;});",
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


def test_dashboard_says_nothing_checked_instead_of_protected_before_any_scan():
    run_popup(r"""
  context.renderDashCenter(null);
  context.renderDashStats([]);
  assert.equal(byId('dash-cls-badge').textContent, 'dashNothingChecked');
  assert(!byId('dash-cls-badge').className.includes('cls-protected'));
  assert.notEqual(String(byId('dash-gauge-num').textContent), '100');
  assert.notEqual(byId('dash-stat-safe').textContent, '100%');
""")


def test_unknown_scans_have_their_own_state_and_reason_in_history_and_dashboard():
    run_popup(r"""
  const list = element('list');
  context.renderCompactHistory([unknownScan], list);
  context.renderDashFeed([unknownScan]);
  for (const html of [list.innerHTML, byId('dash-feed').innerHTML]) {
    assert(html.includes('badge-unknown'), html);
    assert(!html.includes('badge-caution'), html);
    assert(html.includes('classUnknown'), html);
    assert(html.includes('unknownWhy Contract age unavailable'), html);
  }
  context.renderDashCenter(unknownScan);
  assert.equal(byId('dash-cls-badge').className, 'cls-badge cls-unknown');
  assert.equal(byId('dash-cls-badge').textContent, 'classUnknown');
  assert.equal(byId('dash-verdict').textContent, 'unknownWhy Contract age unavailable');
""")


class Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements, self.stack = [], []

    def handle_starttag(self, tag, attrs):
        element = {"tag": tag, **{name: value or "" for name, value in attrs}}
        self.elements.append(element)
        if tag not in ("input", "meta", "link", "br"):
            self.stack.append(element)

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1]["tag"] == tag:
            self.stack.pop()

    def handle_data(self, data):
        for element in self.stack:
            element["text"] = element.get("text", "") + data


def parse(name):
    parser = Markup()
    parser.feed((EXTENSION / name).read_text(encoding="utf-8"))
    return parser.elements


def test_popup_markup_claims_no_protection_before_a_scan():
    html = (EXTENSION / "popup.html").read_text(encoding="utf-8")
    assert ">PROTECTED<" not in html
    assert ">100%<" not in html

