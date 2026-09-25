"""The popup must not claim protection it has not checked, and must work from the keyboard."""

from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from utils.chain_info import CHAIN_INFO

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


def test_popup_version_label_comes_from_the_manifest():
    run_popup(r"""
  await ready();
  const version = 'v' + context.chrome.runtime.getManifest().version;
  assert.deepEqual(versions.map(el => el.textContent), [version, version]);
""")


def test_popup_tabs_follow_the_tab_pattern_from_the_keyboard():
    run_popup(r"""
  await ready();
  tabs[0].focus();
  tabs[0].dispatch('keydown', {key: 'ArrowRight'});
  assert.equal(document.activeElement, tabs[1]);
  assert.deepEqual(tabs.map(tab => tab.getAttribute('aria-selected')), ['false', 'true', 'false', 'false']);
  assert.deepEqual(tabs.map(tab => tab.tabIndex), [-1, 0, -1, -1]);
  tabs[1].dispatch('keydown', {key: 'ArrowLeft'});
  tabs[0].dispatch('keydown', {key: 'ArrowLeft'});
  assert.equal(document.activeElement, tabs[3]);
  tabs[3].dispatch('keydown', {key: 'Home'});
  assert.equal(document.activeElement, tabs[0]);
  tabs[0].dispatch('keydown', {key: 'End'});
  assert.equal(document.activeElement, tabs[3]);
  assert.equal(tabs[3].getAttribute('aria-selected'), 'true');
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


@pytest.mark.parametrize("name", ["popup.html", "sidepanel.html"])
def test_pages_declare_their_language(name):
    assert parse(name)[0]["tag"] == "html" and parse(name)[0].get("lang") == "en"


def test_popup_tabs_and_controls_have_accessible_names():
    elements = parse("popup.html")
    by_id = {element["id"]: element for element in elements if element.get("id")}
    tablist = [element for element in elements if element.get("role") == "tablist"]
    assert len(tablist) == 1
    tabs = [element for element in elements if element.get("role") == "tab"]
    assert [tab["tag"] for tab in tabs] == ["button"] * 4
    assert [tab["aria-selected"] for tab in tabs] == ["true", "false", "false", "false"]
    for tab in tabs:
        panel = by_id[tab["aria-controls"]]
        assert panel["role"] == "tabpanel" and panel["aria-labelledby"] == tab["id"]
    for control in ("enabled", "dash-enabled", "dash-langSelect"):
        label = by_id[by_id[control]["aria-labelledby"]]
        assert label.get("text", "").strip(), control
    assert any(
        element["tag"] == "label" and element.get("for") == "langSelect" for element in elements
    )
    chain = next(
        element for element in parse("sidepanel.html") if element.get("id") == "chainSelect"
    )
    assert chain.get("aria-label")


@pytest.mark.parametrize("stored, name", [(None, "BSC"), (4663, "Robinhood Chain"), (8453, "Base")])
def test_wallet_health_names_the_chain_it_scans(stored, name):
    run_popup(r"""
  const [stored, name] = JSON.parse(process.argv[1]);
  context.t = (key, values) => values ? `${key}:${values.chain}` : key;
  context.chrome.storage.local.get = (defaults, cb) => cb(stored === null ? defaults : {...defaults, selectedChainId: stored});
  await ready();
  context.initDashboard();
  for (const id of ['healthChainHint', 'dash-healthChainHint']) {
    assert.equal(byId(id).textContent, `healthScanSubtext:${name}`, id);
  }
""", [stored, name])


def test_wallet_health_names_no_fixed_chain_and_claims_no_full_history():
    html = (EXTENSION / "popup.html").read_text(encoding="utf-8")
    assert "BNB Chain" not in html and "full history" not in html.lower() and "full approval" not in html.lower()
    by_id = {element["id"]: element for element in parse("popup.html") if element.get("id")}
    for hint in ("healthChainHint", "dash-healthChainHint"):
        # popup.js writes the chain's name there; a data-i18n text would overwrite it.
        assert "data-i18n" not in by_id[hint], hint
    full = {"en": "full", "vi": "toàn bộ", "zh": "完整"}
    for language in ("en", "vi", "zh"):
        messages = json.loads((EXTENSION / "locales" / language / "messages.json").read_text(encoding="utf-8"))
        assert "{chain}" in messages["healthScanSubtext"] and "BNB" not in messages["healthScanSubtext"], language
        for key in ("healthScanSubtext", "healthScanning"):
            assert full[language] not in messages[key].lower(), (language, key)


def test_side_panel_chain_selector_offers_every_supported_chain():
    select = re.search(r'<select id="chainSelect"[^>]*>(.*?)</select>', (EXTENSION / "sidepanel.html").read_text(encoding="utf-8"), re.S)
    offered = set(re.findall(r'<option value="(\d+)"', select.group(1)))
    assert offered == {str(chain_id) for chain_id in CHAIN_INFO}


def test_extension_copy_claims_only_what_it_does():
    # A deployer's record raises the risk score (the firewall's campaign boost); it blocks nothing.
    # Only requests a page sends through the wallet provider are seen, not sends started in the
    # wallet itself.
    block = {"en": "block", "vi": "chặn", "zh": "拦截"}
    raises = {"en": "raises the risk score", "vi": "tăng điểm rủi ro", "zh": "风险分数"}
    every = {"en": "every transaction", "vi": "mỗi giao dịch", "zh": "每笔交易"}
    not_checked = {"en": "not checked", "vi": "không được kiểm tra", "zh": "不会被检查"}
    for language in ("en", "vi", "zh"):
        messages = json.loads((EXTENSION / "locales" / language / "messages.json").read_text(encoding="utf-8"))
        deployer, step = messages["dashDeployerBlockSub"].lower(), messages["step1Desc"].lower()
        assert block[language] not in deployer and raises[language] in deployer, (language, deployer)
        assert every[language] not in step and not_checked[language] in step, (language, step)
    english = json.loads((EXTENSION / "locales" / "en" / "messages.json").read_text(encoding="utf-8"))
    for page, key in (("popup.html", "dashDeployerBlockSub"), ("welcome.html", "step1Desc")):
        shown = next(element for element in parse(page) if element.get("data-i18n") == key)
        assert shown["text"].strip() == english[key], (page, key)


def test_popup_markup_claims_no_protection_before_a_scan():
    html = (EXTENSION / "popup.html").read_text(encoding="utf-8")
    assert ">PROTECTED<" not in html
    assert ">100%<" not in html


@pytest.mark.parametrize("page", ["popup.html", "welcome.html"])
def test_pages_do_not_hard_code_a_version(page):
    assert not re.search(r"v\d+\.\d+\.\d+", (EXTENSION / page).read_text(encoding="utf-8"))


def test_welcome_version_label_comes_from_the_manifest():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for extension JavaScript regression tests")
    script = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const element = () => ({textContent: '', style: {}, addEventListener() {}});
const label = element();
let ready;
const context = vm.createContext({
  window: {addEventListener(type, fn) { if (type === 'DOMContentLoaded') ready = fn; }},
  document: {getElementById: element, querySelector: selector => selector === '.version' ? label : null},
  initI18n: async () => {}, applyTranslations() {}, t: key => key,
  chrome: {runtime: {getManifest: () => JSON.parse(fs.readFileSync('extension/manifest.json', 'utf8'))}},
});
vm.runInContext(fs.readFileSync('extension/welcome.js', 'utf8'), context);
ready().then(() => {
  assert.equal(label.textContent, 'ShieldBot v' + context.chrome.runtime.getManifest().version);
  console.log('completed');
}).catch(error => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run([node, "-e", script], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert result.returncode == 0 and "completed" in result.stdout, result.stdout + result.stderr


def test_contract_monitoring_row_has_its_own_fallback_text():
    row = next(element for element in parse("popup.html") if element.get("data-i18n") == "dashContractMonitor")
    assert row["text"].strip() == "Contract Monitoring"


def test_extension_states_the_scan_chain_count_and_no_mempool_count():
    count = len(CHAIN_INFO)
    html = (EXTENSION / "popup.html").read_text(encoding="utf-8")
    assert f"<span>{count}</span> Chains Supported" in html
    for language in ("en", "vi", "zh"):
        messages = json.loads((EXTENSION / "locales" / language / "messages.json").read_text(encoding="utf-8"))
        assert str(count) in messages["dashCheckChains"]
        for text in [*messages.values(), html]:
            assert not re.search(r"\b7 (chains|chuỗi)|7 条链|mempool", text, re.IGNORECASE)


def contrast(foreground, background):
    def luminance(color):
        channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    light, dark = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


@pytest.mark.parametrize("selector", [".history-time", ".feed-time", ".gauge-sub", ".ctr-meta"])
def test_popup_secondary_text_is_readable(selector):
    html = (EXTENSION / "popup.html").read_text(encoding="utf-8")
    rule = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", html).group(1)
    color = re.search(r"(?:^|;)\s*(?:color|fill):\s*(#[0-9a-fA-F]{6})", rule).group(1)
    # #1e293b is the lightest background any of these sit on.
    assert contrast(color, "#1e293b") >= 4.5, (selector, color)

