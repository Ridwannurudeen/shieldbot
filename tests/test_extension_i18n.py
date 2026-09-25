"""Every string the extension looks up must exist in every language it ships.

The lookup helpers return the key itself when a translation is missing, so a missing key shows
users raw identifiers such as "tabFeed" instead of text.
"""

import json
import re
from pathlib import Path
import shutil
import subprocess

import pytest

EXTENSION = Path(__file__).resolve().parent.parent / "extension"
LANGUAGES = ["en", "vi", "zh"]
REFERENCE = re.compile(
    r"""data-i18n(?:-placeholder)?="([^"]+)"|(?<![\w.$])_?t\(\s*["']([^"']+)["']"""
)


def referenced_keys():
    keys = {}
    for path in sorted(EXTENSION.glob("*.html")) + sorted(EXTENSION.glob("*.js")):
        for match in REFERENCE.finditer(path.read_text(encoding="utf-8")):
            keys.setdefault(match.group(1) or match.group(2), path.name)
    return keys


def messages(language):
    return json.loads(
        (EXTENSION / "locales" / language / "messages.json").read_text(encoding="utf-8")
    )


def test_reference_scan_finds_lookups_in_every_form():
    keys = referenced_keys()
    for key in ("tabSettings", "feedHeading", "overlayTitle", "statusChecking", "overlayNotes"):
        assert key in keys
    # The overlay's own labels are looked up too, not written into content.js in English.
    for key in (
        "overlayProtocol",
        "overlayContract",
        "overlayChainId",
        "overlayIncompleteCoverage",
        "overlayExplainAnalyzing",
    ):
        assert keys.get(key) == "content.js", key


@pytest.mark.parametrize("language", LANGUAGES)
def test_every_referenced_key_is_translated(language):
    translated = messages(language)
    missing = {key: source for key, source in referenced_keys().items() if key not in translated}
    assert not missing, f"{language} is missing {missing}"


@pytest.mark.parametrize("language", LANGUAGES)
def test_translations_are_non_empty_text(language):
    for key, value in messages(language).items():
        assert isinstance(value, str) and value.strip(), key


def test_a_filled_in_value_is_used_as_written():
    # String.replace with a string would expand $' (the text after the placeholder), $` and $& in a
    # value, and a value holding "{origin}" would be filled in by the next placeholder.
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for extension JavaScript regression tests")
    script = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const window = {};
const context = vm.createContext({
  window, document: {},
  chrome: {storage: {local: {get(defaults, done) { done({...defaults, language: 'en'}); }}},
    runtime: {getURL: path => path}},
  fetch: async path => ({json: async () => JSON.parse(fs.readFileSync(`extension/${path}`, 'utf8'))}),
});
vm.runInContext(fs.readFileSync('extension/i18n.js', 'utf8'), context);
(async () => {
  await window.initI18n();
  assert.equal(window.t('scanInjectionFound', {level: "HIGH$'"}), "Injection risk: HIGH$'");
  const mismatch = (domain, origin) => `This sign-in message is for ${domain}, but the page asking you to sign it ` +
    `is ${origin}. A page that asks you to sign in to another site is likely phishing.`;
  for (const domain of ["login$'.example", 'login$`.example', 'login$&.example', '{origin}']) {
    assert.equal(window.t('siweMismatch', {domain, origin: 'dapp.example'}), mismatch(domain, 'dapp.example'));
  }
  assert.equal(window.t('statusConnFailed', {status: 503}), 'Connection failed (503)');
  console.log('completed');
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run(
        [node, "-e", script], cwd=EXTENSION.parent, capture_output=True, text=True, encoding="utf-8", timeout=30
    )
    assert result.returncode == 0 and "completed" in result.stdout, result.stdout + result.stderr


def test_languages_define_the_same_keys():
    english = set(messages("en"))
    for language in LANGUAGES[1:]:
        assert set(messages(language)) == english, language
