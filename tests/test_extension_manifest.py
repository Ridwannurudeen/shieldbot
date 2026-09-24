"""The extension manifest and its store-facing text.

The Chrome Web Store already carries version 3.0.1, lists the languages found in _locales, and shows
the manifest description to every visitor, so these must stay correct and honest.
"""

import json
import re
from pathlib import Path

from utils.chain_info import CHAIN_INFO

EXTENSION = Path(__file__).resolve().parent.parent / "extension"
MANIFEST = json.loads((EXTENSION / "manifest.json").read_text(encoding="utf-8"))
# The locale folder names Chrome accepts; any other folder is silently ignored.
CHROME_LOCALES = {
    "ar",
    "am",
    "bg",
    "bn",
    "ca",
    "cs",
    "da",
    "de",
    "el",
    "en",
    "en_AU",
    "en_GB",
    "en_US",
    "es",
    "es_419",
    "et",
    "fa",
    "fi",
    "fil",
    "fr",
    "gu",
    "he",
    "hi",
    "hr",
    "hu",
    "id",
    "it",
    "ja",
    "kn",
    "ko",
    "lt",
    "lv",
    "ml",
    "mr",
    "ms",
    "nl",
    "no",
    "pl",
    "pt_BR",
    "pt_PT",
    "ro",
    "ru",
    "sk",
    "sl",
    "sr",
    "sv",
    "sw",
    "ta",
    "te",
    "th",
    "tr",
    "uk",
    "vi",
    "zh_CN",
    "zh_TW",
}


def store_locales():
    return {
        folder.name: json.loads((folder / "messages.json").read_text(encoding="utf-8"))
        for folder in (EXTENSION / "_locales").iterdir()
    }


def test_version_is_newer_than_the_published_store_build():
    assert tuple(int(part) for part in MANIFEST["version"].split(".")) > (3, 0, 1)


def test_store_lists_every_shipped_language():
    locales = store_locales()
    assert MANIFEST["default_locale"] == "en"
    assert set(locales) == {"en", "vi", "zh_CN"}
    assert set(locales) <= CHROME_LOCALES


def test_manifest_messages_exist_in_every_locale():
    keys = re.findall(r"__MSG_(\w+)__", json.dumps(MANIFEST))
    assert {"extName", "extDescription"} <= set(keys)
    for code, messages in store_locales().items():
        for key in keys:
            assert messages[key]["message"].strip(), (code, key)


def test_name_is_unchanged_in_every_language():
    for messages in store_locales().values():
        assert messages["extName"]["message"] == "ShieldAI Transaction Firewall"


def test_description_is_short_and_honest():
    for code, messages in store_locales().items():
        assert len(messages["extDescription"]["message"]) <= 132, code
    english = store_locales()["en"]["extDescription"]["message"]
    assert f"{len(CHAIN_INFO)} EVM chains" in english
    assert "Unknown" in english
    assert "block" not in english.lower()


def test_no_new_host_permissions():
    assert MANIFEST["host_permissions"] == ["https://*/*"]
    assert MANIFEST["optional_host_permissions"] == ["http://localhost/*", "http://127.0.0.1/*"]
