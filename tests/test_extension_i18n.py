"""Every string the extension looks up must exist in every language it ships.

The lookup helpers return the key itself when a translation is missing, so a missing key shows
users raw identifiers such as "tabFeed" instead of text.
"""

import json
import re
from pathlib import Path

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


@pytest.mark.parametrize("language", LANGUAGES)
def test_every_referenced_key_is_translated(language):
    translated = messages(language)
    missing = {key: source for key, source in referenced_keys().items() if key not in translated}
    assert not missing, f"{language} is missing {missing}"


@pytest.mark.parametrize("language", LANGUAGES)
def test_translations_are_non_empty_text(language):
    for key, value in messages(language).items():
        assert isinstance(value, str) and value.strip(), key


def test_languages_define_the_same_keys():
    english = set(messages("en"))
    for language in LANGUAGES[1:]:
        assert set(messages(language)) == english, language
