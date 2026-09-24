"""Every allowlisted router and locker must be one that was seen with contract code on its chain.

The fixture records `python -m scripts.check_allowlist_code` run against public RPCs; rerun it
whenever an allowlist changes.
"""

import json
from pathlib import Path

from scripts.check_allowlist_code import ADAPTERS, allowlisted

FIXTURE = Path(__file__).parent / "fixtures" / "allowlist_code.json"


def _checked():
    rows = json.loads(FIXTURE.read_text(encoding="utf-8"))["addresses"]
    return {(row["chain_id"], row["address"]): row for row in rows}


def test_every_allowlisted_address_was_seen_with_code():
    checked = _checked()
    for adapter in (adapter_class() for adapter_class in ADAPTERS):
        for address, kind, label in allowlisted(adapter):
            key = (adapter.chain_id, address)
            assert key in checked, f"{label} on chain {adapter.chain_id} was never checked"
            assert checked[key]["code_size"] > 0, f"{label} has no code on chain {adapter.chain_id}"
            assert (checked[key]["kind"], checked[key]["label"]) == (kind, label)


def test_fixture_has_no_stale_rows():
    allowed = {
        (adapter.chain_id, address)
        for adapter in (adapter_class() for adapter_class in ADAPTERS)
        for address, _, _ in allowlisted(adapter)
    }
    assert set(_checked()) == allowed
