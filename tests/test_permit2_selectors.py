"""Calldata selectors must be the keccak of the full signature they are labelled with."""

import pytest
from eth_utils import keccak

from utils.calldata_decoder import KNOWN_SELECTORS, CalldataDecoder


@pytest.mark.parametrize("selector", sorted(KNOWN_SELECTORS))
def test_selector_is_the_hash_of_its_signature(selector):
    assert keccak(text=KNOWN_SELECTORS[selector]["signature"])[:4].hex() == selector


@pytest.mark.parametrize(
    "selector,name",
    [
        ("2b67b570", "permit (Permit2)"),
        ("2a2d80d1", "permit (Permit2 batch)"),
        ("30f28b7a", "permitTransferFrom (Permit2)"),
        ("edd9444b", "permitTransferFrom (Permit2 batch)"),
    ],
)
def test_permit2_calls_decode_under_their_own_names(selector, name):
    decoded = CalldataDecoder().decode("0x" + selector + "00" * 32)
    assert decoded["function_name"] == name
    assert decoded["category"] == "approval"
    assert decoded["is_approval"] is True
