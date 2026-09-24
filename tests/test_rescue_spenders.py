"""Known safe spenders on Base, Optimism, Arbitrum and Polygon are trusted only on their own chain."""

import pytest

from services.rescue_service import APPROVAL_TOPIC, CHAIN_SAFE_SPENDERS
from tests.test_rescue_bounded_history import (
    LATEST,
    OWNER_TOPIC,
    TOKEN,
    UNLIMITED,
    chain_handler,
    ok,
    scan,
)

AERODROME_ROUTER = "0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43"
QUICKSWAP_ROUTER = "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff"


def approvals_to(spender):
    log = {
        "address": TOKEN,
        "topics": [APPROVAL_TOPIC, OWNER_TOPIC, "0x" + "0" * 24 + spender[2:]],
        "data": UNLIMITED,
        "blockNumber": hex(LATEST - 5),
    }
    return chain_handler(logs=lambda to_b: ok([log]) if to_b == LATEST else ok([]))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "chain_id,spender,label",
    [(8453, AERODROME_ROUTER, "Aerodrome Router"), (137, QUICKSWAP_ROUTER, "QuickSwap Router")],
)
async def test_main_router_on_its_own_chain_is_a_known_spender(chain_id, spender, label):
    result, _, _ = await scan(approvals_to(spender), chain_id)

    [approval] = result["approvals"]
    assert approval["spender_label"] == label
    assert approval["risk_level"] == "MEDIUM"
    assert approval["risk_reason"] == f"Unlimited approval to {label} — safe but excessive"


@pytest.mark.asyncio
async def test_a_router_address_on_another_chain_is_an_unknown_contract():
    # Aerodrome's Base router address holds no code on Optimism.
    result, _, _ = await scan(approvals_to(AERODROME_ROUTER), 10)

    [approval] = result["approvals"]
    assert approval["spender_label"] == "Unknown Contract"
    assert approval["risk_level"] == "HIGH"


def test_chain_spender_addresses_are_lowercase_so_lookups_match():
    # Spenders are read from log topics in lowercase.
    assert all(
        address == address.lower() and len(address) == 42
        for labels in CHAIN_SAFE_SPENDERS.values()
        for address in labels
    )
