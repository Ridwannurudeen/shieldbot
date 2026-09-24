"""Known safe spenders on Base, Optimism, Arbitrum and Polygon are trusted only on their own chain."""

import pytest

from services.rescue_service import APPROVAL_TOPIC, KNOWN_SAFE_SPENDERS
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
PANCAKESWAP_V2_ROUTER = "0x10ed43c718714eb63d5aa57b78b54704e256024e"
UNISWAP_V2_ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
ONEINCH_V6_ROUTER = "0x111111125421ca6dc452d289314280a0f8842a65"


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
    [
        (8453, AERODROME_ROUTER, "Aerodrome Router"),
        (137, QUICKSWAP_ROUTER, "QuickSwap Router"),
        (56, PANCAKESWAP_V2_ROUTER, "PancakeSwap V2"),
        (1, UNISWAP_V2_ROUTER, "Uniswap V2"),
        (56, ONEINCH_V6_ROUTER, "1inch V6"),
        (1, ONEINCH_V6_ROUTER, "1inch V6"),
    ],
)
async def test_main_router_on_its_own_chain_is_a_known_spender(chain_id, spender, label):
    result, _, _ = await scan(approvals_to(spender), chain_id)

    [approval] = result["approvals"]
    assert approval["spender_label"] == label
    assert approval["risk_level"] == "MEDIUM"
    assert approval["risk_reason"] == f"Unlimited approval to {label} — safe but excessive"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "chain_id,spender",
    [
        # Aerodrome's Base router address holds no code on Optimism.
        (10, AERODROME_ROUTER),
        # On Ethereum this address holds another contract (no Uniswap V2 factory or WETH getter).
        (1, PANCAKESWAP_V2_ROUTER),
        # Uniswap documents 0x4752ba... as its BNB Chain V2 router, not this mainnet address.
        (56, UNISWAP_V2_ROUTER),
        # BSC and Ethereum entries are trusted nowhere else.
        (8453, PANCAKESWAP_V2_ROUTER),
        (4663, ONEINCH_V6_ROUTER),
    ],
)
async def test_a_router_address_on_another_chain_is_an_unknown_contract(chain_id, spender):
    result, _, _ = await scan(approvals_to(spender), chain_id)

    [approval] = result["approvals"]
    assert approval["spender_label"] == "Unknown Contract"
    assert approval["risk_level"] == "HIGH"


def test_chain_spender_addresses_are_lowercase_so_lookups_match():
    # Spenders are read from log topics in lowercase.
    assert all(
        address == address.lower() and len(address) == 42
        for labels in KNOWN_SAFE_SPENDERS.values()
        for address in labels
    )
