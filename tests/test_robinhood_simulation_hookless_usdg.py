"""Hookless USDG v4 pools on Robinhood Chain use the ordinary v4 swap encoding."""

import pytest
from eth_abi import encode
from eth_utils import keccak

from services.robinhood_simulation import (
    BALANCE_OVERRIDE_WEI,
    HOOKLESS_V4_FEE_TICK_SPACINGS,
    LOG_WINDOW_BLOCKS,
    PERMIT2,
    UNIVERSAL_ROUTER,
    USDG,
    USDG_BALANCE_SLOT,
    USDG_BUY_BUDGET,
    Pool,
    RobinhoodSimulator,
    _pool_from_initialize,
    build_simulation_request,
    call_labels,
)
from tests.test_robinhood_simulation import (
    FakeRpc,
    evaluate,
    fresh_addresses,
    initialize_log,
    load,
    pool_state_slot,
    rpc_for,
    selector,
)

TOKEN = "0xd0601ce157db5bdc3162bbac2a2c8af5320d9eec"
KEY = (USDG, TOKEN, 100, 1, "0x" + "0" * 40)
POOL = Pool("v4-usdg", USDG, key=KEY)
BUYER = "0x" + "b1" * 20
RECEIVER = "0x" + "b2" * 20
AMOUNT = 10**17
ZERO = "0x" + "0" * 40
MAX_UINT256 = 2**256 - 1
SWAP = "((address,address,uint24,int24,address),bool,uint128,uint128,uint256,bytes)"


def storage_values(key, liquidity):
    slot = pool_state_slot(key)
    return {
        slot[2:]: 1,
        f"{(int(slot, 16) + 3):064x}": liquidity,
    }


def test_usdg_budget_fits_balance_slot_and_slot_one_is_used():
    assert USDG == "0x5fc5360d0400a0fd4f2af552add042d716f1d168"
    assert USDG_BALANCE_SLOT == 1
    assert 0 < USDG_BUY_BUDGET < 2**64

    request = build_simulation_request(POOL, TOKEN, AMOUNT, BUYER, RECEIVER)
    block = request["blockStateCalls"][0]
    slot = "0x" + keccak(encode(["address", "uint256"], [BUYER, USDG_BALANCE_SLOT])).hex()
    assert block["stateOverrides"] == {
        BUYER: {"balance": hex(BALANCE_OVERRIDE_WEI)},
        USDG: {"stateDiff": {slot: "0x" + USDG_BUY_BUDGET.to_bytes(32, "big").hex()}},
    }


def test_hookless_usdg_request_uses_the_exact_single_swap_encoding():
    request = build_simulation_request(POOL, TOKEN, AMOUNT, BUYER, RECEIVER)
    block = request["blockStateCalls"][0]
    labels = call_labels(POOL)
    calls = dict(zip(labels, block["calls"]))
    assert labels == [
        "fund_approve",
        "fund_permit",
        "buy",
        "delivered",
        "approve",
        "permit",
        "sell",
        "after_sell",
        "transfer",
    ]

    unlock = encode(
        ["bytes", "bytes[]"],
        [
            bytes([0x08, 0x0C, 0x0F]),
            [
                encode([SWAP], [(KEY, True, AMOUNT, USDG_BUY_BUDGET, 0, b"")]),
                encode(["address", "uint256"], [USDG, USDG_BUY_BUDGET]),
                encode(["address", "uint256"], [TOKEN, 0]),
            ],
        ],
    )
    assert calls["buy"] == {
        "from": BUYER,
        "to": UNIVERSAL_ROUTER,
        "data": "0x"
        + (
            selector("execute(bytes,bytes[],uint256)")
            + encode(["bytes", "bytes[]", "uint256"], [b"\x10", [unlock], MAX_UINT256])
        ).hex(),
    }
    assert calls["fund_approve"]["to"] == USDG
    assert calls["fund_permit"]["to"] == PERMIT2
    sell_unlock = encode(
        ["bytes", "bytes[]"],
        [
            bytes([0x0B, 0x06, 0x0F]),
            [
                encode(["address", "uint256", "bool"], [TOKEN, AMOUNT, True]),
                encode([SWAP], [(KEY, False, 0, 0, 0, b"")]),
                encode(["address", "uint256"], [USDG, 0]),
            ],
        ],
    )
    assert calls["sell"] == {
        "from": BUYER,
        "to": UNIVERSAL_ROUTER,
        "data": "0x"
        + (
            selector("execute(bytes,bytes[],uint256)")
            + encode(["bytes", "bytes[]", "uint256"], [b"\x10", [sell_unlock], MAX_UINT256])
        ).hex(),
    }


@pytest.mark.asyncio
async def test_direct_usdg_lookup_returns_deepest_active_pool_first():
    token = "0x" + "d0" * 20
    keys = [(USDG, token, fee, spacing, ZERO) for fee, spacing in HOOKLESS_V4_FEE_TICK_SPACINGS]
    slots = {}
    for key, liquidity in zip(keys, (100, 500, 300, 0, 50)):
        slots.update(storage_values(key, liquidity))
    rpc = FakeRpc(token, 10**27, pool_slots=slots)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc

    amount, pools, notes = await simulator._discover(None, token)

    assert amount == 10**21
    assert pools[0] == Pool("v4-usdg", USDG, key=keys[1])
    assert [pool.key for pool in pools] == [keys[1], keys[2], keys[0]]
    assert "1 more pool not simulated (cap of 3 pools)" in notes
    assert "hookless v4-usdg pool 0x" in notes[0]
    assert "initialized but empty" in notes[0]
    assert not any("unsupported route" in note for note in notes)


@pytest.mark.asyncio
async def test_direct_usdg_lookup_skips_an_initialized_empty_pool():
    token = "0x" + "d2" * 20
    live_key = (USDG, token, 500, 10, ZERO)
    empty_key = (USDG, token, 3000, 60, ZERO)
    slots = storage_values(live_key, 500)
    slots.update(storage_values(empty_key, 0))
    rpc = FakeRpc(token, 10**27, pool_slots=slots)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc

    amount, pools, notes = await simulator._discover(None, token)

    empty_id = keccak(
        encode(["address", "address", "uint24", "int24", "address"], list(empty_key))
    ).hex()
    assert amount == 10**21
    assert pools == [Pool("v4-usdg", USDG, key=live_key)]
    assert f"hookless v4-usdg pool 0x{empty_id} initialized but empty" in notes


@pytest.mark.asyncio
async def test_a_live_usdg_pool_is_the_only_pool_simulated_when_another_is_empty():
    fixture = load("v4_hookless_usdg_nvda")
    live_key = tuple(fixture["key"])
    empty_key = (USDG, fixture["token"], 500, 10, ZERO)
    slots = storage_values(live_key, 1)
    slots.update(storage_values(empty_key, 0))
    rpc = rpc_for(fixture, pool_slots=slots)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc

    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])

    live_request = build_simulation_request(
        Pool("v4-usdg", USDG, key=live_key),
        fixture["token"],
        fixture["amount"],
        fixture["buyer"],
        fixture["receiver"],
    )
    simulation_calls = [
        params for calls in rpc.requests for method, params in calls if method == "eth_simulateV1"
    ]
    empty_id = keccak(
        encode(["address", "address", "uint24", "int24", "address"], list(empty_key))
    ).hex()
    assert simulation_calls == [[live_request, hex(rpc.head)]]
    assert f"hookless v4-usdg pool 0x{empty_id} initialized but empty" in result["reason"]


def test_hookless_usdg_initialize_is_supported_and_another_quote_is_not():
    pool, note = _pool_from_initialize(initialize_log(USDG, TOKEN, 3000, 60, ZERO, 1), TOKEN)
    assert pool == Pool("v4-usdg", USDG, key=(USDG, TOKEN, 3000, 60, ZERO))
    assert note is None

    other = "0x" + "aa" * 20
    pool, note = _pool_from_initialize(initialize_log(other, TOKEN, 3000, 60, ZERO, 1), TOKEN)
    assert pool is None
    assert note == f"hookless paired with {other}"


@pytest.mark.asyncio
async def test_a_hookless_non_usdg_quote_remains_in_the_unsupported_summary():
    token, head = "0x" + "d1" * 20, 65_540_000
    other = "0x" + "aa" * 20
    logs = [initialize_log(other, token, 3000, 60, ZERO, head)]
    rpc = FakeRpc(
        token,
        10**27,
        head=head,
        logs={(head - LOG_WINDOW_BLOCKS + 1, head): logs},
    )
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc

    result = await simulator.simulate(token)

    assert all(result[field] is None for field in ("is_honeypot", "can_buy", "can_sell"))
    assert f"unsupported route: 1 v4 pool of this token cannot be simulated (hookless paired with {other})" in result["reason"]
    assert not rpc.simulations


def test_nvda_fixture_request_matches_the_live_calldata():
    fixture = load("v4_hookless_usdg_nvda")
    request = build_simulation_request(
        Pool(fixture["route"], fixture["numeraire"], key=tuple(fixture["key"])),
        fixture["token"],
        fixture["amount"],
        fixture["buyer"],
        fixture["receiver"],
    )
    assert [request, fixture["block_tag"]] == fixture["request"]


def test_nvda_fixture_buy_and_sell_measurements():
    fixture = load("v4_hookless_usdg_nvda")
    outcome = evaluate(fixture)
    assert outcome["block"] == fixture["simulation_block"]
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is True
    assert outcome["is_honeypot"] is False
    assert outcome["buy_tax"] == 0.0
    assert outcome["sell_tax"] == 0.0
    assert outcome["reason"] == (
        "buy and sell succeeded: sold 75179464069520000 token units for 17663054 USDG units"
    )


@pytest.mark.asyncio
async def test_direct_lookup_routes_nvda_through_the_live_hookless_usdg_pool():
    fixture = load("v4_hookless_usdg_nvda")
    state_slots = storage_values(tuple(fixture["key"]), 1)
    rpc = rpc_for(fixture, pool_slots=state_slots, head=fixture["block"])
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])

    assert result["is_honeypot"] is False
    assert result["can_buy"] is result["can_sell"] is True
    assert result["buy_tax"] == result["sell_tax"] == 0.0
    assert result["simulation_block"] == fixture["block"]
    assert "v4-usdg pool" in result["reason"]
    assert "unsupported route" not in result["reason"]
    methods = [method for calls in rpc.requests for method, _ in calls]
    assert methods.count("eth_simulateV1") == 1
    assert "eth_getLogs" not in methods
    assert not rpc.simulations
