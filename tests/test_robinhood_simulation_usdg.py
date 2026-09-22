"""USDG-quoted Doppler pools on Robinhood Chain: USDG is funded inside the single eth_simulateV1 request.

Paxos USDG (0x5fc5...d168, an EIP-1967 proxy) runs the implementation 0x6818...6f8f, verified on Sourcify for
chain 4663. Its storage layout puts `balanceData` (mapping(address => TokenAccountData)) at slot 1, and
TokenAccountData packs `uint64 balance` in the lowest 8 bytes. A live eth_call with a stateDiff of
keccak256(abi.encode(probe, 1)) set to 10**12 made balanceOf(probe) return exactly 10**12.
"""

import pytest
from eth_abi import encode
from eth_utils import keccak

from services.robinhood_simulation import (
    BALANCE_OVERRIDE_WEI,
    PERMIT2,
    UNIVERSAL_ROUTER,
    USDG,
    USDG_BALANCE_SLOT,
    USDG_BUY_BUDGET,
    USDG_MIN_TRAP_COST,
    MIN_TRAP_COST_WEI,
    Pool,
    RobinhoodSimulator,
    _pool_from_initialize,
    build_simulation_request,
    call_labels,
)
from tests.test_robinhood_simulation import (
    HOOK_INITIALIZER,
    ZERO,
    FakeRpc,
    doppler_state,
    error_string,
    evaluate,
    failed_sell,
    fresh_addresses,
    load,
    pool_of,
    rpc_for,
    selector,
    set_router_swap,
    strip_sell_payout,
)

TOKEN = "0xabee1fa055d299141e6a9c560fcb4aaae8551e18"
KEY = (USDG, TOKEN, 0x800000, 8, HOOK_INITIALIZER)
POOL = Pool("v4-doppler", USDG, key=KEY)
BUYER = "0x" + "b1" * 20
RECEIVER = "0x" + "b2" * 20
AMOUNT = 10**21
MAX_UINT256 = 2**256 - 1
SWAP = "((address,address,uint24,int24,address),bool,uint128,uint128,uint256,bytes)"
INITIALIZE_TOPIC = (
    "0x"
    + keccak(text="Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)").hex()
)


def test_usdg_constants():
    assert USDG == "0x5fc5360d0400a0fd4f2af552add042d716f1d168"
    assert USDG_BALANCE_SLOT == 1
    # TokenAccountData.balance is a uint64, so the whole budget must fit in it.
    assert 0 < USDG_BUY_BUDGET < 2**64


def test_usdg_pool_is_funded_by_overriding_the_buyer_balance():
    request = build_simulation_request(POOL, TOKEN, AMOUNT, BUYER, RECEIVER)
    block = request["blockStateCalls"][0]
    slot = "0x" + keccak(encode(["address", "uint256"], [BUYER, USDG_BALANCE_SLOT])).hex()
    assert block["stateOverrides"] == {
        BUYER: {"balance": hex(BALANCE_OVERRIDE_WEI)},
        USDG: {"stateDiff": {slot: "0x" + USDG_BUY_BUDGET.to_bytes(32, "big").hex()}},
    }

    labels = call_labels(POOL)
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
    calls = dict(zip(labels, block["calls"]))
    assert calls["fund_approve"] == {
        "from": BUYER,
        "to": USDG,
        "data": "0x"
        + (
            selector("approve(address,uint256)")
            + encode(["address", "uint256"], [PERMIT2, MAX_UINT256])
        ).hex(),
    }
    assert calls["fund_permit"] == {
        "from": BUYER,
        "to": PERMIT2,
        "data": "0x"
        + (
            selector("approve(address,address,uint160,uint48)")
            + encode(
                ["address", "address", "uint160", "uint48"],
                [USDG, UNIVERSAL_ROUTER, 2**160 - 1, 2**48 - 1],
            )
        ).hex(),
    }

    # An exact-output buy paying at most the USDG budget, settled in USDG, with no ETH attached.
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


@pytest.mark.asyncio
async def test_doppler_usdg_numeraire_is_a_supported_pool():
    rpc = FakeRpc(TOKEN, 10**27, state=doppler_state(KEY, USDG, status=2))
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    amount, pools, notes = await simulator._discover(None, TOKEN)
    assert amount == AMOUNT
    assert pools == [POOL]
    assert not any("unsupported route" in note for note in notes)


def initialize_log(currency0, currency1, hooks, fee=0x800000, tick_spacing=8):
    return {
        "topics": [
            INITIALIZE_TOPIC,
            "0x" + "11" * 32,
            "0x" + "0" * 24 + currency0[2:],
            "0x" + "0" * 24 + currency1[2:],
        ],
        "data": "0x"
        + encode(
            ["uint24", "int24", "address", "uint160", "int24"], [fee, tick_spacing, hooks, 1, 0]
        ).hex(),
    }


def test_doppler_usdg_initialize_log_is_a_supported_pool():
    pool, note = _pool_from_initialize(initialize_log(USDG, TOKEN, HOOK_INITIALIZER), TOKEN)
    assert (pool, note) == (POOL, None)


def test_hookless_usdg_pool_stays_an_unsupported_route():
    pool, note = _pool_from_initialize(
        initialize_log(USDG, TOKEN, ZERO, fee=3000, tick_spacing=60), TOKEN
    )
    assert pool is None
    assert note.startswith("unsupported route: v4 pool 0x")
    assert USDG in note


# --- the live-recorded USDG simulation ------------------------------------------------------


def test_usdg_fixture_request_matches_the_live_verified_calldata():
    fixture = load("v4_doppler_usdg")
    assert fixture["numeraire"] == USDG
    request = build_simulation_request(
        pool_of(fixture), fixture["token"], fixture["amount"], fixture["buyer"], fixture["receiver"]
    )
    assert [request, "latest"] == fixture["request"]


def test_recorded_usdg_buy_and_sell_are_measured():
    outcome = evaluate(load("v4_doppler_usdg"))
    assert outcome["block"] == 67286521
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is True
    assert outcome["is_honeypot"] is False
    assert outcome["buy_tax"] == 0.0
    assert outcome["sell_tax"] == 0.0
    assert outcome["reason"] == "buy and sell succeeded: sold 1000000000000000000000 token units for 19699 USDG units"


def test_usdg_sell_refused_by_the_token_is_a_honeypot():
    outcome = evaluate(failed_sell(load("v4_doppler_usdg"), error_string("TRANSFER_FROM_FAILED")))
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is False
    assert outcome["is_honeypot"] is True


def test_the_usdg_trap_bar_is_one_usdg():
    assert USDG_MIN_TRAP_COST == 10**6
    assert MIN_TRAP_COST_WEI == 10**9


@pytest.mark.parametrize("cost,trap", [(10**6 - 1, False), (10**6, True), (10**9 - 1, True)])
def test_zero_usdg_output_is_a_trap_from_one_usdg_of_buy_cost(cost, trap):
    # Zero output after a buy costing at least 1 USDG means over 99.9999% of the value was lost, which swap
    # rounding (a few base units) cannot explain. Below that it may be dust, so it stays unknown.
    fixture = strip_sell_payout(load("v4_doppler_usdg"))
    set_router_swap(fixture, "buy", fixture["amount"], -cost)
    outcome = evaluate(fixture)
    assert outcome["can_buy"] is True
    if trap:
        assert (outcome["can_sell"], outcome["is_honeypot"]) == (False, True)
        assert "zero output" in outcome["reason"]
    else:
        assert (outcome["can_sell"], outcome["is_honeypot"]) == (None, None)
        assert f"the buy cost only {cost} USDG units, too little to rule out rounding" in outcome["reason"]


def test_the_recorded_usdg_buy_is_below_the_bar_so_a_zero_sell_there_stays_unknown():
    # The live buy cost about 0.02 USDG: a zero output at that size could be rounding.
    outcome = evaluate(strip_sell_payout(load("v4_doppler_usdg")))
    assert (outcome["can_sell"], outcome["is_honeypot"]) == (None, None)
    assert "USDG units, too little to rule out rounding" in outcome["reason"]


@pytest.mark.asyncio
async def test_discovery_simulates_a_usdg_doppler_token_end_to_end():
    fixture = load("v4_doppler_usdg")
    rpc = rpc_for(fixture)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])
    assert result["is_honeypot"] is False
    assert result["can_buy"] is result["can_sell"] is True
    assert result["buy_tax"] == result["sell_tax"] == 0.0
    assert result["simulation_block"] == rpc.head
    assert "unsupported route" not in result["reason"]
    methods = [method for calls in rpc.requests for method, _ in calls]
    assert methods.count("eth_simulateV1") == 1
    assert rpc.simulations == []
