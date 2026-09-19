"""Robinhood Chain (4663) buy/sell simulation: encoding, verdicts, RPC failures and integration."""

import asyncio
import copy
import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from eth_abi import encode
from eth_utils import keccak

from analyzers.honeypot import HoneypotAnalyzer
from core.analyzer import AnalysisContext
from services.honeypot_service import HoneypotService
from services.robinhood_simulation import (
    LOG_WINDOW_BLOCKS,
    MAX_LOG_WINDOWS,
    MAX_POOLS,
    Pool,
    RobinhoodSimulator,
    SimulationUnavailable,
    aggregate_outcomes,
    build_simulation_request,
    call_labels,
    evaluate_simulation,
    tax_percent,
)
from utils.scam_db import ScamDatabase
from utils.web3_client import Web3Client

FIXTURES = Path(__file__).parent / "fixtures" / "robinhood_simulation"
ZERO = "0x" + "0" * 40
POOL_MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951"
HOOK_INITIALIZER = "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"
V2_FACTORY = "0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f"
WETH = "0x0bd7d308f8e1639fab988df18a8011f41eacad73"
FIELDS = ("is_honeypot", "buy_tax", "sell_tax", "can_buy", "can_sell")
SECRET = "rpc-secret-key-51c2"


def load(name):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def pool_of(fixture):
    key = tuple(fixture["key"]) if "key" in fixture else None
    return Pool(fixture["route"], fixture["numeraire"], key=key, pair=fixture.get("pair"))


def selector(signature):
    return keccak(text=signature)[:4]


def revert_data(signature, types=(), values=()):
    return "0x" + (selector(signature) + encode(list(types), list(values))).hex()


def error_string(message):
    return revert_data("Error(string)", ["string"], [message])


def calls_by_label(fixture):
    calls = fixture["response"]["result"][0]["calls"]
    return dict(zip(call_labels(pool_of(fixture)), calls))


def set_uint(call, value):
    call["returnData"] = "0x" + value.to_bytes(32, "big").hex()


def make_revert(call, data):
    call.update(
        status="0x0",
        logs=[],
        returnData="0x",
        error={
            "message": "execution reverted",
            "code": 3,
            "data": data,
        },
    )


def failed_sell(fixture, data):
    """The sell reverts: balances stay where the buy left them."""
    fixture = copy.deepcopy(fixture)
    calls = calls_by_label(fixture)
    make_revert(calls["sell"], data)
    set_uint(calls["after_sell"], fixture["amount"])
    if "pool_after_sell" in calls:
        calls["pool_after_sell"]["returnData"] = calls["pool_before_sell"]["returnData"]
    return fixture


def evaluate(fixture, sell_amount=None):
    return evaluate_simulation(
        pool_of(fixture),
        fixture["token"],
        fixture["amount"],
        fixture["buyer"],
        fixture["response"]["result"],
        sell_amount,
    )


# --- encoding pinned to live-verified requests --------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "v4_native_liquidity_launcher",
        "v4_doppler_weth",
        "v4_doppler_native_fee_hook",
        "v4_weth_hookless",
        "v2_router02",
        "v2_honeypot_sell_reverts",
    ],
)
def test_request_matches_live_verified_calldata(name):
    fixture = load(name)
    request = build_simulation_request(
        pool_of(fixture),
        fixture["token"],
        fixture["amount"],
        fixture["buyer"],
        fixture["receiver"],
    )
    assert [request, "latest"] == fixture["request"]


def test_v4_buy_and_sell_use_the_deployed_router_layout():
    # The deployed Universal Router's ExactInputSingleParams carries minHopPriceX36 before hookData.
    fixture = load("v4_native_liquidity_launcher")
    calls = calls_by_label(fixture)
    request = fixture["request"][0]["blockStateCalls"][0]["calls"]
    labels = call_labels(pool_of(fixture))
    buy = request[labels.index("buy")]
    sell = request[labels.index("sell")]
    execute = selector("execute(bytes,bytes[],uint256)").hex()
    swap = "((address,address,uint24,int24,address),bool,uint128,uint128,uint256,bytes)"
    key = tuple(fixture["key"])
    unlock_buy = encode(
        ["bytes", "bytes[]"],
        [
            bytes([0x08, 0x0C, 0x0F]),
            [
                encode([swap], [(key, True, fixture["amount"], 10**19, 0, b"")]),
                encode(["address", "uint256"], [ZERO, 10**19]),
                encode(["address", "uint256"], [fixture["token"], 0]),
            ],
        ],
    )
    unlock_sell = encode(
        ["bytes", "bytes[]"],
        [
            bytes([0x0B, 0x06, 0x0F]),
            [
                encode(["address", "uint256", "bool"], [fixture["token"], fixture["amount"], True]),
                encode([swap], [(key, False, 0, 0, 0, b"")]),
                encode(["address", "uint256"], [ZERO, 0]),
            ],
        ],
    )
    deadline = 2**256 - 1
    assert (
        buy["data"]
        == "0x"
        + execute
        + encode(["bytes", "bytes[]", "uint256"], [b"\x10", [unlock_buy], deadline]).hex()
    )
    assert (
        sell["data"]
        == "0x"
        + execute
        + encode(["bytes", "bytes[]", "uint256"], [b"\x10", [unlock_sell], deadline]).hex()
    )
    assert buy["value"] == hex(10**19)
    assert calls["buy"]["status"] == calls["sell"]["status"] == "0x1"


# --- verdicts on recorded live simulations --------------------------------------------------


@pytest.mark.parametrize(
    "name,block,output",
    [
        ("v4_native_liquidity_launcher", 65551497, 2526684544832),
        ("v4_doppler_weth", 65551506, 59887538073233),
        ("v4_doppler_native_fee_hook", 65551521, 7988294284787),
        ("v4_weth_hookless", 65704949, 2002143633592),
        ("v2_router02", 65551531, 1141608),
    ],
)
def test_recorded_buy_and_sell_are_measured(name, block, output):
    outcome = evaluate(load(name))
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is True
    assert outcome["is_honeypot"] is False
    assert outcome["buy_tax"] == 0.0
    assert outcome["sell_tax"] == 0.0
    assert outcome["block"] == block
    assert str(output) in outcome["reason"]


def test_live_honeypot_is_proven_unsellable():
    # Recorded live on 4663: the buy succeeds, Router02 reports the token refused the sell transfer,
    # and a plain transfer to a fresh address still succeeds.
    outcome = evaluate(load("v2_honeypot_sell_reverts"))
    assert outcome["block"] == 65554454
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is False
    assert outcome["is_honeypot"] is True
    assert outcome["buy_tax"] == 0.0
    assert outcome["sell_tax"] is None
    assert 'Error("TransferHelper: TRANSFER_FROM_FAILED")' in outcome["reason"]
    assert "plain transfer of half the tokens to a fresh address succeeded" in outcome["reason"]


@pytest.mark.parametrize(
    "name,message",
    [
        ("v4_native_liquidity_launcher", "TRANSFER_FROM_FAILED"),
        ("v4_doppler_weth", "TRANSFER_FROM_FAILED"),
        ("v4_weth_hookless", "TRANSFER_FROM_FAILED"),
        ("v2_router02", "TransferHelper: TRANSFER_FROM_FAILED"),
    ],
)
def test_token_refusing_the_sell_is_a_honeypot(name, message):
    outcome = evaluate(failed_sell(load(name), error_string(message)))
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is False
    assert outcome["is_honeypot"] is True
    assert outcome["buy_tax"] == 0.0
    assert outcome["sell_tax"] is None
    assert message in outcome["reason"]


def test_hook_reverting_the_sell_is_a_honeypot():
    inner = error_string("sells disabled")
    data = revert_data(
        "WrappedError(address,bytes4,bytes,bytes)",
        ["address", "bytes4", "bytes", "bytes"],
        [
            HOOK_INITIALIZER,
            selector(
                "afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),int256,bytes)"
            ),
            bytes.fromhex(inner[2:]),
            selector("HookCallFailed()"),
        ],
    )
    outcome = evaluate(failed_sell(load("v4_doppler_weth"), data))
    assert outcome["can_sell"] is False
    assert outcome["is_honeypot"] is True
    assert HOOK_INITIALIZER in outcome["reason"]
    assert "sells disabled" in outcome["reason"]


@pytest.mark.parametrize(
    "name,data",
    [
        ("v4_native_liquidity_launcher", revert_data("SwapAmountCannotBeZero()")),
        ("v2_router02", error_string("UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT")),
    ],
)
def test_sell_crediting_nothing_to_the_pool_is_a_honeypot(name, data):
    outcome = evaluate(failed_sell(load(name), data))
    assert outcome["can_sell"] is False
    assert outcome["is_honeypot"] is True


def strip_sell_payout(fixture):
    buyer_topic = "0x" + "0" * 24 + fixture["buyer"][2:]
    calls = calls_by_label(fixture)
    calls["sell"]["logs"] = [
        log for log in calls["sell"]["logs"] if log["topics"][-1] != buyer_topic
    ]
    return fixture


@pytest.mark.parametrize("name", ["v4_doppler_weth", "v4_doppler_native_fee_hook"])
def test_zero_sell_output_from_a_hooked_pool_is_a_honeypot(name):
    # The hook runs after the Swap event, so it can take the whole payout from the seller.
    outcome = evaluate(strip_sell_payout(load(name)))
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is False
    assert outcome["is_honeypot"] is True
    assert "zero output" in outcome["reason"]


@pytest.mark.parametrize(
    "name", ["v4_native_liquidity_launcher", "v4_weth_hookless", "v2_router02"]
)
def test_zero_output_while_a_hookless_pool_paid_out_is_unknown(name):
    # Without a hook nothing sits between the pool's payout and the seller, so a payout the Swap event
    # reports but no transfer delivered is a gap in the trace, not something the token did.
    outcome = evaluate(strip_sell_payout(load(name)))
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is None
    assert outcome["is_honeypot"] is None
    assert outcome["sell_tax"] is None
    assert outcome["reason"] == "Malformed eth_simulateV1 sell logs"


def test_zero_output_from_a_hookless_pool_that_paid_nothing_is_a_honeypot():
    fixture = strip_sell_payout(load("v4_native_liquidity_launcher"))
    event = router_swap_event(fixture)
    words = [event["data"][2 + 64 * index : 2 + 64 * (index + 1)] for index in range(6)]
    words[0] = encode(["int128"], [0]).hex()
    event["data"] = "0x" + "".join(words)
    outcome = evaluate(fixture)
    assert outcome["can_sell"] is False
    assert outcome["is_honeypot"] is True
    assert "zero output" in outcome["reason"]


@pytest.mark.parametrize(
    "name",
    [
        "v4_native_liquidity_launcher",
        "v4_weth_hookless",
        "v4_doppler_weth",
        "v4_doppler_native_fee_hook",
        "v2_router02",
    ],
)
def test_a_successful_sell_without_logs_is_unknown(name):
    fixture = load(name)
    calls_by_label(fixture)["sell"]["logs"] = []
    outcome = evaluate(fixture)
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is None
    assert outcome["is_honeypot"] is None
    assert outcome["sell_tax"] is None
    assert outcome["reason"] == "Malformed eth_simulateV1 sell logs"


def test_a_duplicated_sell_swap_event_leaves_the_sell_tax_unmeasured():
    fixture = load("v4_doppler_weth")
    calls_by_label(fixture)["sell"]["logs"].append(copy.deepcopy(router_swap_event(fixture)))
    outcome = evaluate(fixture)
    assert outcome["can_sell"] is True
    assert outcome["sell_tax"] is None
    assert "sell tax unmeasurable" in outcome["reason"]


@pytest.mark.parametrize(
    "data,label",
    [
        (revert_data("InvalidCommandType(uint256)", ["uint256"], [0x3F]), "InvalidCommandType"),
        (revert_data("UnsupportedAction(uint256)", ["uint256"], [0x19]), "UnsupportedAction"),
        (revert_data("SliceOutOfBounds()"), "SliceOutOfBounds"),
        (revert_data("InputLengthMismatch()"), "InputLengthMismatch"),
        (revert_data("InsufficientAllowance(uint256)", ["uint256"], [0]), "InsufficientAllowance"),
        (revert_data("AllowanceExpired(uint256)", ["uint256"], [1]), "AllowanceExpired"),
        (
            revert_data("V4TooLittleReceived(uint256,uint256)", ["uint256", "uint256"], [1, 0]),
            "V4TooLittleReceived",
        ),
        (revert_data("DeltaNotPositive(address)", ["address"], [ZERO]), "DeltaNotPositive"),
        (revert_data("CurrencyNotSettled()"), "CurrencyNotSettled"),
        (
            revert_data(
                "ExecutionFailed(uint256,bytes)",
                ["uint256", "bytes"],
                [0, bytes.fromhex(error_string("TRANSFER_FROM_FAILED")[2:])],
            ),
            "ExecutionFailed",
        ),
    ],
)
def test_router_and_permit2_plumbing_errors_stay_unknown(data, label):
    outcome = evaluate(failed_sell(load("v4_native_liquidity_launcher"), data))
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is None
    assert outcome["is_honeypot"] is None
    assert label in outcome["reason"]


@pytest.mark.parametrize(
    "data",
    [
        "0x",
        "0xdeadbeef",
        error_string("UniswapV2: K"),
        revert_data("Panic(uint256)", ["uint256"], [0x11]),
        revert_data(
            "WrappedError(address,bytes4,bytes,bytes)",
            ["address", "bytes4", "bytes", "bytes"],
            [
                "0x" + "12" * 20,
                b"\x00" * 4,
                b"",
                selector("NativeTransferFailed()"),
            ],
        ),
    ],
)
def test_unknown_or_undecodable_sell_reverts_stay_unknown(data):
    outcome = evaluate(failed_sell(load("v4_native_liquidity_launcher"), data))
    assert outcome["can_sell"] is None
    assert outcome["is_honeypot"] is None
    assert outcome["reason"]


def test_v4_token_refusal_string_is_not_a_trap_on_the_v2_route():
    outcome = evaluate(failed_sell(load("v2_router02"), error_string("TRANSFER_FROM_FAILED")))
    assert outcome["can_sell"] is None
    assert outcome["is_honeypot"] is None


@pytest.mark.parametrize("name", ["v4_native_liquidity_launcher", "v4_doppler_weth", "v4_doppler_native_fee_hook", "v2_router02"])
@pytest.mark.parametrize(
    "data",
    [
        error_string("TRANSFER_FROM_FAILED"),
        revert_data(
            "WrappedError(address,bytes4,bytes,bytes)",
            ["address", "bytes4", "bytes", "bytes"],
            [
                HOOK_INITIALIZER,
                b"\x00" * 4,
                b"",
                selector("HookCallFailed()"),
            ],
        ),
        "0x",
    ],
)
def test_buy_revert_leaves_every_verdict_unknown(name, data):
    fixture = load(name)
    make_revert(calls_by_label(fixture)["buy"], data)
    outcome = evaluate(fixture)
    assert all(outcome[field] is None for field in FIELDS)
    assert "buy reverted" in outcome["reason"]


@pytest.mark.parametrize("label", ["approve", "permit"])
def test_failed_sell_approval_is_unknown_even_if_the_sell_then_fails(label):
    fixture = failed_sell(
        load("v4_native_liquidity_launcher"), error_string("TRANSFER_FROM_FAILED")
    )
    make_revert(calls_by_label(fixture)[label], "0x")
    outcome = evaluate(fixture)
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is outcome["is_honeypot"] is None


def test_weth_funding_failure_is_unknown():
    fixture = load("v4_doppler_weth")
    make_revert(calls_by_label(fixture)["fund"], "0x")
    outcome = evaluate(fixture)
    assert all(outcome[field] is None for field in FIELDS)


@pytest.mark.parametrize(
    "name", ["v4_native_liquidity_launcher", "v4_doppler_native_fee_hook", "v2_router02"]
)
def test_untraced_native_transfers_make_the_sell_unknown_instead_of_a_trap(name):
    # Without traceTransfers evidence in the buy, a sell paying ETH looks like zero output.
    fixture = load(name)
    calls = calls_by_label(fixture)
    calls["buy"]["logs"] = [
        log for log in calls["buy"]["logs"] if log["address"] != "0x" + "e" * 40
    ]
    calls["sell"]["logs"] = [
        log for log in calls["sell"]["logs"] if log["address"] != "0x" + "e" * 40
    ]
    outcome = evaluate(fixture)
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is None
    assert outcome["is_honeypot"] is None
    assert "tracing unavailable" in outcome["reason"]


def test_a_reverting_sell_is_still_a_honeypot_without_transfer_tracing():
    # A revert is authoritative on its own, so the tracing guard must not downgrade it to unknown.
    fixture = load("v2_honeypot_sell_reverts")
    for call in fixture["response"]["result"][0]["calls"]:
        call["logs"] = [log for log in call["logs"] if log["address"] != "0x" + "e" * 40]
    outcome = evaluate(fixture)
    assert outcome["can_sell"] is False
    assert outcome["is_honeypot"] is True
    assert 'Error("TransferHelper: TRANSFER_FROM_FAILED")' in outcome["reason"]


def test_buy_transfer_tax_is_measured_but_sell_is_not_sizeable():
    fixture = load("v4_native_liquidity_launcher")
    calls = calls_by_label(fixture)
    set_uint(calls["delivered"], fixture["amount"] * 95 // 100)
    outcome = evaluate(fixture)
    assert outcome["buy_tax"] == 5.0
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is None
    assert outcome["is_honeypot"] is None
    assert outcome["sell_tax"] is None
    assert "not sizeable" in outcome["reason"]


def test_buy_delivering_nothing_cannot_buy():
    fixture = load("v2_router02")
    set_uint(calls_by_label(fixture)["delivered"], 0)
    outcome = evaluate(fixture)
    assert outcome["buy_tax"] == 100.0
    assert outcome["can_buy"] is False
    assert outcome["can_sell"] is outcome["is_honeypot"] is None


def router_swap_event(fixture):
    pool = pool_of(fixture)
    router = "0x" + "0" * 24 + "8876789976decbfcbbbe364623c63652db8c0904"
    pool_id = "0x" + keccak(encode(["address", "address", "uint24", "int24", "address"], list(pool.key))).hex()
    swap_topic = "0x" + keccak(text="Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)").hex()
    (event,) = [
        log
        for log in calls_by_label(fixture)["sell"]["logs"]
        if log["address"] == POOL_MANAGER and log["topics"] == [swap_topic, pool_id, router]
    ]
    return event


def test_v4_sell_tax_is_the_pool_manager_credit_from_the_router_swap_event():
    fixture = load("v4_native_liquidity_launcher")
    event = router_swap_event(fixture)
    words = [event["data"][2 + 64 * index : 2 + 64 * (index + 1)] for index in range(6)]
    credited = fixture["amount"] * 88 // 100
    words[1] = encode(["int128"], [-credited]).hex()
    event["data"] = "0x" + "".join(words)
    outcome = evaluate(fixture)
    assert outcome["sell_tax"] == 12.0
    assert outcome["can_sell"] is True
    assert outcome["is_honeypot"] is False


def test_v4_sell_without_the_router_swap_event_has_unknown_sell_tax():
    fixture = load("v4_doppler_weth")
    event = router_swap_event(fixture)
    calls_by_label(fixture)["sell"]["logs"].remove(event)
    outcome = evaluate(fixture)
    assert outcome["sell_tax"] is None
    assert outcome["can_sell"] is True
    assert "sell tax unmeasurable" in outcome["reason"]


def test_hook_token_flows_through_the_pool_manager_are_not_a_tax():
    # Live: this Doppler pool's fee hook moves the token in and out of the PoolManager during the
    # router's swap, so PoolManager balance deltas differ from the amounts the buyer received and sent.
    fixture = load("v4_doppler_native_fee_hook")
    token, manager = fixture["token"], "0x" + "0" * 24 + POOL_MANAGER[2:]
    buyer = "0x" + "0" * 24 + fixture["buyer"][2:]
    transfer = "0x" + keccak(text="Transfer(address,address,uint256)").hex()
    for label in ("buy", "sell"):
        flows = [
            log
            for log in calls_by_label(fixture)[label]["logs"]
            if log["address"] == token
            and log["topics"][0] == transfer
            and manager in log["topics"]
            and buyer not in log["topics"]
        ]
        assert flows
    outcome = evaluate(fixture)
    assert outcome["buy_tax"] == outcome["sell_tax"] == 0.0


def test_v2_sell_tax_is_measured_from_the_pair_balance():
    fixture = load("v2_router02")
    calls = calls_by_label(fixture)
    before = int(calls["pool_before_sell"]["returnData"], 16)
    set_uint(calls["pool_after_sell"], before + fixture["amount"] * 88 // 100)
    outcome = evaluate(fixture)
    assert outcome["sell_tax"] == 12.0
    assert outcome["can_sell"] is True
    assert outcome["is_honeypot"] is False


def test_inconsistent_pool_balances_leave_the_tax_unknown():
    fixture = load("v2_router02")
    calls = calls_by_label(fixture)
    before = int(calls["pool_before_sell"]["returnData"], 16)
    set_uint(calls["pool_after_sell"], before + fixture["amount"] + 1)
    outcome = evaluate(fixture)
    assert outcome["sell_tax"] is None
    assert outcome["can_sell"] is True


@pytest.mark.parametrize("result", [None, [], [{}], [{"number": "0x1", "calls": []}], "bad"])
def test_malformed_simulation_output_is_unknown(result):
    fixture = load("v4_native_liquidity_launcher")
    outcome = evaluate_simulation(
        pool_of(fixture), fixture["token"], fixture["amount"], fixture["buyer"], result
    )
    assert all(outcome[field] is None for field in FIELDS)
    assert "malformed" in outcome["reason"].lower()


# --- tax arithmetic -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sent,received,expected",
    [
        (1000, 950, 5.0),
        (1000, 1000, 0.0),
        (1000, 0, 100.0),
        (3, 2, 33.3333),
        (10**21, 10**21 * 97 // 100, 3.0),
        (0, 0, None),
        (100, 101, None),
        (100, -1, None),
    ],
)
def test_tax_percent(sent, received, expected):
    assert tax_percent(sent, received) == expected


# --- aggregation across pools ---------------------------------------------------------------


def outcome(**fields):
    base = {
        "route": "v4-native",
        "pool": "0xpool",
        "block": 10,
        "reason": "measured",
        **{field: None for field in FIELDS},
    }
    return {**base, **fields}


def test_trap_pool_is_not_masked_by_a_sellable_pool():
    sellable = outcome(
        pool="0xsellable",
        can_buy=True,
        can_sell=True,
        is_honeypot=False,
        buy_tax=0.0,
        sell_tax=1.0,
        reason="buy and sell succeeded",
    )
    trap = outcome(
        route="v2",
        pool="0xtrap",
        block=12,
        can_buy=True,
        can_sell=False,
        is_honeypot=True,
        buy_tax=3.0,
        reason="sell reverted: token transfer refused",
    )
    for outcomes in ([sellable, trap], [trap, sellable]):
        result = aggregate_outcomes(outcomes, [])
        assert result["is_honeypot"] is True
        assert result["can_sell"] is False
        assert result["can_buy"] is True
        assert result["buy_tax"] == 3.0
        assert result["sell_tax"] == 1.0
        assert result["simulation_block"] == 12
        assert "0xsellable" in result["reason"] and "0xtrap" in result["reason"]


def test_sell_tax_of_one_hundred_percent_is_a_honeypot():
    result = aggregate_outcomes(
        [outcome(can_buy=True, can_sell=True, is_honeypot=True, buy_tax=0.0, sell_tax=100.0)], []
    )
    assert result["is_honeypot"] is True


def test_unknown_pools_do_not_create_verdicts():
    result = aggregate_outcomes(
        [outcome(reason="buy reverted: 0x")], ["V2 pair 0xabc has no reserves"]
    )
    assert all(result[field] is None for field in FIELDS)
    assert "no reserves" in result["reason"] and "buy reverted" in result["reason"]


def test_no_outcomes_is_unknown_with_reason():
    result = aggregate_outcomes([], ["No supported pool found"])
    assert all(result[field] is None for field in FIELDS)
    assert result["simulation_block"] is None
    assert result["reason"] == "No supported pool found"


# --- RPC transport ---------------------------------------------------------------------------


def http_response(status, payload=None):
    response = MagicMock(status=status)
    response.json = AsyncMock(return_value=payload)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=response)
    context.__aexit__ = AsyncMock(return_value=False)
    return context


def http_session(*responses):
    session = MagicMock()
    session.post.side_effect = list(responses)
    return session


@pytest.mark.asyncio
async def test_http_429_is_retried_with_backoff_then_unknown():
    simulator = RobinhoodSimulator("https://rpc.invalid")
    session = http_session(*(http_response(429) for _ in range(3)))
    with patch("services.robinhood_simulation.asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(SimulationUnavailable, match="HTTP 429"):
            await simulator._request(session, [("eth_blockNumber", [])])
    assert session.post.call_count == 3
    assert [call.args for call in sleep.await_args_list] == [(1.0,), (2.0,)]


@pytest.mark.asyncio
async def test_http_429_then_success_returns_rows():
    simulator = RobinhoodSimulator("https://rpc.invalid")
    session = http_session(
        http_response(429), http_response(200, {"jsonrpc": "2.0", "id": 0, "result": "0x10"})
    )
    with patch("services.robinhood_simulation.asyncio.sleep", new_callable=AsyncMock):
        rows = await simulator._request(session, [("eth_blockNumber", [])])
    assert rows == [{"jsonrpc": "2.0", "id": 0, "result": "0x10"}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        {"code": -32005, "message": "limit exceeded"},
        {"code": 429, "message": "Too Many Requests"},
        {"code": -32000, "message": "rate limit reached"},
    ],
)
async def test_json_rpc_rate_limit_is_retried_then_unknown(error):
    simulator = RobinhoodSimulator("https://rpc.invalid")
    rows = [
        {"jsonrpc": "2.0", "id": 0, "error": error},
        {"jsonrpc": "2.0", "id": 1, "result": "0x1"},
    ]
    session = http_session(*(http_response(200, rows) for _ in range(3)))
    with patch("services.robinhood_simulation.asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(SimulationUnavailable, match="rate limit"):
            await simulator._request(session, [("eth_blockNumber", []), ("eth_chainId", [])])
    assert session.post.call_count == 3
    assert sleep.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", [None, "text", [1], {"jsonrpc": "2.0", "id": 7, "result": "0x1"}]
)
async def test_malformed_rpc_envelope_is_unavailable(payload):
    simulator = RobinhoodSimulator("https://rpc.invalid")
    with pytest.raises(SimulationUnavailable, match="Malformed"):
        await simulator._request(
            http_session(http_response(200, payload)), [("eth_blockNumber", [])]
        )


@pytest.mark.asyncio
async def test_http_error_status_is_unavailable_without_retry():
    simulator = RobinhoodSimulator("https://rpc.invalid")
    session = http_session(http_response(503))
    with pytest.raises(SimulationUnavailable, match="HTTP 503"):
        await simulator._request(session, [("eth_blockNumber", [])])
    assert session.post.call_count == 1


TOKEN = "0x" + "7a" * 20


def adapter_with(simulator_request):
    from adapters.robinhood import RobinhoodAdapter

    with patch("adapters.evm_base.Web3"):
        adapter = RobinhoodAdapter()
    adapter._simulator._request = simulator_request
    return adapter


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure,reason",
    [
        (aiohttp.ClientConnectionError(f"https://rpc.invalid/{SECRET}"), "ClientConnectionError"),
        (asyncio.TimeoutError(), "TimeoutError"),
        (SimulationUnavailable("RPC rate limited (HTTP 429) after 3 attempts"), "HTTP 429"),
    ],
)
async def test_rpc_failures_are_unknown_and_never_simulation_failed(failure, reason, caplog):
    adapter = adapter_with(AsyncMock(side_effect=failure))
    caplog.set_level(logging.DEBUG)
    honeypot = await adapter.check_honeypot(TOKEN)
    taxes = await adapter.get_tax_info(TOKEN)
    assert honeypot["status"] == taxes["status"] == "unknown"
    assert all(honeypot.get(field) is None for field in ("is_honeypot", "can_buy", "can_sell"))
    assert taxes["buy_tax"] is None and taxes["sell_tax"] is None
    assert reason in honeypot["reason"] and reason in taxes["reason"]
    assert "simulation_failed" not in honeypot and "simulation_failed" not in taxes
    assert "simulation_success" not in honeypot
    assert honeypot["field_providers"] == taxes["field_providers"] == {}
    assert SECRET not in caplog.text


# --- discovery and end-to-end replay ----------------------------------------------------------


def word(value):
    return "0x" + value.to_bytes(32, "big").hex()


def address_word(address):
    return "0x" + encode(["address"], [address]).hex()


def doppler_state(key=None, numeraire=ZERO, status=0):
    key = key or (ZERO, ZERO, 0, 0, ZERO)
    return (
        "0x"
        + encode(
            [
                "address",
                "uint256",
                "address",
                "bytes",
                "uint8",
                "(address,address,uint24,int24,address)",
                "int24",
            ],
            [numeraire, 0, ZERO, b"", status, key, 0],
        ).hex()
    )


def pool_state_slot(key):
    pool_id = keccak(encode(["address", "address", "uint24", "int24", "address"], list(key)))
    return "0x" + keccak(pool_id + (6).to_bytes(32, "big")).hex()


class FakeRpc:
    """Answers the simulator's JSON-RPC calls from explicit tables; records every request."""

    def __init__(
        self,
        token,
        supply,
        pair=ZERO,
        reserves=(0, 0),
        state=None,
        slot0=0,
        simulations=(),
        logs=None,
        head=65_540_000,
    ):
        self.token = token
        self.supply = supply
        self.pair = pair
        self.reserves = reserves
        self.state = state or doppler_state()
        self.slot0 = slot0
        self.simulations = list(simulations)
        self.logs = logs or {}
        self.head = head
        self.requests = []

    async def __call__(self, session, calls):
        self.requests.append(calls)
        return [
            {"jsonrpc": "2.0", "id": index, **self.answer(method, params)}
            for index, (method, params) in enumerate(calls)
        ]

    def answer(self, method, params):
        if method == "eth_blockNumber":
            return {"result": hex(self.head)}
        if method == "eth_getLogs":
            query = params[0]
            return {
                "result": self.logs.get(
                    (int(query["fromBlock"], 16), int(query["toBlock"], 16)), []
                )
            }
        if method == "eth_simulateV1":
            expected, response = self.simulations.pop(0)
            assert params == expected
            return response
        target, data = params[0]["to"], params[0]["data"]
        if data == "0x" + selector("totalSupply()").hex():
            assert target == self.token
            return {"result": word(self.supply)}
        if data.startswith("0x" + selector("getPair(address,address)").hex()):
            assert target == V2_FACTORY
            return {"result": address_word(self.pair)}
        if data == "0x" + selector("getReserves()").hex():
            assert target == self.pair
            return {
                "result": "0x" + encode(["uint112", "uint112", "uint32"], [*self.reserves, 1]).hex()
            }
        if data.startswith("0x" + selector("getState(address)").hex()):
            assert target == HOOK_INITIALIZER
            return {"result": self.state}
        if data.startswith("0x" + selector("extsload(bytes32)").hex()):
            assert target == POOL_MANAGER
            return {"result": word(self.slot0)}
        raise AssertionError(f"unexpected call {method} {params}")


def replay(fixture, sell_amount=None):
    return (
        [
            build_simulation_request(
                pool_of(fixture),
                fixture["token"],
                fixture["amount"],
                fixture["buyer"],
                fixture["receiver"],
                sell_amount,
            ),
            "latest",
        ],
        fixture["response"],
    )


def fresh_addresses(*fixtures):
    return patch(
        "services.robinhood_simulation._fresh_address",
        side_effect=[
            address for fixture in fixtures for address in (fixture["buyer"], fixture["receiver"])
        ],
    )


def rpc_for(fixture, **overrides):
    token = fixture["token"]
    options = {
        "token": token,
        "supply": fixture["amount"] * 1_000_000,
        "simulations": [replay(fixture)],
    }
    if fixture["route"] == "v4-native":
        options["slot0"] = 1 << 100
    elif fixture["route"] == "v4-doppler":
        options["state"] = doppler_state(tuple(fixture["key"]), fixture["numeraire"], status=2)
    elif fixture["route"] == "v2":
        options.update(pair=fixture["pair"], reserves=(10**20, 10**27))
    options.update(overrides)
    return FakeRpc(**options)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["v4_native_liquidity_launcher", "v4_doppler_weth", "v4_doppler_native_fee_hook", "v2_router02"])
async def test_discovery_finds_the_pool_and_runs_one_simulation(name):
    fixture = load(name)
    rpc = rpc_for(fixture)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])
    assert result["is_honeypot"] is False
    assert result["can_buy"] is result["can_sell"] is True
    assert result["buy_tax"] == result["sell_tax"] == 0.0
    assert result["simulation_block"] == int(fixture["response"]["result"][0]["number"], 16)
    methods = [method for calls in rpc.requests for method, _ in calls]
    assert methods.count("eth_simulateV1") == 1
    assert "eth_getLogs" not in methods
    assert rpc.simulations == []


@pytest.mark.asyncio
async def test_liquidity_launcher_lookup_reads_the_derived_pool_slot():
    fixture = load("v4_native_liquidity_launcher")
    rpc = rpc_for(fixture)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(fixture):
        await simulator.simulate(fixture["token"])
    extsload = [
        params[0]["data"]
        for calls in rpc.requests
        for method, params in calls
        if method == "eth_call"
        and params[0]["data"].startswith("0x" + selector("extsload(bytes32)").hex())
    ]
    assert extsload == [
        "0x" + selector("extsload(bytes32)").hex() + pool_state_slot(tuple(fixture["key"]))[2:]
    ]


@pytest.mark.asyncio
async def test_unfundable_doppler_numeraire_is_an_unsupported_route():
    token = "0x75642a3674678a5b6b409fb554204160c0371e18"
    numeraire = "0xf51fb54de60f6e16252e852a5ed0e60b8307606a"
    key = (token, numeraire, 0x800000, 8, HOOK_INITIALIZER)
    rpc = FakeRpc(token, 10**27, state=doppler_state(key, numeraire, status=2))
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    result = await simulator.simulate(token)
    assert all(result[field] is None for field in FIELDS)
    assert "unsupported route" in result["reason"]
    assert numeraire in result["reason"]
    methods = [method for calls in rpc.requests for method, _ in calls]
    assert "eth_simulateV1" not in methods


def initialize_log(currency0, currency1, fee, tick_spacing, hooks, block):
    pool_id = keccak(
        encode(
            ["address", "address", "uint24", "int24", "address"],
            [currency0, currency1, fee, tick_spacing, hooks],
        )
    )
    return {
        "address": POOL_MANAGER,
        "topics": [
            "0x"
            + keccak(
                text="Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)"
            ).hex(),
            "0x" + pool_id.hex(),
            address_word(currency0),
            address_word(currency1),
        ],
        "data": "0x"
        + encode(
            ["uint24", "int24", "address", "uint160", "int24"], [fee, tick_spacing, hooks, 2**96, 0]
        ).hex(),
        "blockNumber": hex(block),
    }


@pytest.mark.asyncio
async def test_log_scan_is_bounded_and_no_pool_is_unknown():
    rpc = FakeRpc(TOKEN, 10**27)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    result = await simulator.simulate(TOKEN)
    assert all(result[field] is None for field in FIELDS)
    assert "No supported pool" in result["reason"]
    windows = [
        params[0] for calls in rpc.requests for method, params in calls if method == "eth_getLogs"
    ]
    assert len(windows) == MAX_LOG_WINDOWS
    for window in windows:
        assert int(window["toBlock"], 16) - int(window["fromBlock"], 16) + 1 <= LOG_WINDOW_BLOCKS
        assert window["address"] == POOL_MANAGER
    assert int(windows[0]["toBlock"], 16) == rpc.head
    assert int(windows[-1]["fromBlock"], 16) == rpc.head - MAX_LOG_WINDOWS * LOG_WINDOW_BLOCKS + 1


@pytest.mark.asyncio
async def test_log_scan_finds_hookless_native_pool_with_any_fee_tier():
    fixture = copy.deepcopy(load("v4_native_liquidity_launcher"))
    head = 65_540_000
    other = initialize_log(ZERO, "0x" + "99" * 20, 500, 1, ZERO, head - 5)
    custom_hook = initialize_log(
        ZERO, fixture["token"], 3000, 60, "0x" + "c0" * 19 + "ff", head - 4
    )
    found = initialize_log(ZERO, fixture["token"], 2500, 25, ZERO, head - 3)
    rpc = rpc_for(
        fixture,
        slot0=0,
        head=head,
        logs={(head - LOG_WINDOW_BLOCKS + 1, head): [other, custom_hook, found]},
    )
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])
    assert result["can_sell"] is True
    assert "unsupported" in result["reason"] and "0x" + "c0" * 19 + "ff" in result["reason"]
    assert rpc.simulations == []


@pytest.mark.asyncio
async def test_v2_pair_without_reserves_is_skipped():
    rpc = FakeRpc(TOKEN, 10**27, pair="0x" + "55" * 20, reserves=(0, 0))
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    result = await simulator.simulate(TOKEN)
    assert all(result[field] is None for field in FIELDS)
    assert "no reserves" in result["reason"]


@pytest.mark.asyncio
async def test_every_found_pool_is_simulated_and_a_trap_pool_wins():
    native = load("v4_native_liquidity_launcher")
    v2 = load("v2_router02")
    token = native["token"]
    # Same token on its V2 pair: size the recorded V2 buy to the token's shared buy amount.
    v2 = json.loads(json.dumps(v2).replace(v2["token"][2:], token[2:]))
    v2["amount"] = native["amount"]
    calls = calls_by_label(v2)
    set_uint(calls["delivered"], native["amount"])
    trap = failed_sell(v2, error_string("TransferHelper: TRANSFER_FROM_FAILED"))
    rpc = FakeRpc(
        token,
        native["amount"] * 1_000_000,
        pair=v2["pair"],
        reserves=(10**20, 10**27),
        slot0=1 << 100,
        simulations=[replay(native), replay(trap)],
    )
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(native, trap):
        result = await simulator.simulate(token)
    methods = [method for calls in rpc.requests for method, _ in calls]
    assert methods.count("eth_simulateV1") == 2
    assert "eth_getLogs" not in methods
    assert result["is_honeypot"] is True
    assert result["can_sell"] is False
    assert result["can_buy"] is True
    assert "TransferHelper: TRANSFER_FROM_FAILED" in result["reason"]
    assert "buy and sell succeeded" in result["reason"]


@pytest.mark.asyncio
async def test_simulated_pools_are_capped():
    fixture = load("v4_native_liquidity_launcher")
    token = fixture["token"]
    head = 65_540_000
    tiers = ((100, 1), (500, 10), (2500, 25), (3000, 60))
    logs = [
        initialize_log(ZERO, token, fee, spacing, ZERO, head - index)
        for index, (fee, spacing) in enumerate(tiers)
    ]
    simulations = [
        (
            [
                build_simulation_request(
                    Pool("v4-native", ZERO, key=(ZERO, token, fee, spacing, ZERO)),
                    token,
                    fixture["amount"],
                    fixture["buyer"],
                    fixture["receiver"],
                ),
                "latest",
            ],
            fixture["response"],
        )
        for fee, spacing in tiers[:MAX_POOLS]
    ]
    rpc = FakeRpc(
        token,
        fixture["amount"] * 1_000_000,
        head=head,
        simulations=simulations,
        logs={(head - LOG_WINDOW_BLOCKS + 1, head): logs},
    )
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with patch(
        "services.robinhood_simulation._fresh_address",
        side_effect=[fixture["buyer"], fixture["receiver"]] * MAX_POOLS,
    ):
        result = await simulator.simulate(token)
    assert MAX_POOLS == 3
    methods = [method for calls in rpc.requests for method, _ in calls]
    assert methods.count("eth_simulateV1") == MAX_POOLS
    assert rpc.simulations == []
    assert "not simulated (cap of 3 pools)" in result["reason"]
    assert result["can_sell"] is True


@pytest.mark.asyncio
async def test_hookless_weth_pool_found_by_the_log_scan_is_measured():
    fixture = load("v4_weth_hookless")
    head = 65_540_000
    logs = {(head - LOG_WINDOW_BLOCKS + 1, head): [initialize_log(*fixture["key"], head)]}
    rpc = rpc_for(fixture, logs=logs, head=head)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])
    assert result["can_buy"] is result["can_sell"] is True
    assert result["buy_tax"] == result["sell_tax"] == 0.0
    assert result["is_honeypot"] is False
    assert result["simulation_block"] == 65704949
    assert "v4-weth pool" in result["reason"]
    assert rpc.simulations == []


@pytest.mark.asyncio
async def test_log_scan_finds_a_hookless_weth_pool():
    # Hookless WETH pools need the same WETH funding as a Doppler WETH pool and no new encoding.
    token = "0x" + "b3" * 20
    amount, head = 10**18, 65_540_000
    key = (WETH, token, 100, 1, ZERO)
    pool = Pool("v4-weth", WETH, key=key)
    buyer, receiver = "0x" + "11" * 20, "0x" + "22" * 20
    request = build_simulation_request(pool, token, amount, buyer, receiver)
    rpc = FakeRpc(
        token,
        amount * 1_000_000,
        head=head,
        simulations=[([request, "latest"], {"error": {"code": -32000, "message": "boom"}})],
        logs={(head - LOG_WINDOW_BLOCKS + 1, head): [initialize_log(*key, head)]},
    )
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with patch(
        "services.robinhood_simulation._fresh_address", side_effect=[buyer, receiver]
    ):
        result = await simulator.simulate(token)
    pool_id = keccak(encode(["address", "address", "uint24", "int24", "address"], list(key)))
    assert f"v4-weth pool 0x{pool_id.hex()}" in result["reason"]
    assert call_labels(pool)[:3] == ["fund", "fund_approve", "fund_permit"]
    assert all(result[field] is None for field in FIELDS)


def short_delivery(fixture, delivered):
    """The buy paid out `amount`, but a transfer tax delivered less to the buyer."""
    fixture = copy.deepcopy(fixture)
    set_uint(calls_by_label(fixture)["delivered"], delivered)
    return fixture


def sized_sell(fixture, delivered):
    """A follow-up sized to the delivered balance: the whole balance reaches the pair."""
    fixture = short_delivery(fixture, delivered)
    calls = calls_by_label(fixture)
    set_uint(calls["after_sell"], 0)
    set_uint(calls["pool_after_sell"], int(calls["pool_before_sell"]["returnData"], 16) + delivered)
    return fixture


def simulation_requests(rpc):
    return [calls for calls in rpc.requests if calls[0][0] == "eth_simulateV1"]


@pytest.mark.parametrize("name", ["v2_router02", "v4_doppler_weth", "v4_native_liquidity_launcher"])
def test_sized_request_buys_the_full_amount_and_sells_the_delivered_balance(name):
    fixture = load(name)
    pool, token, amount = pool_of(fixture), fixture["token"], fixture["amount"]
    delivered = amount * 88 // 100
    addresses = (fixture["buyer"], fixture["receiver"])
    labels = call_labels(pool)

    def calls_of(*args):
        request = build_simulation_request(*args)
        return dict(zip(labels, request["blockStateCalls"][0]["calls"]))

    sized = calls_of(pool, token, amount, *addresses, delivered)
    full = calls_of(pool, token, amount, *addresses)
    smaller = calls_of(pool, token, delivered, *addresses)
    assert sized["buy"] == full["buy"]
    assert sized["sell"] == smaller["sell"] != full["sell"]
    assert sized["transfer"] == smaller["transfer"]
    assert [label for label in labels if sized[label] != full[label]] == ["sell", "transfer"]


def test_sized_evaluation_measures_the_sell_of_a_taxed_token():
    fixture = load("v2_router02")
    delivered = fixture["amount"] * 88 // 100
    outcome = evaluate(sized_sell(fixture, delivered), sell_amount=delivered)
    assert outcome["can_buy"] is outcome["can_sell"] is True
    assert outcome["buy_tax"] == 12.0
    assert outcome["sell_tax"] == 0.0
    assert outcome["is_honeypot"] is False
    assert outcome["retry_sell_amount"] is None


@pytest.mark.asyncio
async def test_short_delivery_is_retried_once_sized_to_the_delivered_balance():
    fixture = load("v2_router02")
    delivered = fixture["amount"] * 88 // 100
    first, second = short_delivery(fixture, delivered), sized_sell(fixture, delivered)
    rpc = rpc_for(fixture, simulations=[replay(first), replay(second, sell_amount=delivered)])
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(first, second):
        result = await simulator.simulate(fixture["token"])
    assert len(simulation_requests(rpc)) == 2
    assert result["can_buy"] is result["can_sell"] is True
    assert result["buy_tax"] == 12.0
    assert result["sell_tax"] == 0.0
    assert result["is_honeypot"] is False


@pytest.mark.asyncio
async def test_a_still_short_follow_up_stays_unknown_after_one_extra_request():
    fixture = load("v2_router02")
    delivered = fixture["amount"] * 88 // 100
    first = short_delivery(fixture, delivered)
    second = short_delivery(fixture, delivered * 9 // 10)
    rpc = rpc_for(fixture, simulations=[replay(first), replay(second, sell_amount=delivered)])
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(first, second):
        result = await simulator.simulate(fixture["token"])
    assert len(simulation_requests(rpc)) == 2
    assert result["can_buy"] is True
    assert result["can_sell"] is None
    assert result["is_honeypot"] is None
    assert result["sell_tax"] is None
    assert "not sizeable in one request" in result["reason"]


@pytest.mark.asyncio
async def test_a_failed_follow_up_keeps_the_buy_evidence_and_stays_unknown():
    fixture = load("v2_router02")
    delivered = fixture["amount"] * 88 // 100
    first = short_delivery(fixture, delivered)
    sized = replay(first, sell_amount=delivered)[0]
    rpc = rpc_for(
        fixture,
        simulations=[replay(first), (sized, {"error": {"code": -32000, "message": "boom"}})],
    )
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(first, first):
        result = await simulator.simulate(fixture["token"])
    assert len(simulation_requests(rpc)) == 2
    assert result["can_buy"] is True
    assert result["buy_tax"] == 12.0
    assert result["can_sell"] is None
    assert result["is_honeypot"] is None
    assert "not sizeable in one request" in result["reason"]


@pytest.mark.asyncio
async def test_a_full_delivery_issues_exactly_one_simulation_request():
    fixture = load("v2_router02")
    rpc = rpc_for(fixture)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])
    assert len(simulation_requests(rpc)) == 1
    assert result["can_sell"] is True


@pytest.mark.asyncio
async def test_simulate_v1_unsupported_is_unknown():
    fixture = load("v4_native_liquidity_launcher")
    request, _ = replay(fixture)
    rpc = rpc_for(
        fixture,
        simulations=[
            (
                request,
                {
                    "error": {
                        "code": -32601,
                        "message": "the method eth_simulateV1 does not exist/is not available",
                    }
                },
            )
        ],
    )
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])
    assert all(result[field] is None for field in FIELDS)
    assert "eth_simulateV1 unsupported" in result["reason"]


@pytest.mark.asyncio
async def test_malformed_simulate_v1_result_is_unknown():
    fixture = load("v2_router02")
    request, _ = replay(fixture)
    rpc = rpc_for(fixture, simulations=[(request, {"result": {"unexpected": True}})])
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])
    assert all(result[field] is None for field in FIELDS)
    assert "malformed" in result["reason"].lower()


@pytest.mark.asyncio
async def test_invalid_token_address_makes_no_rpc_call():
    rpc = FakeRpc(TOKEN, 10**27)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc
    result = await simulator.simulate("not-an-address")
    assert all(result[field] is None for field in FIELDS)
    assert rpc.requests == []


# --- caching ------------------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("concurrent", [False, True])
async def test_one_simulation_per_token_across_both_adapter_methods(concurrent):
    fixture = load("v4_native_liquidity_launcher")
    rpc = rpc_for(fixture)
    adapter = adapter_with(rpc)
    with fresh_addresses(fixture):
        if concurrent:
            honeypot, taxes = await asyncio.gather(
                adapter.check_honeypot(fixture["token"]),
                adapter.get_tax_info(fixture["token"].upper().replace("0X", "0x")),
            )
        else:
            honeypot = await adapter.check_honeypot(fixture["token"])
            taxes = await adapter.get_tax_info(fixture["token"])
    methods = [method for calls in rpc.requests for method, _ in calls]
    assert methods.count("eth_simulateV1") == 1
    assert honeypot["is_honeypot"] is False and honeypot["status"] == "ok"
    assert taxes["buy_tax"] == taxes["sell_tax"] == 0.0 and taxes["status"] == "ok"


# --- adapter shapes and integration -------------------------------------------------------------


@pytest.mark.asyncio
async def test_adapter_shapes_match_evm_base_with_simulation_providers():
    fixture = load("v4_doppler_weth")
    adapter = adapter_with(rpc_for(fixture))
    with fresh_addresses(fixture):
        honeypot = await adapter.check_honeypot(fixture["token"])
        taxes = await adapter.get_tax_info(fixture["token"])
    assert honeypot == {
        "is_honeypot": False,
        "can_buy": True,
        "can_sell": True,
        "status": "ok",
        "reason": honeypot["reason"],
        "simulation_block": 65551506,
        "field_providers": {
            "is_honeypot": "eth_simulateV1",
            "can_buy": "eth_simulateV1",
            "can_sell": "eth_simulateV1",
        },
    }
    assert taxes == {
        "buy_tax": 0.0,
        "sell_tax": 0.0,
        "status": "ok",
        "reason": taxes["reason"],
        "simulation_block": 65551506,
        "field_providers": {"buy_tax": "eth_simulateV1", "sell_tax": "eth_simulateV1"},
    }


def client_with(adapter):
    client = Web3Client.__new__(Web3Client)
    client._adapters = {4663: adapter}
    return client


@pytest.mark.asyncio
async def test_4663_end_to_end_measured_simulation_is_ok():
    fixture = load("v4_native_liquidity_launcher")
    adapter = adapter_with(rpc_for(fixture))
    service = HoneypotService(client_with(adapter))
    with (
        fresh_addresses(fixture),
        patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock()) as goplus,
    ):
        data = await service.fetch_honeypot_data(fixture["token"], chain_id=4663)
        result = await HoneypotAnalyzer(service).analyze(
            AnalysisContext(fixture["token"], chain_id=4663)
        )
    goplus.assert_not_awaited()
    assert data["status"] == "ok"
    assert data["field_providers"] == {field: "eth_simulateV1" for field in FIELDS}
    assert (
        data["is_honeypot"],
        data["can_buy"],
        data["can_sell"],
        data["buy_tax"],
        data["sell_tax"],
    ) == (False, True, True, 0.0, 0.0)
    assert data["simulation_failed"] is False
    assert result.data["status"] == "ok"
    assert all(result.data["coverage"].values())
    assert result.score == 0


@pytest.mark.asyncio
async def test_4663_end_to_end_unmeasured_simulation_is_unknown():
    fixture = load("v4_native_liquidity_launcher")
    fixture = copy.deepcopy(fixture)
    make_revert(calls_by_label(fixture)["buy"], error_string("TRANSFER_FAILED"))
    adapter = adapter_with(rpc_for(fixture))
    service = HoneypotService(client_with(adapter))
    unavailable = AsyncMock(
        return_value={"status": "unknown", "reason": "GoPlus has no data", "data": {}}
    )
    with (
        fresh_addresses(fixture),
        patch.object(ScamDatabase, "fetch_token_security", new=unavailable),
    ):
        data = await service.fetch_honeypot_data(fixture["token"], chain_id=4663)
        result = await HoneypotAnalyzer(service).analyze(
            AnalysisContext(fixture["token"], chain_id=4663)
        )
    assert data["status"] == "unknown"
    assert all(data[field] is None for field in FIELDS)
    assert data["simulation_failed"] is False
    assert "buy reverted" in data["reason"]
    assert result.data["status"] == "unknown"
    assert result.score == 0


@pytest.mark.asyncio
async def test_4663_proven_honeypot_is_flagged_through_the_analyzer():
    fixture = load("v2_honeypot_sell_reverts")
    adapter = adapter_with(rpc_for(fixture))
    service = HoneypotService(client_with(adapter))
    unavailable = AsyncMock(
        return_value={"status": "unknown", "reason": "GoPlus has no data", "data": {}}
    )
    with (
        fresh_addresses(fixture),
        patch.object(ScamDatabase, "fetch_token_security", new=unavailable),
    ):
        result = await HoneypotAnalyzer(service).analyze(
            AnalysisContext(fixture["token"], chain_id=4663)
        )
    assert result.data["is_honeypot"] is True
    assert result.data["can_sell"] is False
    assert result.data["field_providers"]["can_sell"] == "eth_simulateV1"
    assert "Honeypot detected" in result.flags and "Cannot sell token" in result.flags


@pytest.mark.asyncio
async def test_goplus_never_overwrites_a_simulation_proven_honeypot():
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [4663]
    client.check_honeypot = AsyncMock(
        return_value={
            "is_honeypot": True,
            "can_buy": True,
            "can_sell": False,
            "status": "ok",
            "reason": "sell reverted",
            "field_providers": {
                "is_honeypot": "eth_simulateV1",
                "can_buy": "eth_simulateV1",
                "can_sell": "eth_simulateV1",
            },
        }
    )
    client.get_tax_info = AsyncMock(
        return_value={
            "buy_tax": 0.0,
            "sell_tax": None,
            "status": "unknown",
            "reason": "sell tax unmeasured",
            "field_providers": {"buy_tax": "eth_simulateV1"},
        }
    )
    clean = {
        "is_honeypot": "0",
        "buy_tax": "0",
        "sell_tax": "0.02",
        "cannot_buy": "0",
        "cannot_sell_all": "0",
        "transfer_pausable": "0",
    }
    with patch.object(
        ScamDatabase,
        "fetch_token_security",
        new=AsyncMock(
            return_value={
                "status": "ok",
                "reason": None,
                "data": clean,
            }
        ),
    ) as goplus:
        data = await HoneypotService(client).fetch_honeypot_data(TOKEN, chain_id=4663)
    goplus.assert_awaited_once()
    assert data["is_honeypot"] is True
    assert data["can_sell"] is False
    assert data["buy_tax"] == 0.0
    assert data["sell_tax"] == 2.0
    assert {field: data["field_providers"][field] for field in FIELDS} == {
        "is_honeypot": "eth_simulateV1",
        "can_buy": "eth_simulateV1",
        "can_sell": "eth_simulateV1",
        "buy_tax": "eth_simulateV1",
        "sell_tax": "goplus",
    }


@pytest.mark.asyncio
async def test_bsc_provider_label_stays_honeypot_is():
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [56]
    client.check_honeypot = AsyncMock(
        return_value={
            "is_honeypot": False,
            "status": "ok",
            "reason": "honeypot.is result",
            "field_providers": {"is_honeypot": "honeypot.is"},
        }
    )
    client.get_tax_info = AsyncMock(
        return_value={
            "buy_tax": 1.0,
            "sell_tax": 2.0,
            "status": "ok",
            "reason": "honeypot.is simulation taxes",
            "field_providers": {"buy_tax": "honeypot.is", "sell_tax": "honeypot.is"},
        }
    )
    with patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock()) as goplus:
        data = await HoneypotService(client).fetch_honeypot_data(TOKEN)
    goplus.assert_not_awaited()
    assert data["field_providers"] == {field: "honeypot.is" for field in FIELDS}


# --- legacy token scanner -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_legacy_scanner_uses_simulation_for_4663():
    from scanner.token_scanner import TokenScanner

    web3 = MagicMock()
    web3.supports_honeypot_simulation.return_value = True
    web3.check_honeypot = AsyncMock(
        return_value={
            "is_honeypot": False,
            "can_buy": True,
            "can_sell": True,
            "status": "ok",
            "reason": "measured",
            "field_providers": {"is_honeypot": "eth_simulateV1"},
        }
    )
    web3.get_tax_info = AsyncMock(
        return_value={
            "buy_tax": 0.0,
            "sell_tax": 3.0,
            "status": "ok",
            "reason": "measured",
            "field_providers": {"buy_tax": "eth_simulateV1", "sell_tax": "eth_simulateV1"},
        }
    )
    scanner = TokenScanner(web3)
    result = {"checks": {"can_sell": True}, "risks": []}
    await scanner._check_honeypot(TOKEN, result, chain_id=4663)
    assert await scanner._check_taxes(TOKEN, result, chain_id=4663) is True
    web3.supports_honeypot_simulation.assert_called_with(4663)
    web3.check_honeypot.assert_awaited_once_with(TOKEN, chain_id=4663)
    web3.get_tax_info.assert_awaited_once_with(TOKEN, chain_id=4663)
    assert result["is_honeypot"] is False
    assert result["honeypot_status"] == "ok"
    assert result["checks"]["can_sell"] is True
    assert (result["buy_tax"], result["sell_tax"], result["tax_status"]) == (0.0, 3.0, "ok")


@pytest.mark.asyncio
async def test_legacy_scanner_still_refuses_chains_without_a_honeypot_provider():
    from scanner.token_scanner import TokenScanner

    web3 = MagicMock()
    web3.supports_honeypot_simulation.return_value = False
    scanner = TokenScanner(web3)
    result = {"checks": {"can_sell": True}, "risks": []}
    await scanner._check_honeypot(TOKEN, result, chain_id=1)
    assert await scanner._check_taxes(TOKEN, result, chain_id=1) is False
    web3.check_honeypot.assert_not_called()
    web3.get_tax_info.assert_not_called()
    assert result["is_honeypot"] is None and result["checks"]["can_sell"] is None


def honeypot_web3(provider):
    web3 = MagicMock()
    web3.supports_honeypot_simulation.return_value = True
    web3.check_honeypot = AsyncMock(
        return_value={
            "is_honeypot": True,
            "can_buy": True,
            "can_sell": False,
            "status": "ok",
            "reason": "sell reverted: the token refused the transfer to the pool",
            "field_providers": {"is_honeypot": provider} if provider else {},
        }
    )
    return web3


@pytest.mark.asyncio
async def test_legacy_scanner_keeps_a_simulation_proven_honeypot_for_an_old_verified_token():
    # Our simulation executed the sell and it reverted, so the false-positive override must not apply.
    from scanner.token_scanner import TokenScanner

    scanner = TokenScanner(honeypot_web3("eth_simulateV1"))
    result = {"checks": {"can_sell": False}, "risks": [], "is_verified": True, "contract_age_days": 400}
    await scanner._check_honeypot(TOKEN, result, chain_id=4663)
    assert result["is_honeypot"] is True
    assert result["honeypot_reason"] == "sell reverted: the token refused the transfer to the pool"
    assert "HONEYPOT DETECTED - Cannot sell after buying" in result["risks"]
    assert not any("appears legitimate" in risk for risk in result["risks"])


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["honeypot.is", None])
async def test_legacy_scanner_still_softens_a_third_party_flag_for_an_old_verified_token(provider):
    from scanner.token_scanner import TokenScanner

    scanner = TokenScanner(honeypot_web3(provider))
    result = {"checks": {"can_sell": False}, "risks": [], "is_verified": True, "contract_age_days": 400}
    await scanner._check_honeypot(TOKEN, result, chain_id=56)
    assert result["is_honeypot"] is False
    assert any("appears legitimate" in risk for risk in result["risks"])
    assert "HONEYPOT DETECTED - Cannot sell after buying" not in result["risks"]


@pytest.mark.asyncio
async def test_legacy_scanner_flags_a_simulation_honeypot_that_is_new_or_unverified():
    from scanner.token_scanner import TokenScanner

    scanner = TokenScanner(honeypot_web3("eth_simulateV1"))
    result = {"checks": {"can_sell": False}, "risks": [], "is_verified": False, "contract_age_days": 2}
    await scanner._check_honeypot(TOKEN, result, chain_id=4663)
    assert result["is_honeypot"] is True


def test_web3_client_reports_simulation_support_per_adapter():
    from adapters.robinhood import RobinhoodAdapter
    from utils.web3_client import UnsupportedChainError

    with patch("adapters.evm_base.Web3"):
        robinhood = RobinhoodAdapter()
    client = Web3Client.__new__(Web3Client)
    client._adapters = {4663: robinhood, 56: MagicMock(spec=["check_honeypot"])}
    assert client.supports_honeypot_simulation(4663) is True
    assert client.supports_honeypot_simulation(56) is False
    with pytest.raises(UnsupportedChainError):
        client.supports_honeypot_simulation(1)
