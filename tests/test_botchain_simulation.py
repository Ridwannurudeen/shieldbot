"""BOT Chain (677) BDEX buy/sell simulation: request shapes, pool aware sizing, verdicts on simulations
recorded live (tests/fixtures/botchain_simulation/RECORDING.md), attributable and unattributable sell
failures, the confirmation run, RPC failures and the time budget."""

import ast
import asyncio
import copy
import inspect
import itertools
import json
import re
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from eth_abi import decode, encode
from eth_utils import keccak

import services.botchain_simulation as botchain_simulation
from adapters.robinhood import SIMULATION_PROVIDER
from core.unknown_ledger import UnknownLedger
from services.botchain_simulation import (
    BUY_CAP_WEI,
    CHAIN_ID,
    CONFIRMATION_DELAY_SECONDS,
    EXACT_SINGLE,
    MAX_POOLS,
    MAX_SIMULATIONS,
    MIN_POOL_DEPTH_WEI,
    MIN_TRAP_COST_WEI,
    RPC_TIMEOUT_SECONDS,
    RPC_URL,
    V2_ROUTES,
    V3_FACTORY,
    V3_FEES,
    V3_ROUTER,
    WBOT,
    BotChainSimulator,
    Pool,
    SimulationUnavailable,
    _confirm_trap,
    _pool_swap,
    build_simulation_request,
    buy_amount,
    call_labels,
    evaluate_simulation,
)
from services.robinhood_simulation import SIM_RPC_TIMEOUT_SECONDS

FIXTURES = Path(__file__).parent / "fixtures" / "botchain_simulation"
FIELDS = ("is_honeypot", "buy_tax", "sell_tax", "can_buy", "can_sell")
ZERO_WORD = "0x" + "0" * 64
BASE_BLOCK = 0x1AA4E80
BASE_TIME = 1792938251
ADDRESSES = [
    "0xb07b07b07b07b07b07b07b07b07b07b07b07b001",
    "0xb07b07b07b07b07b07b07b07b07b07b07b07b002",
    "0xb07b07b07b07b07b07b07b07b07b07b07b07b003",
]
PAYER = "0x" + "fa" * 20
COW = "0x5af9a0e7472134a6a5ad02a7d327e83ddd24b337"
COW_PAIR = Pool("BDEX", "0x27bfc83a0fc9352a03ac92096c3dde1fcf3f6542")
USDT = "0xababc7ddc03e501d190c676bf3d92ef0e6e87a3c"
USDT_V3 = Pool("v3", "0x64f418471a1a7932a190e10da5a8551db5abec05", 3000)
USDT_PAIR = Pool("BDEX", "0xdc7547f3cea82c6af7fd420656ce532c6da9b98d")
BDEX_REFUSED = "TransferHelper::transferFrom: transferFrom failed"
BDEX_NO_INPUT = "BotDexV2Library: INSUFFICIENT_INPUT_AMOUNT"
SPLIT_HEX = re.compile(r"0x[0-9a-fA-F]{32}(?:_[0-9a-fA-F]{1,32})+")


def _join(value):
    """Undo RECORDING.md's underscore after every 32 hex digits."""
    if isinstance(value, dict):
        return {key: _join(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_join(item) for item in value]
    if isinstance(value, str):
        return SPLIT_HEX.sub(lambda match: match.group().replace("_", ""), value)
    return value


def load(name):
    return _join(json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8")))


def simulations(name):
    """The fixture's eth_simulateV1 exchanges, in the order the simulator sent them."""
    return [
        exchange
        for exchange in load(name)["exchanges"]
        if exchange["calls"][0][0] == "eth_simulateV1"
    ]


def _word(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def _address_word(address: str) -> str:
    return "0x" + "0" * 24 + address[2:]


def error_string(message):
    return (
        "0x" + (keccak(text="Error(string)")[:4] + encode(["string"], [message])).hex()
    )


class Run:
    """One recorded eth_simulateV1 run: the pool, the inputs the request was built from and the reply."""

    def __init__(self, exchange, pool, token):
        request, block = exchange["calls"][0][1]
        calls = request["blockStateCalls"][0]["calls"]
        self.pool = pool
        self.token = token
        self.block = block
        self.request = request
        self.amount = int(calls[0]["value"], 16)
        self.buyer = calls[1]["from"]
        self.sell_amount = None
        self.receiver = ADDRESSES[0]
        if len(calls) > 2:
            sell = bytes.fromhex(calls[call_labels(pool).index("sell")]["data"][10:])
            self.sell_amount = (
                decode([EXACT_SINGLE], sell)[0][5]
                if pool.route == "v3"
                else int.from_bytes(sell[:32], "big")
            )
            self.receiver = "0x" + calls[-1]["data"][34:74]
        self.result = exchange["response"][0]["result"]

    def labels(self):
        return call_labels(self.pool, self.sell_amount is None)

    def calls(self, result=None):
        result = self.result if result is None else result
        return dict(
            zip(self.labels(), [call for block in result for call in block["calls"]])
        )

    def evaluate(self, result=None, confirmation=False):
        return evaluate_simulation(
            self.pool,
            self.token,
            self.amount,
            self.buyer,
            self.result if result is None else result,
            self.sell_amount,
            confirmation,
        )


def cow_runs():
    first, sized = simulations("cow")
    return Run(first, COW_PAIR, COW), Run(sized, COW_PAIR, COW)


def usdt_runs():
    v3_first, v3_sized, v2_first, v2_sized = simulations("usdt")
    return (
        Run(v3_first, USDT_V3, USDT),
        Run(v3_sized, USDT_V3, USDT),
        Run(v2_first, USDT_PAIR, USDT),
        Run(v2_sized, USDT_PAIR, USDT),
    )


def make_revert(call, data):
    call.update(
        status="0x0",
        logs=[],
        returnData="0x",
        error={"message": "execution reverted", "code": 3, "data": data},
    )


def failed_sell(run, data):
    """The run's reply with the sell reverted with `data`."""
    result = copy.deepcopy(run.result)
    calls = run.calls(result)
    make_revert(calls["sell"], data)
    # A reverted sell leaves the seller holding everything it bought, so the plain transfer that the
    # recorded (successful) sell left unfunded now succeeds.
    calls["after_sell"]["returnData"] = calls["delivered"]["returnData"]
    calls["transfer"].update(status="0x1", returnData=ZERO_WORD[:-1] + "1", error=None)
    return result


def as_confirmation(result):
    """A one block reply answered as a confirmation: its buy calls in one block, its sell calls in the
    next."""
    (block,) = copy.deepcopy(result)
    number = int(block["number"], 16)
    return [
        {"calls": block["calls"][:2], "number": hex(number)},
        {"calls": block["calls"][2:], "number": hex(number + 1)},
    ]


def _zero_sell_output(run, wbot_paid):
    """The sell's WBOT transfer to the seller removed and the pool's Swap event showing `wbot_paid`."""
    result = copy.deepcopy(run.result)
    sell = run.calls(result)["sell"]
    buyer_topic = _address_word(run.buyer)
    sell["logs"] = [
        log
        for log in sell["logs"]
        if not (log["address"].lower() == WBOT and log["topics"][2] == buyer_topic)
    ]
    swap_topic = (
        botchain_simulation.V3_SWAP_TOPIC
        if run.pool.route == "v3"
        else botchain_simulation.V2_SWAP_TOPIC
    )
    for log in sell["logs"]:
        if (
            log["address"].lower() == run.pool.address
            and log["topics"][0] == swap_topic
        ):
            data = bytes.fromhex(log["data"][2:])
            words = [data[i : i + 32] for i in range(0, len(data), 32)]
            if run.pool.route == "v3":
                words[1] = (-wbot_paid).to_bytes(32, "big", signed=True)
            else:
                words[3] = wbot_paid.to_bytes(32, "big")
            log["data"] = "0x" + b"".join(words).hex()
    return result


def _sell_taxed(run, percent):
    """The pool's V3 Swap event on the sell shows it received `percent`% less than the seller sent."""
    result = copy.deepcopy(run.result)
    for log in run.calls(result)["sell"]["logs"]:
        if log["address"].lower() == run.pool.address:
            data = bytes.fromhex(log["data"][2:])
            words = [data[i : i + 32] for i in range(0, len(data), 32)]
            words[0] = (run.sell_amount * (100 - percent) // 100).to_bytes(
                32, "big", signed=True
            )
            log["data"] = "0x" + b"".join(words).hex()
    return result


# --- the simulator against recorded and scripted RPC answers ------------------------------------


def cycling_addresses():
    """The fresh addresses the recordings drew, in turn."""
    return patch.object(
        botchain_simulation, "_fresh_address", side_effect=itertools.cycle(ADDRESSES)
    )


def run_addresses(*runs):
    """Each run's own buyer and receiver in turn; a ("confirm", run) adds PAYER as the third."""
    addresses = []
    for run in runs:
        if isinstance(run, tuple):
            addresses += [run[1].buyer, run[1].receiver, PAYER]
        else:
            addresses += [run.buyer, run.receiver]
    return patch.object(botchain_simulation, "_fresh_address", side_effect=addresses)


class Replay:
    """Stands in for BotChainSimulator._post: answers each request from the fixture's recorded exchanges
    in order, after checking it is the request recorded, and each eth_simulateV1 from `answers` when
    given (a reply's result list, an error row dict, or an exception to raise)."""

    def __init__(self, name, answers=None, delay=0.0):
        self.exchanges = [
            exchange
            for exchange in load(name)["exchanges"]
            if answers is None or exchange["calls"][0][0] != "eth_simulateV1"
        ]
        self.answers = None if answers is None else iter(answers)
        self.delay = delay
        self.calls = []

    async def __call__(self, session, calls, url=None, timeout=None):
        self.calls.append(calls)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.answers is not None and calls[0][0] == "eth_simulateV1":
            answer = next(self.answers)
            if isinstance(answer, BaseException):
                raise answer
            if isinstance(answer, dict):
                return [{"jsonrpc": "2.0", "id": 0, **answer}]
            return [{"jsonrpc": "2.0", "id": 0, "result": answer}]
        exchange = self.exchanges.pop(0)
        assert [list(call) for call in calls] == exchange["calls"]
        return exchange["response"]

    def simulate_requests(self):
        return [calls[0][1] for calls in self.calls if calls[0][0] == "eth_simulateV1"]


def simulator_for(post, **kwargs):
    simulator = BotChainSimulator(**kwargs)
    simulator._post = post
    return simulator


def two_trapped_pools():
    """USDT's two recorded pools, each refusing the sell in its sized run and in its confirmation."""
    v3_first, v3_sized, v2_first, v2_sized = usdt_runs()
    v3_trapped = failed_sell(v3_sized, error_string("STF"))
    v2_trapped = failed_sell(v2_sized, error_string(BDEX_REFUSED))
    answers = [
        v3_first.result,
        v3_trapped,
        as_confirmation(v3_trapped),
        v2_first.result,
        v2_trapped,
        as_confirmation(v2_trapped),
    ]
    order = [
        v3_first,
        v3_sized,
        ("confirm", v3_sized),
        v2_first,
        v2_sized,
        ("confirm", v2_sized),
    ]
    return answers, order


# --- constants and request shapes ----------------------------------------------------------------


def test_the_chain_contracts_and_limits():
    assert CHAIN_ID == 677
    assert RPC_URL == "https://rpc.botchain.ai"
    assert WBOT == "0xd5452816194a3784dba983426cce7c122f4abd30"
    assert V2_ROUTES == {
        "BDEX": (
            "0x117115f3b72c8d1989178089a67d0c26f8ee0aa3",
            "0x1414ed29fdfd322c3c0a830330ed982e2d629e76",
        )
    }
    assert V3_FACTORY == "0x1c51c173323ec11bb4e3c4fd2314c225dc4b5419"
    assert V3_ROUTER == "0x07032d47a1b9f8460cbee9dc17c1d3e438693929"
    assert V3_FEES == (500, 3000, 10_000)
    assert MAX_POOLS == 2
    assert RPC_TIMEOUT_SECONDS == 12
    assert BUY_CAP_WEI == 5 * 10**17
    assert MIN_POOL_DEPTH_WEI == 5 * 10**16


def test_the_v3_router_selectors_are_the_original_swaprouters():
    # The original SwapRouter's single hop structs: eight fields, a uint256 deadline after the recipient.
    assert keccak(text=f"exactInputSingle({EXACT_SINGLE})")[:4].hex() == "414bf389"
    assert keccak(text=f"exactOutputSingle({EXACT_SINGLE})")[:4].hex() == "db3e2198"


def test_the_swaprouter02_layout_is_not_the_one_used():
    seven_fields = "(address,address,uint24,address,uint256,uint256,uint160)"
    assert keccak(text=f"exactInputSingle({seven_fields})")[:4].hex() != "414bf389"
    _, v3_sized, _, _ = usdt_runs()
    assert (
        v3_sized.request["blockStateCalls"][0]["calls"][0]["data"][:10] == "0x414bf389"
    )


@pytest.mark.parametrize("index", [0, 1, 2, 3])
def test_every_recorded_usdt_request_is_the_one_the_simulator_builds(index):
    run = usdt_runs()[index]
    request = build_simulation_request(
        run.pool, run.token, run.amount, run.buyer, run.receiver, run.sell_amount
    )
    assert request == run.request
    assert run.block == hex(BASE_BLOCK)


@pytest.mark.parametrize("index", [0, 1])
def test_every_recorded_cow_request_is_the_one_the_simulator_builds(index):
    run = cow_runs()[index]
    request = build_simulation_request(
        run.pool, run.token, run.amount, run.buyer, run.receiver, run.sell_amount
    )
    assert request == run.request


def test_a_v3_buy_is_exact_input_with_native_value_and_a_max_deadline():
    v3_first, v3_sized, _, _ = usdt_runs()
    buy, _, _, sell, _, _ = v3_sized.request["blockStateCalls"][0]["calls"]
    assert buy["to"] == sell["to"] == V3_ROUTER
    assert len(buy["data"]) == len(sell["data"]) == 10 + 8 * 64
    assert decode([EXACT_SINGLE], bytes.fromhex(buy["data"][10:]))[0] == (
        WBOT,
        USDT,
        3000,
        v3_sized.buyer,
        2**256 - 1,
        v3_sized.amount,
        0,
        0,
    )
    assert int(buy["value"], 16) == v3_sized.amount == BUY_CAP_WEI
    # Every sell pays WBOT, as an ERC-20, to the seller.
    assert decode([EXACT_SINGLE], bytes.fromhex(sell["data"][10:]))[0] == (
        USDT,
        WBOT,
        3000,
        v3_sized.buyer,
        2**256 - 1,
        v3_sized.sell_amount,
        0,
        0,
    )
    assert "value" not in sell


def test_a_v2_buy_is_swap_exact_eth_for_tokens_and_the_sell_pays_wbot():
    _, sized = cow_runs()
    calls = sized.request["blockStateCalls"][0]["calls"]
    buy, sell = calls[0], calls[call_labels(COW_PAIR).index("sell")]
    assert buy["to"] == sell["to"] == V2_ROUTES["BDEX"][1]
    assert (
        buy["data"][:10]
        == "0x"
        + keccak(text="swapExactETHForTokens(uint256,address[],address,uint256)")[
            :4
        ].hex()
    )
    assert decode(
        ["uint256", "address[]", "address", "uint256"], bytes.fromhex(buy["data"][10:])
    ) == (0, (WBOT, COW), sized.buyer, 2**256 - 1)
    signature = "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)"
    assert sell["data"][:10] == "0x" + keccak(text=signature)[:4].hex()
    assert decode(
        ["uint256", "uint256", "address[]", "address", "uint256"],
        bytes.fromhex(sell["data"][10:]),
    ) == (sized.sell_amount, 0, (COW, WBOT), sized.buyer, 2**256 - 1)


def test_the_first_run_holds_only_the_buy_and_the_balance_it_delivered():
    first, _ = cow_runs()
    (block,) = first.request["blockStateCalls"]
    assert [call["to"] for call in block["calls"]] == [V2_ROUTES["BDEX"][1], COW]
    assert block["stateOverrides"] == {first.buyer: {"balance": hex(100 * 10**18)}}
    assert first.request["validation"] is False
    assert "traceTransfers" not in first.request


def test_the_confirmation_request_is_the_one_recorded_live():
    fixture = load("cow_confirmation")
    (exchange,) = fixture["exchanges"]
    request, block = exchange["calls"][0][1]
    pool = Pool("BDEX", fixture["pool"], None, fixture["depth"])
    built = build_simulation_request(
        pool,
        fixture["token"],
        buy_amount(fixture["depth"]),
        ADDRESSES[0],
        ADDRESSES[1],
        fixture["sell_amount"],
        (ADDRESSES[2], fixture["sell_time"]),
    )
    assert built == request
    assert block == hex(BASE_BLOCK)
    assert fixture["sell_time"] == BASE_TIME + CONFIRMATION_DELAY_SECONDS


def test_the_node_ran_the_confirmations_sell_block_an_hour_later():
    fixture = load("cow_confirmation")
    buy_block, sell_block = fixture["exchanges"][0]["response"][0]["result"]
    assert int(sell_block["number"], 16) == int(buy_block["number"], 16) + 1
    assert int(sell_block["timestamp"], 16) == BASE_TIME + CONFIRMATION_DELAY_SECONDS
    # The confirmation, which had no trap to confirm, measured the same taxes as the plain run.
    assert (fixture["outcome"]["buy_tax"], fixture["outcome"]["sell_tax"]) == (1.0, 1.0)


def test_a_confirmation_has_a_separate_address_pay_for_the_buy_and_sells_an_hour_later():
    _, sized = cow_runs()
    args = (
        sized.pool,
        sized.token,
        sized.amount,
        sized.buyer,
        sized.receiver,
        sized.sell_amount,
    )
    (plain,) = build_simulation_request(*args)["blockStateCalls"]
    buy, sell = build_simulation_request(*args, (PAYER, BASE_TIME + 3600))[
        "blockStateCalls"
    ]
    assert buy == {
        "stateOverrides": {
            **plain["stateOverrides"],
            PAYER: {"balance": hex(100 * 10**18)},
        },
        "calls": [{**plain["calls"][0], "from": PAYER}, plain["calls"][1]],
    }
    assert sell == {
        "blockOverrides": {"time": hex(BASE_TIME + 3600)},
        "calls": plain["calls"][2:],
    }


# --- sizing ----------------------------------------------------------------------------------------


def test_the_cow_buy_is_sized_from_the_pairs_wbot_depth_not_the_cap():
    # COW's pair 0x27bf...6542 holds 7.646 WBOT, so the buy spends a fiftieth of it: 0.153 BOT, not 0.5.
    depth_batch = load("cow")["exchanges"][1]
    reserve0, reserve1, _ = decode(
        ["uint112", "uint112", "uint32"],
        bytes.fromhex(depth_batch["response"][0]["result"][2:]),
    )
    assert COW < WBOT and reserve1 == 7_646_347_941_360_187_793
    first, sized = cow_runs()
    assert first.amount == sized.amount == buy_amount(reserve1) == reserve1 // 50
    assert first.amount == 152_926_958_827_203_755


@pytest.mark.parametrize(
    "depth,amount",
    [
        (MIN_POOL_DEPTH_WEI, MIN_POOL_DEPTH_WEI // 50),
        (25 * 10**18, BUY_CAP_WEI),
        (246 * 10**18, BUY_CAP_WEI),
        (24 * 10**18, 24 * 10**18 // 50),
    ],
)
def test_the_buy_spends_a_fiftieth_of_the_depth_up_to_half_a_bot(depth, amount):
    assert buy_amount(depth) == amount


def test_both_usdt_pools_are_deep_enough_for_the_full_half_bot():
    for run in usdt_runs():
        assert run.amount == BUY_CAP_WEI


@pytest.mark.asyncio
async def test_the_recorded_cow_scan_measures_a_one_percent_tax_both_ways():
    replay = Replay("cow")
    with cycling_addresses():
        result = await simulator_for(replay).simulate(COW)
    assert {field: result[field] for field in FIELDS} == {
        "is_honeypot": False,
        "buy_tax": 1.0,
        "sell_tax": 1.0,
        "can_buy": True,
        "can_sell": True,
    }
    assert result["simulation_block"] == BASE_BLOCK
    assert not replay.exchanges
    recorded = load("cow")["result"]
    assert {key: result[key] for key in recorded} == recorded


@pytest.mark.asyncio
async def test_the_recorded_usdt_scan_is_untaxed_on_both_routes():
    replay = Replay("usdt")
    with cycling_addresses():
        result = await simulator_for(replay).simulate(USDT)
    assert {field: result[field] for field in FIELDS} == {
        "is_honeypot": False,
        "buy_tax": 0.0,
        "sell_tax": 0.0,
        "can_buy": True,
        "can_sell": True,
    }
    assert (
        "v3 pool 0x64f418471a1a7932a190e10da5a8551db5abec05 at block 27938432: buy and sell succeeded"
        in result["reason"]
    )
    assert (
        "BDEX pool 0xdc7547f3cea82c6af7fd420656ce532c6da9b98d at block 27938432: buy and sell succeeded"
        in result["reason"]
    )
    assert not replay.exchanges


@pytest.mark.asyncio
async def test_pools_under_the_minimum_depth_are_skipped_with_a_note():
    replay = Replay("usdt")
    with cycling_addresses():
        result = await simulator_for(replay).simulate(USDT)
    assert (
        "v3 pool 0x050a7c2ec050a1d1402053a40a2eb0f6275ed70a holds 1027388415374721 wei WBOT, "
        "under the 50000000000000000 wei minimum depth; not simulated"
    ) in result["reason"]
    assert (
        "v3 pool 0x5cf483e886a83de87bd31acb24d3f346454e49eb holds 9 wei WBOT"
        in result["reason"]
    )
    # The deeper pool runs first: the V3 3000 pool, then the V2 pair.
    targets = [
        request[0]["blockStateCalls"][0]["calls"][0]["to"]
        for request in replay.simulate_requests()
    ]
    assert targets == [V3_ROUTER, V3_ROUTER, V2_ROUTES["BDEX"][1], V2_ROUTES["BDEX"][1]]


@pytest.mark.asyncio
async def test_the_newest_vanity_pair_with_no_reserves_is_not_simulated():
    replay = Replay("lk2e")
    result = await simulator_for(replay).simulate(
        "0x04bbf9ec920e8996bb96e5c451f621e5df6d9999"
    )
    assert all(result[field] is None for field in FIELDS)
    assert result["reason"] == (
        "BDEX pool 0xc47bf4f4f34ee9cb19e0bd3c39ad981e4b745221 holds no WBOT; "
        "No supported pool with enough WBOT depth"
    )
    assert not replay.simulate_requests()
    assert "rpc_failed" not in result and "simulation_failed" not in result


@pytest.mark.asyncio
async def test_a_token_with_no_bdex_wbot_pool_is_unknown():
    replay = Replay("no_pool")
    result = await simulator_for(replay).simulate(
        "0x68caea9104419203cf8b8f0b222e75709b97bfc6"
    )
    assert all(result[field] is None for field in FIELDS)
    assert (
        result["reason"]
        == "No supported pool found (BDEX V3 or BDEX V2, paired with WBOT)"
    )
    # Only the discovery batch: no depth batch and no simulation.
    assert len(replay.calls) == 1
    assert "rpc_failed" not in result and "simulation_failed" not in result


def test_the_discovery_batch_is_total_supply_three_get_pools_and_one_get_pair():
    (calls) = load("cow")["exchanges"][0]["calls"]
    assert len(calls) == 5
    targets = [params[0]["to"] for _, params in calls]
    selectors = [params[0]["data"][:10] for _, params in calls]
    assert targets == [COW, V3_FACTORY, V3_FACTORY, V3_FACTORY, V2_ROUTES["BDEX"][0]]
    get_pool = "0x" + keccak(text="getPool(address,address,uint24)")[:4].hex()
    get_pair = "0x" + keccak(text="getPair(address,address)")[:4].hex()
    assert selectors == ["0x18160ddd", get_pool, get_pool, get_pool, get_pair]
    fees = [int(params[0]["data"][-64:], 16) for _, params in calls[1:4]]
    assert fees == [500, 3000, 10_000]


def _discovery_rpc(token, pools, depths):
    """A _post answering discovery from tables: `pools` maps (factory, fee) to an address, `depths` maps
    a V3 pool to its WBOT balance and a pair to its (reserve0, reserve1)."""
    calls_seen = []

    async def post(session, calls, url=None, timeout=None):
        calls_seen.append(calls)
        rows = []
        for index, (method, params) in enumerate(calls):
            if method == "eth_getBlockByNumber":
                result = {"number": hex(BASE_BLOCK), "timestamp": hex(BASE_TIME)}
            else:
                to, data = params[0]["to"], params[0]["data"]
                if data == "0x18160ddd":
                    result = _word(10**24)
                elif to == V3_FACTORY:
                    result = _address_word(
                        pools.get((to, int(data[-64:], 16)), "0x" + "0" * 40)
                    )
                elif to == V2_ROUTES["BDEX"][0]:
                    result = _address_word(pools.get((to, None), "0x" + "0" * 40))
                elif to == WBOT:
                    result = _word(depths["0x" + data[-40:]])
                else:
                    reserves = depths[to]
                    result = (
                        "0x"
                        + encode(["uint112", "uint112", "uint32"], [*reserves, 0]).hex()
                    )
            rows.append({"jsonrpc": "2.0", "id": index, "result": result})
        return rows

    return post, calls_seen


@pytest.mark.asyncio
async def test_discovery_keeps_the_two_pools_holding_the_most_wbot_and_reads_a_pairs_wbot_side():
    # A token above WBOT sorts second, so WBOT is the pair's token0 and reserve0 its depth.
    token = "0x" + "f" * 40
    pair = "0x" + "a" * 40
    pools = {(V3_FACTORY, fee): "0x" + f"{fee:040x}" for fee in V3_FEES}
    pools[(V2_ROUTES["BDEX"][0], None)] = pair
    depths = {
        "0x" + f"{500:040x}": 2 * 10**18,
        "0x" + f"{3000:040x}": 3 * 10**18,
        "0x" + f"{10_000:040x}": 0,
        pair: (5 * 10**18, 10**30),
    }
    post, _ = _discovery_rpc(token, pools, depths)
    found, notes, source = await simulator_for(post)._discover(None, token)
    assert [(pool.route, pool.address, pool.liquidity) for pool in found] == [
        ("BDEX", pair, 5 * 10**18),
        ("v3", "0x" + f"{3000:040x}", 3 * 10**18),
    ]
    assert source == (BASE_BLOCK, BASE_TIME)
    assert f"v3 pool {'0x' + f'{10_000:040x}'} holds no WBOT" in notes
    assert (
        f"v3 pool {'0x' + f'{500:040x}'} not simulated (cap of {MAX_POOLS} pools)"
        in notes
    )


@pytest.mark.asyncio
async def test_wbot_itself_is_not_simulated():
    result = await BotChainSimulator().simulate(WBOT)
    assert all(result[field] is None for field in FIELDS)
    assert "WBOT is the asset" in result["reason"]


@pytest.mark.asyncio
async def test_an_invalid_address_is_not_simulated():
    result = await BotChainSimulator().simulate("0x1234")
    assert result["reason"] == "Invalid token address"


# --- verdicts on the recorded runs ---------------------------------------------------------------


def test_the_cow_first_run_measures_the_buy_tax_and_asks_for_a_sized_sell():
    first, sized = cow_runs()
    outcome = first.evaluate()
    assert (outcome["can_buy"], outcome["buy_tax"], outcome["can_sell"]) == (
        True,
        1.0,
        None,
    )
    assert outcome["retry_sell_amount"] == sized.sell_amount
    payout = -_pool_swap(COW_PAIR, COW, first.calls()["buy"]["logs"])[0]
    assert outcome["reason"] == (
        f"bought {sized.sell_amount} token units for {first.amount} wei WBOT (the pool paid out "
        f"{payout}); the sell was not simulated in this run"
    )


def test_the_cow_sized_run_measures_a_one_percent_tax_both_ways():
    _, sized = cow_runs()
    outcome = sized.evaluate()
    assert (
        outcome["buy_tax"],
        outcome["sell_tax"],
        outcome["can_sell"],
        outcome["is_honeypot"],
    ) == (1.0, 1.0, True, False)
    assert outcome["simulation_failed"] is False


@pytest.mark.parametrize("index", [1, 3])
def test_usdt_sells_untaxed_through_both_routes(index):
    outcome = usdt_runs()[index].evaluate()
    assert {field: outcome[field] for field in FIELDS} == {
        "is_honeypot": False,
        "buy_tax": 0.0,
        "sell_tax": 0.0,
        "can_buy": True,
        "can_sell": True,
    }


def test_a_sized_run_that_delivers_a_different_balance_is_not_sizeable():
    _, sized = cow_runs()
    outcome = evaluate_simulation(
        sized.pool,
        sized.token,
        sized.amount,
        sized.buyer,
        sized.result,
        sized.sell_amount + 1,
    )
    assert (outcome["can_buy"], outcome["can_sell"], outcome["retry_sell_amount"]) == (
        True,
        None,
        None,
    )
    assert outcome["reason"].startswith("sell not sizeable in one request")


# --- traps and Unknown --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "index,message",
    [(1, "STF"), (3, BDEX_REFUSED), (3, BDEX_NO_INPUT)],
)
def test_a_token_refusing_the_sell_is_a_honeypot(index, message):
    run = usdt_runs()[index]
    outcome = run.evaluate(failed_sell(run, error_string(message)))
    assert (outcome["is_honeypot"], outcome["can_sell"], outcome["can_buy"]) == (
        True,
        False,
        True,
    )
    assert outcome["reason"].startswith("sell reverted: ")
    assert (
        "a plain transfer of half the tokens to a fresh address succeeded"
        in outcome["reason"]
    )


def test_a_v3_pool_refusing_an_underpaid_sell_is_not_a_honeypot():
    run = usdt_runs()[1]
    outcome = run.evaluate(failed_sell(run, error_string("IIA")))
    assert (outcome["is_honeypot"], outcome["can_sell"], outcome["sell_tax"]) == (
        None,
        None,
        None,
    )
    assert outcome["simulation_failed"] is False and outcome["trap"] is None
    assert "fee-on-transfer token sold into a V3 pool" in outcome["reason"]


@pytest.mark.parametrize(
    "index,data",
    [
        # Uniswap's own strings are not what BDEX's Router02 reverts with.
        (3, error_string("TransferHelper: TRANSFER_FROM_FAILED")),
        (3, error_string("UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT")),
        (3, error_string("BotDexV2: INSUFFICIENT_OUTPUT_AMOUNT")),
        (1, error_string("Too little received")),
        (1, "0x"),
        # Each router's refusal string counts only on its own route.
        (1, error_string(BDEX_REFUSED)),
        (1, error_string(BDEX_NO_INPUT)),
        (3, error_string("STF")),
        (3, error_string("IIA")),
    ],
)
def test_an_unattributed_sell_failure_stays_unknown(index, data):
    run = usdt_runs()[index]
    outcome = run.evaluate(failed_sell(run, data))
    assert (outcome["is_honeypot"], outcome["can_sell"]) == (None, None)
    assert "unattributed" in outcome["reason"]


def test_a_reverted_buy_leaves_every_verdict_unknown():
    _, sized = cow_runs()
    result = copy.deepcopy(sized.result)
    make_revert(sized.calls(result)["buy"], error_string("BotDexV2: K"))
    outcome = sized.evaluate(result)
    assert all(outcome[field] is None for field in FIELDS)
    assert outcome["reason"] == 'buy reverted: Error("BotDexV2: K")'


def test_a_sell_paying_nothing_after_a_paid_buy_is_a_honeypot():
    for run in (usdt_runs()[1], usdt_runs()[3]):
        outcome = run.evaluate(_zero_sell_output(run, 0))
        assert (outcome["is_honeypot"], outcome["can_sell"], outcome["trap"]) == (
            True,
            False,
            "zero output",
        )


def test_a_pool_paying_wbot_the_trace_never_sent_is_malformed():
    run = usdt_runs()[1]
    outcome = run.evaluate(_zero_sell_output(run, 10**15))
    assert outcome["simulation_failed"] is True
    assert outcome["reason"] == "Malformed eth_simulateV1 sell logs"


def test_a_zero_sell_after_a_dust_buy_stays_unknown():
    run = usdt_runs()[1]
    result = _zero_sell_output(run, 0)
    for log in run.calls(result)["buy"]["logs"]:
        if log["address"].lower() == run.pool.address:
            data = bytes.fromhex(log["data"][2:])
            words = [data[i : i + 32] for i in range(0, len(data), 32)]
            words[1] = (MIN_TRAP_COST_WEI - 1).to_bytes(32, "big", signed=True)
            log["data"] = "0x" + b"".join(words).hex()
    outcome = evaluate_simulation(
        run.pool, run.token, MIN_TRAP_COST_WEI - 1, run.buyer, result, run.sell_amount
    )
    assert (outcome["is_honeypot"], outcome["can_sell"]) == (None, None)
    assert "too little to rule out rounding" in outcome["reason"]


def test_a_buy_the_pool_only_partly_filled_is_too_illiquid_to_size():
    run = usdt_runs()[1]
    outcome = evaluate_simulation(
        run.pool, run.token, run.amount - 1, run.buyer, run.result, run.sell_amount
    )
    assert outcome["simulation_failed"] is True
    outcome = evaluate_simulation(
        run.pool, run.token, run.amount + 1, run.buyer, run.result, run.sell_amount
    )
    assert all(outcome[field] is None for field in FIELDS)
    assert "too illiquid to size a buy" in outcome["reason"]


def test_a_buy_that_delivered_nothing_cannot_buy():
    first, _ = cow_runs()
    result = copy.deepcopy(first.result)
    first.calls(result)["delivered"]["returnData"] = ZERO_WORD
    outcome = first.evaluate(result)
    assert outcome["can_buy"] is False
    assert outcome["reason"] == "buy succeeded but delivered no tokens"


def test_a_pool_swap_reads_the_tokens_side_by_address_order():
    pool = Pool("BDEX", "0x" + "a" * 40)
    swap = {
        "address": pool.address,
        "topics": [botchain_simulation.V2_SWAP_TOPIC, ZERO_WORD, ZERO_WORD],
        "data": "0x" + encode(["uint256"] * 4, [7, 0, 0, 11]).hex(),
    }
    # amount0In 7, amount1Out 11: the pool received 7 of token0 and paid 11 of token1.
    assert _pool_swap(pool, "0x" + "f" * 40, [swap]) == (-11, 7)
    assert _pool_swap(pool, "0x" + "1" * 40, [swap]) == (7, -11)


# --- the confirmation run and the cleared trap rule -------------------------------------------------


def test_a_confirmation_that_could_not_run_keeps_the_first_runs_trap():
    run = usdt_runs()[3]
    first = run.evaluate(failed_sell(run, error_string(BDEX_REFUSED)))
    confirmation = {
        **first,
        "rpc_failed": True,
        "trap": None,
        "block": None,
        "reason": "boom",
    }
    outcome = _confirm_trap(first, confirmation)
    assert (outcome["is_honeypot"], outcome["can_sell"], outcome["trap"]) == (
        True,
        False,
        first["trap"],
    )
    assert "could not run (boom)" in outcome["reason"]


@pytest.mark.asyncio
async def test_a_trap_reproduced_by_its_confirmation_is_a_honeypot():
    first, sized = cow_runs()
    trapped = failed_sell(sized, error_string(BDEX_REFUSED))
    replay = Replay("cow", [first.result, trapped, as_confirmation(trapped)])
    with run_addresses(first, sized, ("confirm", sized)):
        result = await simulator_for(replay).simulate(COW)
    assert (result["is_honeypot"], result["can_sell"], result["can_buy"]) == (
        True,
        False,
        True,
    )
    assert (
        "reproduced by a re-run whose buy a separate address paid" in result["reason"]
    )
    confirmation = replay.simulate_requests()[2][0]
    assert confirmation["blockStateCalls"][1]["blockOverrides"] == {
        "time": hex(BASE_TIME + CONFIRMATION_DELAY_SECONDS)
    }
    assert confirmation["blockStateCalls"][0]["calls"][0]["from"] == PAYER


@pytest.mark.asyncio
async def test_a_trap_its_confirmation_did_not_reproduce_is_unknown():
    first, sized = cow_runs()
    trapped = failed_sell(sized, error_string(BDEX_REFUSED))
    replay = Replay("cow", [first.result, trapped, as_confirmation(sized.result)])
    with run_addresses(first, sized, ("confirm", sized)):
        result = await simulator_for(replay).simulate(COW)
    assert (result["is_honeypot"], result["can_sell"]) == (None, None)
    assert result["simulation_failed"] is True
    assert "the trap did not reproduce" in result["reason"]


@pytest.mark.asyncio
async def test_a_confirmation_the_rpc_could_not_run_keeps_the_trap():
    first, sized = cow_runs()
    trapped = failed_sell(sized, error_string(BDEX_REFUSED))
    crashed = {"error": {"code": -32603, "message": "internal error"}}
    replay = Replay("cow", [first.result, trapped, crashed])
    with run_addresses(first, sized, ("confirm", sized)):
        result = await simulator_for(replay).simulate(COW)
    assert (result["is_honeypot"], result["can_sell"]) == (True, False)
    assert (
        "could not run (eth_simulateV1 failed (JSON-RPC error -32603))"
        in result["reason"]
    )


@pytest.mark.asyncio
async def test_a_shallower_pool_refusing_the_sell_leaves_the_token_unknown_when_the_deepest_sold():
    v3_first, v3_sized, v2_first, v2_sized = usdt_runs()
    trapped = failed_sell(v2_sized, error_string(BDEX_REFUSED))
    replay = Replay(
        "usdt",
        [
            v3_first.result,
            v3_sized.result,
            v2_first.result,
            trapped,
            as_confirmation(trapped),
        ],
    )
    with run_addresses(v3_first, v3_sized, v2_first, v2_sized, ("confirm", v2_sized)):
        result = await simulator_for(replay).simulate(USDT)
    assert (result["is_honeypot"], result["can_sell"]) == (None, None)
    assert result["simulation_failed"] is True
    assert (
        f"not counted as a trap because the pool holding the most WBOT, {USDT_V3.address}, sold "
        "(sell tax 0%), so sellability is left unknown"
    ) in result["reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize("percent,verdict", [(50, (None, None)), (51, (True, False))])
async def test_only_a_deepest_pool_selling_at_no_more_than_half_tax_clears_another_pools_trap(
    percent, verdict
):
    v3_first, v3_sized, v2_first, v2_sized = usdt_runs()
    assert v3_sized.evaluate(_sell_taxed(v3_sized, percent))["sell_tax"] == float(
        percent
    )
    trapped = failed_sell(v2_sized, error_string(BDEX_REFUSED))
    replay = Replay(
        "usdt",
        [
            v3_first.result,
            _sell_taxed(v3_sized, percent),
            v2_first.result,
            trapped,
            as_confirmation(trapped),
        ],
    )
    with run_addresses(v3_first, v3_sized, v2_first, v2_sized, ("confirm", v2_sized)):
        result = await simulator_for(replay).simulate(USDT)
    assert (result["is_honeypot"], result["can_sell"]) == verdict


@pytest.mark.asyncio
async def test_a_trapped_deepest_pool_is_not_cleared_by_a_shallower_clean_one():
    v3_first, v3_sized, v2_first, v2_sized = usdt_runs()
    trapped = failed_sell(v3_sized, error_string("STF"))
    replay = Replay(
        "usdt",
        [
            v3_first.result,
            trapped,
            as_confirmation(trapped),
            v2_first.result,
            v2_sized.result,
        ],
    )
    with run_addresses(v3_first, v3_sized, ("confirm", v3_sized), v2_first, v2_sized):
        result = await simulator_for(replay).simulate(USDT)
    assert (result["is_honeypot"], result["can_sell"]) == (True, False)
    assert "simulation_failed" not in result


@pytest.mark.asyncio
async def test_a_v3_iia_sell_beside_a_clean_pair_never_reads_honeypot():
    v3_first, v3_sized, v2_first, v2_sized = usdt_runs()
    underpaid = failed_sell(v3_sized, error_string("IIA"))
    replay = Replay(
        "usdt", [v3_first.result, underpaid, v2_first.result, v2_sized.result]
    )
    with run_addresses(v3_first, v3_sized, v2_first, v2_sized):
        result = await simulator_for(replay).simulate(USDT)
    # No confirmation ran: IIA is not a trap. The pair sold, so the token is not a honeypot, and the
    # V3 pool's sell is left unmeasured.
    assert len(replay.simulate_requests()) == 4
    assert result["is_honeypot"] is False and result["can_sell"] is True


# --- RPC failures: Unknown, with a note naming them, and no retry ----------------------------------


@pytest.mark.asyncio
async def test_a_discovery_timeout_is_unknown_and_not_retried():
    post = AsyncMock(side_effect=asyncio.TimeoutError())
    result = await simulator_for(post).simulate(COW)
    assert all(result[field] is None for field in FIELDS)
    assert result["rpc_failed"] is True
    assert result["reason"] == f"RPC request timed out after {RPC_TIMEOUT_SECONDS} s"
    assert post.await_count == 1


@pytest.mark.asyncio
async def test_a_simulation_timeout_is_unknown_and_not_retried():
    first, sized = cow_runs()
    replay = Replay("cow", [asyncio.TimeoutError()])
    with run_addresses(first):
        result = await simulator_for(replay).simulate(COW)
    assert all(result[field] is None for field in FIELDS)
    assert result["rpc_failed"] is True
    assert "RPC request timed out after 12 s" in result["reason"]
    assert len(replay.simulate_requests()) == 1


@pytest.mark.asyncio
async def test_a_sized_follow_up_the_rpc_could_not_run_keeps_the_buy_evidence():
    first, sized = cow_runs()
    replay = Replay("cow", [first.result, asyncio.TimeoutError()])
    with run_addresses(first, sized):
        result = await simulator_for(replay).simulate(COW)
    assert (
        result["can_buy"],
        result["buy_tax"],
        result["can_sell"],
        result["is_honeypot"],
    ) == (
        True,
        1.0,
        None,
        None,
    )
    assert result["rpc_failed"] is True
    assert "sized follow-up: RPC request timed out after 12 s" in result["reason"]


@pytest.mark.asyncio
async def test_an_unsupported_simulation_method_is_unknown():
    first, _ = cow_runs()
    replay = Replay(
        "cow",
        [
            {
                "error": {
                    "code": -32601,
                    "message": "the method eth_simulateV1 does not exist",
                }
            }
        ],
    )
    with run_addresses(first):
        result = await simulator_for(replay).simulate(COW)
    assert all(result[field] is None for field in FIELDS)
    assert "eth_simulateV1 unsupported by the RPC" in result["reason"]


@pytest.mark.asyncio
async def test_a_node_error_row_in_discovery_is_unknown_and_not_retried():
    exchange = load("cow")["exchanges"][0]
    rows = copy.deepcopy(exchange["response"])
    rows[4] = {
        "jsonrpc": "2.0",
        "id": 4,
        "error": {"code": -32000, "message": "request timed out"},
    }
    post = AsyncMock(return_value=rows)
    result = await simulator_for(post).simulate(COW)
    assert result["rpc_failed"] is True
    assert result["reason"] == "BDEX pair lookup failed (JSON-RPC error -32000)"
    assert post.await_count == 1


def _session(*responses):
    """A session whose post() answers each response (status, payload) in turn, or raises it."""
    session = MagicMock()
    contexts = []
    for item in responses:
        if isinstance(item, BaseException):
            contexts.append(item)
            continue
        status, payload = item
        response = MagicMock(status=status)
        response.json = AsyncMock(return_value=payload)
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=response)
        context.__aexit__ = AsyncMock(return_value=False)
        contexts.append(context)
    session.post.side_effect = contexts
    return session


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,payload,reason",
    [
        (429, None, "RPC rate limited (HTTP 429)"),
        (
            200,
            {
                "jsonrpc": "2.0",
                "id": 0,
                "error": {"code": -32005, "message": "limit exceeded"},
            },
            "RPC rate limited (JSON-RPC rate limit error)",
        ),
        (503, None, "RPC HTTP 503"),
        (
            200,
            {"jsonrpc": "2.0", "id": True, "result": "0x1"},
            "Malformed RPC response",
        ),
    ],
)
async def test_a_rate_limit_or_a_bad_answer_is_unknown_after_one_request(
    status, payload, reason
):
    session = _session((status, payload))
    with pytest.raises(SimulationUnavailable) as raised:
        await BotChainSimulator()._request(session, [("eth_blockNumber", [])])
    assert raised.value.reason == reason
    assert session.post.call_count == 1


@pytest.mark.asyncio
async def test_a_connection_reset_is_asked_once_more():
    ok = (200, {"jsonrpc": "2.0", "id": 0, "result": "0x1"})
    session = _session(aiohttp.ServerDisconnectedError(), ok)
    rows = await BotChainSimulator()._request(session, [("eth_blockNumber", [])])
    assert rows == [{"jsonrpc": "2.0", "id": 0, "result": "0x1"}]
    assert session.post.call_count == 2


@pytest.mark.asyncio
async def test_a_second_connection_reset_is_not_retried():
    session = _session(
        aiohttp.ServerDisconnectedError(), aiohttp.ServerDisconnectedError()
    )
    with pytest.raises(aiohttp.ServerDisconnectedError):
        await BotChainSimulator()._request(session, [("eth_blockNumber", [])])
    assert session.post.call_count == 2


@pytest.mark.asyncio
async def test_a_connection_that_never_opened_is_not_retried():
    error = aiohttp.ClientConnectorError(MagicMock(), OSError(111, "refused"))
    session = _session(error)
    with pytest.raises(aiohttp.ClientConnectorError):
        await BotChainSimulator()._request(session, [("eth_blockNumber", [])])
    assert session.post.call_count == 1


@pytest.mark.asyncio
async def test_a_reset_twice_leaves_the_scan_unknown():
    post = AsyncMock(side_effect=aiohttp.ServerDisconnectedError())
    result = await simulator_for(post).simulate(COW)
    assert all(result[field] is None for field in FIELDS)
    assert result["rpc_failed"] is True
    assert result["reason"] == "Simulation RPC request failed (ServerDisconnectedError)"
    assert post.await_count == 2


@pytest.mark.asyncio
async def test_every_request_gives_up_after_twelve_seconds():
    captured = {}

    class Session:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    with patch.object(botchain_simulation.aiohttp, "ClientSession", Session):
        await simulator_for(Replay("no_pool")).simulate(
            "0x68caea9104419203cf8b8f0b222e75709b97bfc6"
        )
    assert captured["timeout"].total == RPC_TIMEOUT_SECONDS == 12


# --- the time budget and the lane ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_two_pools_with_a_trap_in_each_finish_under_twenty_seconds_at_two_seconds_a_call():
    answers, order = two_trapped_pools()
    replay = Replay("usdt", answers, delay=2.2)
    started = time.monotonic()
    with run_addresses(*order):
        result = await simulator_for(replay).simulate(USDT)
    elapsed = time.monotonic() - started
    assert (result["is_honeypot"], result["can_sell"]) == (True, False)
    # Discovery, the depth batch with the header, and per pool a first run, a sized run and a
    # confirmation: eight requests, none retried.
    assert len(replay.calls) == 8
    assert elapsed < 20


@pytest.mark.asyncio
async def test_one_simulation_holds_the_lane_at_a_time():
    simulator = BotChainSimulator()
    active, peak = 0, 0

    async def run(token):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return botchain_simulation.aggregate_outcomes([], ["No supported pool found"])

    simulator._run = run
    await asyncio.gather(*(simulator.simulate("0x" + f"{i:040x}") for i in range(1, 5)))
    assert peak == 1


@pytest.mark.asyncio
async def test_a_user_joining_a_background_simulation_promotes_it():
    simulator = BotChainSimulator()
    release = asyncio.Event()

    async def run(token):
        await release.wait()
        return botchain_simulation.aggregate_outcomes([], ["No supported pool found"])

    simulator._run = run
    token = "0x" + "1" * 40
    background = botchain_simulation.BACKGROUND.set(True)
    first = asyncio.create_task(simulator.simulate(token))
    await asyncio.sleep(0)
    botchain_simulation.BACKGROUND.reset(background)
    second = asyncio.create_task(simulator.simulate(token))
    await asyncio.sleep(0)
    assert token in simulator._promoted
    release.set()
    assert await first == await second


# --- the admission cap ----------------------------------------------------------------------------


def distinct_tokens(count):
    return ["0x" + f"{i:040x}" for i in range(1, count + 1)]


def held_simulator(tokens):
    """A simulator whose run for each token waits until that token's event is set."""
    simulator = BotChainSimulator()
    releases = {token: asyncio.Event() for token in tokens}
    started = []

    async def run(token):
        started.append(token)
        await releases[token].wait()
        return botchain_simulation.aggregate_outcomes([], ["No supported pool found"])

    simulator._run = run
    return simulator, releases, started


@pytest.mark.asyncio
async def test_a_new_token_at_the_cap_is_unknown_without_a_task_or_an_rpc_call(monkeypatch):
    ledger = UnknownLedger()
    monkeypatch.setattr("services.botchain_simulation.unknown_ledger", ledger)
    *admitted, refused = distinct_tokens(MAX_SIMULATIONS + 1)
    simulator, releases, started = held_simulator(admitted)
    callers = [asyncio.create_task(simulator.simulate(token)) for token in admitted]
    await asyncio.sleep(0)
    with (
        patch.object(
            botchain_simulation.asyncio, "create_task", wraps=asyncio.create_task
        ) as create_task,
        patch.object(botchain_simulation.aiohttp, "ClientSession") as session,
    ):
        result = await simulator.simulate(refused)
    create_task.assert_not_called()
    session.assert_not_called()
    # A refusal is no answer from the provider, nor a failure of it.
    counts = ledger.for_chain(CHAIN_ID)[botchain_simulation.SIMULATION_PROVIDER]
    assert (counts["answered"], counts["unknown"], counts["failed"]) == (0, 1, 0)
    assert refused not in started
    assert len(simulator._inflight) == MAX_SIMULATIONS
    assert all(result[field] is None for field in FIELDS)
    assert result["rpc_failed"] is True
    assert result["reason"] == (
        f"Simulation not run: {MAX_SIMULATIONS} simulations already in progress"
    )
    assert refused not in simulator._cache
    for release in releases.values():
        release.set()
    await asyncio.gather(*callers)


@pytest.mark.asyncio
async def test_the_same_token_at_the_cap_joins_its_simulation():
    tokens = distinct_tokens(MAX_SIMULATIONS)
    simulator, releases, started = held_simulator(tokens)
    callers = [asyncio.create_task(simulator.simulate(token)) for token in tokens]
    await asyncio.sleep(0)
    joined = asyncio.create_task(simulator.simulate(tokens[0]))
    await asyncio.sleep(0)
    assert len(simulator._inflight) == MAX_SIMULATIONS
    for release in releases.values():
        release.set()
    results = await asyncio.gather(*callers)
    assert await joined is results[0]
    assert "not run" not in results[0]["reason"]
    assert started.count(tokens[0]) == 1


@pytest.mark.asyncio
async def test_a_new_token_is_admitted_again_once_a_simulation_finishes():
    *tokens, later = distinct_tokens(MAX_SIMULATIONS + 1)
    simulator, releases, started = held_simulator([*tokens, later])
    callers = [asyncio.create_task(simulator.simulate(token)) for token in tokens]
    await asyncio.sleep(0)
    assert (await simulator.simulate(later))["rpc_failed"] is True
    releases[tokens[0]].set()
    await callers[0]
    assert len(simulator._inflight) == MAX_SIMULATIONS - 1
    admitted = asyncio.create_task(simulator.simulate(later))
    await asyncio.sleep(0)
    assert len(simulator._inflight) == MAX_SIMULATIONS
    for release in releases.values():
        release.set()
    await asyncio.gather(*callers)
    result = await admitted
    assert later in started
    assert result["reason"] == "No supported pool found"
    assert "rpc_failed" not in result
    assert simulator._inflight == {}


@pytest.mark.asyncio
async def test_the_count_returns_to_zero_after_simulations_raise():
    simulator = BotChainSimulator()

    async def run(token):
        raise RuntimeError("boom")

    simulator._run = run
    tokens = distinct_tokens(MAX_SIMULATIONS + 1)
    results = await asyncio.gather(
        *(simulator.simulate(token) for token in tokens[:-1])
    )
    assert all(result["rpc_failed"] is True for result in results)
    assert simulator._inflight == {}
    result = await simulator.simulate(tokens[-1])
    assert result["reason"] == "Simulation RPC request failed (RuntimeError)"


@pytest.mark.asyncio
async def test_the_count_returns_to_zero_after_simulations_are_cancelled():
    *tokens, later = distinct_tokens(MAX_SIMULATIONS + 1)
    simulator, releases, started = held_simulator([*tokens, later])
    callers = [asyncio.create_task(simulator.simulate(token)) for token in tokens]
    # Let every simulation start: one cancelled before its first step never runs its finally.
    while not started:
        await asyncio.sleep(0)
    for task in list(simulator._inflight.values()):
        task.cancel()
    outcomes = await asyncio.gather(*callers, return_exceptions=True)
    assert all(isinstance(outcome, asyncio.CancelledError) for outcome in outcomes)
    assert simulator._inflight == {}
    admitted = asyncio.create_task(simulator.simulate(later))
    await asyncio.sleep(0)
    assert len(simulator._inflight) == 1
    releases[later].set()
    assert (await admitted)["reason"] == "No supported pool found"
    assert simulator._inflight == {}


def test_entries_a_closed_loop_left_behind_hold_no_slot():
    *stale, fresh = distinct_tokens(MAX_SIMULATIONS + 1)
    simulator, releases, started = held_simulator([fresh])
    loop = asyncio.new_event_loop()

    async def leave_entries():
        callers = [asyncio.ensure_future(simulator.simulate(token)) for token in stale]
        await asyncio.sleep(0)
        # Cancelled before its first step, a simulation never runs the finally that pops its entry.
        simulations = list(simulator._inflight.values())
        for task in [*simulations, *callers]:
            task.cancel()
        await asyncio.gather(*simulations, *callers, return_exceptions=True)

    loop.run_until_complete(leave_entries())
    loop.close()
    assert len(simulator._inflight) == MAX_SIMULATIONS
    releases[fresh].set()
    result = asyncio.run(simulator.simulate(fresh))
    assert result["reason"] == "No supported pool found"
    assert started == [fresh]


def background_simulations(simulator, tokens):
    """Start each token's simulation as the hunter or the launch watch would, under BACKGROUND."""
    background = botchain_simulation.BACKGROUND.set(True)
    try:
        return [asyncio.create_task(simulator.simulate(token)) for token in tokens]
    finally:
        botchain_simulation.BACKGROUND.reset(background)


async def background_simulate(simulator, token):
    background = botchain_simulation.BACKGROUND.set(True)
    try:
        return await simulator.simulate(token)
    finally:
        botchain_simulation.BACKGROUND.reset(background)


@pytest.mark.asyncio
async def test_background_work_at_the_cap_is_refused_and_a_users_new_token_is_still_simulated():
    *queued, theirs, mine = distinct_tokens(MAX_SIMULATIONS + 2)
    simulator, releases, started = held_simulator([*queued, mine])
    callers = background_simulations(simulator, queued)
    await asyncio.sleep(0)
    refused = await background_simulate(simulator, theirs)
    assert refused["rpc_failed"] is True
    assert refused["reason"] == (
        f"Simulation not run: {MAX_SIMULATIONS} simulations already in progress"
    )
    user = asyncio.create_task(simulator.simulate(mine))
    await asyncio.sleep(0)
    assert len(simulator._inflight) == MAX_SIMULATIONS + 1
    releases[queued[0]].set()
    releases[mine].set()
    result = await user
    assert result["reason"] == "No supported pool found"
    # The lane took the user's simulation ahead of the background ones waiting.
    assert started[:2] == [queued[0], mine]
    for release in releases.values():
        release.set()
    await asyncio.gather(*callers)
    assert simulator._inflight == {}


@pytest.mark.asyncio
async def test_users_are_capped_on_their_own_beside_background_work():
    tokens = distinct_tokens(2 * MAX_SIMULATIONS + 2)
    theirs = tokens[:MAX_SIMULATIONS]
    mine = tokens[MAX_SIMULATIONS : 2 * MAX_SIMULATIONS]
    user_refused, background_refused = tokens[-2:]
    simulator, releases, started = held_simulator([*theirs, *mine])
    callers = background_simulations(simulator, theirs)
    callers += [asyncio.create_task(simulator.simulate(token)) for token in mine]
    await asyncio.sleep(0)
    assert len(simulator._inflight) == 2 * MAX_SIMULATIONS
    reason = f"Simulation not run: {MAX_SIMULATIONS} simulations already in progress"
    assert (await simulator.simulate(user_refused))["reason"] == reason
    assert (await background_simulate(simulator, background_refused))["reason"] == reason
    assert user_refused not in started and background_refused not in started
    for release in releases.values():
        release.set()
    await asyncio.gather(*callers)
    assert simulator._inflight == {}


@pytest.mark.asyncio
async def test_a_background_simulation_a_user_joined_counts_against_users():
    tokens = distinct_tokens(MAX_SIMULATIONS + 1)
    simulator, releases, started = held_simulator(tokens[:-1])
    callers = background_simulations(simulator, tokens[:-1])
    await asyncio.sleep(0)
    callers += [asyncio.create_task(simulator.simulate(token)) for token in tokens[:-1]]
    await asyncio.sleep(0)
    result = await simulator.simulate(tokens[-1])
    assert result["reason"] == (
        f"Simulation not run: {MAX_SIMULATIONS} simulations already in progress"
    )
    for release in releases.values():
        release.set()
    await asyncio.gather(*callers)
    assert simulator._inflight == {}


# --- the optional simulation RPC ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_simulation_rpc_answers_the_simulations_when_configured():
    first, sized = cow_runs()
    replay = Replay("cow", [])
    sim = AsyncMock(
        side_effect=[
            [{"jsonrpc": "2.0", "id": 0, "result": first.result}],
            [{"jsonrpc": "2.0", "id": 0, "result": sized.result}],
        ]
    )
    simulator = simulator_for(replay, sim_rpc_url="https://sim.example")
    simulator._sim_request = sim
    with cycling_addresses():
        result = await simulator.simulate(COW)
    assert (result["buy_tax"], result["sell_tax"], result["can_sell"]) == (
        1.0,
        1.0,
        True,
    )
    assert sim.await_count == 2
    assert not replay.simulate_requests()


@pytest.mark.asyncio
async def test_a_failing_simulation_rpc_falls_back_to_the_official_rpc():
    first, sized = cow_runs()
    replay = Replay("cow", [first.result, sized.result])
    sim = AsyncMock(side_effect=SimulationUnavailable("RPC HTTP 502"))
    simulator = simulator_for(replay, sim_rpc_url="https://sim.example")
    simulator._sim_request = sim
    with cycling_addresses():
        result = await simulator.simulate(COW)
    assert (result["buy_tax"], result["sell_tax"], result["can_sell"]) == (
        1.0,
        1.0,
        True,
    )
    assert sim.await_count == 2
    assert len(replay.simulate_requests()) == 2


@pytest.mark.asyncio
async def test_the_simulation_rpc_is_asked_with_its_own_short_timeout():
    simulator = BotChainSimulator(
        "https://official.example", sim_rpc_url="https://sim.example"
    )
    session = _session((200, {"jsonrpc": "2.0", "id": 0, "result": "0x1"}))
    await simulator._sim_request(session, [("eth_blockNumber", [])])
    args, kwargs = session.post.call_args
    assert args == ("https://sim.example",)
    assert kwargs["timeout"].total == SIM_RPC_TIMEOUT_SECONDS


def test_without_a_simulation_rpc_the_official_one_is_the_default():
    simulator = BotChainSimulator()
    assert (simulator._rpc_url, simulator._sim_rpc_url) == (RPC_URL, None)
    assert BotChainSimulator(sim_rpc_url="")._sim_rpc_url is None


# --- the ledger and the wording -----------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,token,outcome",
    [
        ("cow", COW, "answered"),
        ("no_pool", "0x68caea9104419203cf8b8f0b222e75709b97bfc6", "unknown"),
    ],
)
async def test_the_ledger_records_under_the_instances_chain_id(name, token, outcome):
    simulator = simulator_for(Replay(name))
    assert simulator.chain_id == CHAIN_ID
    simulator.chain_id = 999
    with (
        cycling_addresses(),
        patch.object(botchain_simulation, "unknown_ledger") as ledger,
    ):
        await simulator.simulate(token)
    ledger.record.assert_called_once_with(SIMULATION_PROVIDER, 999, outcome)


@pytest.mark.asyncio
async def test_a_simulation_that_could_not_run_counts_failed():
    simulator = simulator_for(AsyncMock(side_effect=asyncio.TimeoutError()))
    with patch.object(botchain_simulation, "unknown_ledger") as ledger:
        await simulator.simulate(COW)
    ledger.record.assert_called_once_with(SIMULATION_PROVIDER, CHAIN_ID, "failed")


def test_no_string_in_the_module_says_safe():
    tree = ast.parse(inspect.getsource(botchain_simulation))
    strings = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    assert strings and not [text for text in strings if "safe" in text.lower()]


def test_no_recorded_result_or_reason_says_safe():
    reasons = [
        load(name)["result"]["reason"] for name in ("cow", "usdt", "lk2e", "no_pool")
    ]
    run = usdt_runs()[1]
    reasons += [
        run.evaluate(failed_sell(run, error_string(message)))["reason"]
        for message in ("STF", "IIA", "other")
    ]
    assert reasons and not [reason for reason in reasons if "safe" in reason.lower()]
