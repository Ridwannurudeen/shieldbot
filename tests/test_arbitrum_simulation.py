"""Arbitrum One (42161) buy/sell simulation: encoding, verdicts on recorded live simulations, attributable and
unattributable sell failures, RPC failures, pool discovery and the adapter's integration."""

import copy
import dataclasses
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_abi import encode
from eth_utils import keccak

from adapters.arbitrum import SIMULATION_RPC_URL, ArbitrumAdapter
from adapters.evm_base import EvmAdapter
from analyzers.honeypot import HoneypotAnalyzer
from core.analyzer import AnalysisContext
from core.extension_formatter import format_extension_alert
from core.risk_engine import RiskEngine
from core.unknown_ledger import UnknownLedger
from services.arbitrum_simulation import (
    CHAIN_ID,
    MAX_POOLS,
    MIN_TRAP_COST_WEI,
    V2_ROUTES,
    V3_FACTORY,
    WETH,
    ArbitrumSimulator,
    Pool,
    build_simulation_request,
    call_labels,
    evaluate_simulation,
)
from services.honeypot_service import HoneypotService
from utils.scam_db import ScamDatabase
from utils.web3_client import Web3Client

FIXTURES = Path(__file__).parent / "fixtures" / "arbitrum_simulation"
FIELDS = ("is_honeypot", "buy_tax", "sell_tax", "can_buy", "can_sell")
ZERO_WORD = "0x" + "0" * 64


def load(name):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def pool_of(fixture):
    return Pool(fixture["route"], fixture["pool"], fixture["fee"])


def evaluate(fixture):
    return evaluate_simulation(
        pool_of(fixture),
        fixture["token"],
        fixture["amount"],
        fixture["buyer"],
        fixture["response"]["result"],
        fixture["sell_amount"],
    )


def calls_by_label(fixture):
    return dict(zip(call_labels(pool_of(fixture)), fixture["response"]["result"][0]["calls"]))


def error_string(message):
    return "0x" + (keccak(text="Error(string)")[:4] + encode(["string"], [message])).hex()


def make_revert(call, data):
    call.update(
        status="0x0",
        logs=[],
        returnData="0x",
        error={"message": "execution reverted", "code": 3, "data": data},
    )


def failed_sell(fixture, data):
    fixture = copy.deepcopy(fixture)
    calls = calls_by_label(fixture)
    make_revert(calls["sell"], data)
    # A reverted sell leaves the seller holding everything it bought, so the plain transfer that the
    # recorded (successful) sell left unfunded now succeeds.
    calls["after_sell"]["returnData"] = calls["delivered"]["returnData"]
    calls["transfer"].update(status="0x1", returnData=ZERO_WORD[:-1] + "1", error=None)
    return fixture


# --- the request the RPC accepted -------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["v3_arb", "v2_sushiswap_magic", "v2_fee_on_transfer", "v2_fee_on_transfer_sized", "v2_honeypot"],
)
def test_the_request_is_the_one_recorded_live(name):
    fixture = load(name)
    request = build_simulation_request(
        pool_of(fixture),
        fixture["token"],
        fixture["amount"],
        fixture["buyer"],
        fixture["receiver"],
        fixture["sell_amount"],
    )
    assert request == fixture["request"][0]


def test_the_confirmation_request_is_the_one_recorded_live():
    fixture = load("v2_honeypot_confirmation")
    request = build_simulation_request(
        pool_of(fixture),
        fixture["token"],
        fixture["amount"],
        fixture["buyer"],
        fixture["receiver"],
        fixture["sell_amount"],
        (fixture["payer"], fixture["sell_time"]),
    )
    assert request == fixture["request"][0]


def test_a_v3_trade_goes_through_swaprouter02_with_no_deadline():
    fixture = load("v3_arb")
    buy, _, _, sell, _, _ = fixture["request"][0]["blockStateCalls"][0]["calls"]
    assert buy["to"] == sell["to"] == "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45"
    # exactOutputSingle and exactInputSingle of IV3SwapRouter: seven words, no deadline.
    assert (
        buy["data"][:10]
        == "0x"
        + keccak(
            text="exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))"
        )[:4].hex()
    )
    assert len(buy["data"]) == 10 + 7 * 64
    assert (
        sell["data"][:10]
        == "0x"
        + keccak(text="exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))")[
            :4
        ].hex()
    )


# --- verdicts on recorded live simulations -----------------------------------------------------


@pytest.mark.parametrize("name", ["v3_arb", "v2_sushiswap_magic"])
def test_a_recorded_clean_token_buys_and_sells_untaxed(name):
    outcome = evaluate(load(name))
    assert {field: outcome[field] for field in FIELDS} == {
        "is_honeypot": False,
        "buy_tax": 0.0,
        "sell_tax": 0.0,
        "can_buy": True,
        "can_sell": True,
    }
    assert outcome["simulation_failed"] is False
    assert outcome["reason"].startswith("buy and sell succeeded")


def test_a_fee_on_transfer_buy_asks_for_a_sized_sell():
    fixture = load("v2_fee_on_transfer")
    outcome = evaluate(fixture)
    assert outcome["buy_tax"] == 2.0
    assert outcome["can_buy"] is True
    assert outcome["can_sell"] is None
    assert outcome["retry_sell_amount"] == load("v2_fee_on_transfer_sized")["sell_amount"]


def test_the_sized_sell_measures_the_two_percent_tax_both_ways():
    outcome = evaluate(load("v2_fee_on_transfer_sized"))
    assert (
        outcome["buy_tax"],
        outcome["sell_tax"],
        outcome["can_sell"],
        outcome["is_honeypot"],
    ) == (2.0, 2.0, True, False)


V2_SWAP_TOPIC = "0x" + keccak(text="Swap(address,uint256,uint256,uint256,uint256,address)").hex()


def _seller_swap(fixture):
    (event,) = [
        log
        for log in calls_by_label(fixture)["sell"]["logs"]
        if log["address"].lower() == fixture["pool"] and log["topics"][0] == V2_SWAP_TOPIC
    ]
    return event


def _swapped_back(fixture, tokens, recipient):
    """The sell of a token that swaps `tokens` of its own collected balance through the pair inside the
    seller's transfer: the pair's Swap for them pays `recipient` and comes before the seller's, and the
    pair's token balance rises by `tokens` more than the seller sent it."""
    fixture = copy.deepcopy(fixture)
    calls = calls_by_label(fixture)
    seller_swap = _seller_swap(fixture)
    swapback = copy.deepcopy(seller_swap)
    swapback["topics"][2] = _address_word(recipient)
    amounts = [tokens, 0, 0, 10**12] if fixture["token"] < WETH else [0, tokens, 10**12, 0]
    swapback["data"] = "0x" + encode(["uint256"] * 4, amounts).hex()
    logs = calls["sell"]["logs"]
    logs.insert(logs.index(seller_swap), swapback)
    calls["pool_after_sell"]["returnData"] = _word(
        int(calls["pool_after_sell"]["returnData"], 16) + tokens
    )
    return fixture


@pytest.mark.parametrize("share", [1, 5])
def test_a_v2_sell_tax_is_the_sellers_swap_input_when_the_token_swaps_back_inside_its_sell(share):
    # A swap-back of 1% of the sell raises the pair's balance by 99% of what the seller sent, a 1% tax by
    # the balance; one of 5% raises it by more than the seller sent, which the balance cannot measure.
    # The pair's Swap paying the seller states the 98% it counted as the seller's input either way.
    fixture = load("v2_fee_on_transfer_sized")
    swapped_back = _swapped_back(
        fixture, fixture["sell_amount"] * share // 100, V2_ROUTES["uniswap-v2"][1]
    )
    outcome = evaluate(swapped_back)
    assert (outcome["sell_tax"], outcome["can_sell"], outcome["is_honeypot"]) == (2.0, True, False)


def test_two_v2_swaps_paying_the_seller_leave_the_sell_tax_unmeasured():
    fixture = copy.deepcopy(load("v2_fee_on_transfer_sized"))
    duplicate = copy.deepcopy(_seller_swap(fixture))
    calls_by_label(fixture)["sell"]["logs"].append(duplicate)
    outcome = evaluate(fixture)
    assert (outcome["sell_tax"], outcome["can_sell"]) == (None, True)
    assert outcome["simulation_failed"] is False
    assert "sell tax unmeasurable" in outcome["reason"]


@pytest.mark.asyncio
async def test_a_sell_whose_tax_could_not_be_measured_is_sellable_at_an_unknown_tax_and_scores_nothing():
    fixture = copy.deepcopy(load("v2_fee_on_transfer_sized"))
    duplicate = copy.deepcopy(_seller_swap(fixture))
    calls_by_label(fixture)["sell"]["logs"].append(duplicate)
    service = _service_with(fixture, pools={(V2_ROUTES["uniswap-v2"][0], None): fixture["pool"]})
    unavailable = AsyncMock(return_value={"status": "unknown", "reason": "GoPlus has no data", "data": {}})
    with fresh_addresses(fixture), patch.object(ScamDatabase, "fetch_token_security", new=unavailable):
        result = await HoneypotAnalyzer(service).analyze(
            AnalysisContext(fixture["token"], chain_id=42161)
        )
    data = result.data
    assert (data["is_honeypot"], data["can_sell"], data["buy_tax"], data["sell_tax"]) == (
        False,
        True,
        2.0,
        None,
    )
    assert data["simulation_failed"] is False
    assert data["status"] == "unknown"
    assert result.score == 0


def test_a_real_honeypot_recorded_live_is_caught():
    # ARBROKER: every sell forwards the token's ETH to a tax wallet that rejects it (see the fixture note).
    outcome = evaluate(load("v2_honeypot"))
    assert (outcome["is_honeypot"], outcome["can_buy"], outcome["can_sell"], outcome["buy_tax"]) == (
        True,
        True,
        False,
        0.0,
    )
    assert outcome["simulation_failed"] is False
    assert outcome["reason"] == (
        'sell reverted: the token refused the transfer to the pool (Error("TransferHelper: TRANSFER_FROM_FAILED")); '
        "a plain transfer of half the tokens to a fresh address succeeded"
    )


def test_the_real_honeypot_still_refuses_the_sell_in_its_confirmation_recorded_live():
    # The buy paid by a separate address, the sell an hour later: the same refusal (see the fixture note).
    fixture = load("v2_honeypot_confirmation")
    outcome = evaluate_simulation(
        pool_of(fixture),
        fixture["token"],
        fixture["amount"],
        fixture["buyer"],
        fixture["response"]["result"],
        fixture["sell_amount"],
        confirmation=True,
    )
    assert (outcome["is_honeypot"], outcome["can_buy"], outcome["can_sell"]) == (True, True, False)
    assert outcome["trap"] == evaluate(load("v2_honeypot"))["trap"] is not None
    # The sell block ran at the overridden time.
    buy_block, sell_block = fixture["response"]["result"]
    assert int(sell_block["number"], 16) == int(buy_block["number"], 16) + 1
    times = {log["blockTimestamp"] for call in sell_block["calls"] for log in call["logs"]}
    assert times == {hex(fixture["sell_time"])}


# --- sell failures: only attributable evidence makes a honeypot -----------------------------------


@pytest.mark.parametrize(
    "name,message",
    [
        ("v3_arb", "STF"),
        ("v2_sushiswap_magic", "TransferHelper: TRANSFER_FROM_FAILED"),
        ("v2_sushiswap_magic", "UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT"),
    ],
)
def test_a_token_refusing_the_sell_is_a_honeypot(name, message):
    outcome = evaluate(failed_sell(load(name), error_string(message)))
    assert (outcome["is_honeypot"], outcome["can_sell"], outcome["can_buy"]) == (True, False, True)
    assert outcome["reason"].startswith("sell reverted: ")
    assert "a plain transfer of half the tokens to a fresh address succeeded" in outcome["reason"]


def test_a_v3_pool_refusing_a_fee_on_transfer_sell_is_not_a_honeypot():
    outcome = evaluate(failed_sell(load("v3_arb"), error_string("IIA")))
    assert (outcome["is_honeypot"], outcome["can_sell"], outcome["simulation_failed"]) == (
        None,
        None,
        False,
    )
    assert "fee-on-transfer token sold into a V3 pool" in outcome["reason"]


@pytest.mark.parametrize(
    "name,data",
    [
        ("v2_sushiswap_magic", error_string("UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT")),
        ("v3_arb", error_string("Too little received")),
        ("v3_arb", "0x"),
        # Each router's refusal string counts only on its own route.
        ("v3_arb", error_string("TransferHelper: TRANSFER_FROM_FAILED")),
        ("v3_arb", error_string("UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT")),
        ("v2_sushiswap_magic", error_string("STF")),
    ],
)
def test_an_unattributed_sell_failure_stays_unknown(name, data):
    outcome = evaluate(failed_sell(load(name), data))
    assert (outcome["is_honeypot"], outcome["can_sell"]) == (None, None)
    assert "unattributed" in outcome["reason"]


def test_a_blanket_transfer_block_is_named_in_the_reason():
    fixture = failed_sell(load("v3_arb"), error_string("STF"))
    make_revert(calls_by_label(fixture)["transfer"], error_string("blocked"))
    outcome = evaluate(fixture)
    assert outcome["is_honeypot"] is True
    assert (
        'a plain transfer to a fresh address also reverted (Error("blocked"))' in outcome["reason"]
    )


def test_a_reverted_buy_leaves_every_verdict_unknown():
    fixture = copy.deepcopy(load("v3_arb"))
    make_revert(calls_by_label(fixture)["buy"], error_string("STF"))
    outcome = evaluate(fixture)
    assert all(outcome[field] is None for field in FIELDS)
    assert outcome["reason"] == 'buy reverted: Error("STF")'


def _zero_sell_output(fixture, weth_paid):
    """The sell's WETH transfer to the seller removed and the pool's Swap event showing `weth_paid`."""
    fixture = copy.deepcopy(fixture)
    sell = calls_by_label(fixture)["sell"]
    buyer_topic = "0x" + "0" * 24 + fixture["buyer"][2:]
    sell["logs"] = [
        log
        for log in sell["logs"]
        if not (log["address"].lower() == WETH and log["topics"][2] == buyer_topic)
    ]
    for log in sell["logs"]:
        if log["address"].lower() == fixture["pool"]:
            data = bytes.fromhex(log["data"][2:])
            token_is_0 = fixture["token"] < WETH
            words = [data[i : i + 32] for i in range(0, len(data), 32)]
            words[1 if token_is_0 else 0] = (-weth_paid).to_bytes(32, "big", signed=True)
            log["data"] = "0x" + b"".join(words).hex()
    return fixture


def test_a_sell_paying_nothing_is_a_honeypot():
    outcome = evaluate(_zero_sell_output(load("v3_arb"), 0))
    assert (outcome["is_honeypot"], outcome["can_sell"]) == (True, False)
    assert "returned zero output" in outcome["reason"]


def test_a_pool_paying_weth_the_trace_never_sent_is_malformed():
    outcome = evaluate(_zero_sell_output(load("v3_arb"), 10**15))
    assert outcome["simulation_failed"] is True
    assert outcome["reason"] == "Malformed eth_simulateV1 sell logs"


def test_weth_paid_to_anyone_but_the_seller_is_not_the_sells_output():
    fixture = copy.deepcopy(load("v3_arb"))
    buyer_topic = "0x" + "0" * 24 + fixture["buyer"][2:]
    elsewhere = "0x" + "0" * 24 + "ab" * 20
    for log in calls_by_label(fixture)["sell"]["logs"]:
        if log["address"].lower() == WETH and log["topics"][2] == buyer_topic:
            log["topics"][2] = elsewhere
    outcome = evaluate(fixture)
    assert outcome["can_sell"] is None
    assert outcome["reason"] == "Malformed eth_simulateV1 sell logs"


def test_a_zero_sell_after_a_dust_buy_stays_unknown():
    fixture = _zero_sell_output(load("v3_arb"), 0)
    for log in calls_by_label(fixture)["buy"]["logs"]:
        if log["address"].lower() == fixture["pool"]:
            data = bytes.fromhex(log["data"][2:])
            words = [data[i : i + 32] for i in range(0, len(data), 32)]
            words[1 if fixture["token"] < WETH else 0] = (MIN_TRAP_COST_WEI - 1).to_bytes(
                32, "big", signed=True
            )
            log["data"] = "0x" + b"".join(words).hex()
    outcome = evaluate(fixture)
    assert (outcome["is_honeypot"], outcome["can_sell"]) == (None, None)
    assert "too little to rule out rounding" in outcome["reason"]


# --- the simulator: RPC failures and pool discovery ---------------------------------------------


def _row(index, result=None, error=None):
    return {"jsonrpc": "2.0", "id": index, **({"error": error} if error else {"result": result})}


def _word(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def _address_word(address: str) -> str:
    return "0x" + "0" * 24 + address[2:]


# The source block time FakeRpc reports, and the payer of a confirmation run's buy.
TIMESTAMP = 1_790_000_000
PAYER = "0x" + "fa" * 20


class FakeRpc:
    """Answers the simulator's JSON-RPC batches: discovery from tables, then the recorded simulation, and
    a confirmation run (two blocks) from `confirmation`."""

    def __init__(self, fixture, pools=None, balances=None, simulate=None, confirmation=None):
        self.fixture = fixture
        self.pools = pools if pools is not None else {(V3_FACTORY, fixture["fee"]): fixture["pool"]}
        self.balances = balances if balances is not None else {fixture["pool"]: 10**20}
        self.simulate = simulate
        self.confirmation = confirmation
        self.calls = []

    async def __call__(self, session, calls):
        self.calls.append(calls)
        rows = []
        for index, (method, params) in enumerate(calls):
            if method == "eth_getBlockByNumber":
                rows.append(
                    _row(index, {"number": self.fixture["request"][1], "timestamp": hex(TIMESTAMP)})
                )
            elif method == "eth_simulateV1":
                if self.simulate:
                    rows.append(self.simulate(index))
                else:
                    confirming = len(params[0]["blockStateCalls"]) == 2
                    assert self.confirmation or not confirming, "unexpected confirmation run"
                    answer = self.confirmation if confirming else self.fixture
                    rows.append({**answer["response"], "id": index})
            else:
                to, data = params[0]["to"], params[0]["data"]
                if data == "0x18160ddd":
                    rows.append(_row(index, _word(self.fixture["amount"] * 1_000_000)))
                elif data.startswith(
                    "0x" + keccak(text="getPool(address,address,uint24)")[:4].hex()
                ):
                    fee = int(data[-64:], 16)
                    rows.append(
                        _row(index, _address_word(self.pools.get((to, fee), "0x" + "0" * 40)))
                    )
                elif data.startswith("0x" + keccak(text="getPair(address,address)")[:4].hex()):
                    rows.append(
                        _row(index, _address_word(self.pools.get((to, None), "0x" + "0" * 40)))
                    )
                elif to == WETH:
                    rows.append(_row(index, _word(self.balances.get("0x" + data[-40:], 0))))
                else:
                    raise AssertionError(f"unexpected call {method} {params}")
        return rows


def simulator_for(rpc):
    simulator = ArbitrumSimulator("https://rpc.invalid")
    simulator._request = rpc
    return simulator


def fresh_addresses(fixture):
    return patch(
        "services.arbitrum_simulation._fresh_address",
        side_effect=[fixture["buyer"], fixture["receiver"]] * 4,
    )


def run_addresses(fixture, *runs):
    """The fixture's buyer and receiver for each run in turn, and PAYER as a "confirm" run's third."""
    addresses = []
    for run in runs:
        addresses += [fixture["buyer"], fixture["receiver"]] + ([PAYER] if run == "confirm" else [])
    return patch("services.arbitrum_simulation._fresh_address", side_effect=addresses)


def as_confirmation(fixture):
    """The fixture's simulation answered as a confirmation run: its buy calls in one block, its sell
    calls in the next."""
    fixture = copy.deepcopy(fixture)
    (block,) = fixture["response"]["result"]
    number = int(block["number"], 16)
    fixture["response"]["result"] = [
        {"calls": block["calls"][:2], "number": hex(number)},
        {"calls": block["calls"][2:], "number": hex(number + 1)},
    ]
    return fixture


def _answering(fixture, *answers, **fake):
    """A FakeRpc for the fixture answering each eth_simulateV1 in turn from `answers`."""
    replies = iter(answers)
    return FakeRpc(fixture, simulate=lambda index: {**next(replies)["response"], "id": index}, **fake)


@pytest.mark.asyncio
async def test_a_crashed_simulation_handler_leaves_every_trade_field_unknown():
    fixture = load("v3_arb")
    rpc = FakeRpc(
        fixture,
        simulate=lambda index: _row(
            index, error={"code": -32603, "message": "method handler crashed"}
        ),
    )
    with fresh_addresses(fixture):
        result = await simulator_for(rpc).simulate(fixture["token"])
    assert all(result[field] is None for field in FIELDS)
    # Nothing about the token was observed: no failed simulation to score, only an unknown.
    assert "simulation_failed" not in result
    assert result["rpc_failed"] is True
    assert "eth_simulateV1 failed (JSON-RPC error -32603)" in result["reason"]


@pytest.mark.asyncio
async def test_a_sized_follow_up_the_rpc_could_not_run_keeps_the_buy_evidence_without_a_failed_simulation():
    first = load("v2_fee_on_transfer")
    crashed = {"jsonrpc": "2.0", "error": {"code": -32603, "message": "method handler crashed"}}
    replies = iter([first["response"], crashed])
    rpc = FakeRpc(
        first,
        pools={(V2_ROUTES["uniswap-v2"][0], None): first["pool"]},
        simulate=lambda index: {**next(replies), "id": index},
    )
    with fresh_addresses(first):
        result = await simulator_for(rpc).simulate(first["token"])
    assert (result["can_buy"], result["buy_tax"], result["can_sell"], result["is_honeypot"]) == (
        True,
        2.0,
        None,
        None,
    )
    assert result["rpc_failed"] is True
    assert "simulation_failed" not in result
    assert "sized follow-up: eth_simulateV1 failed (JSON-RPC error -32603)" in result["reason"]


@pytest.mark.asyncio
async def test_a_recorded_token_is_simulated_end_to_end():
    fixture = load("v3_arb")
    with fresh_addresses(fixture):
        result = await simulator_for(FakeRpc(fixture)).simulate(fixture["token"])
    assert {field: result[field] for field in FIELDS} == {
        "is_honeypot": False,
        "buy_tax": 0.0,
        "sell_tax": 0.0,
        "can_buy": True,
        "can_sell": True,
    }
    assert result["simulation_block"] == int(fixture["request"][1], 16)
    assert "simulation_failed" not in result


@pytest.mark.asyncio
async def test_discovery_simulates_the_pools_holding_the_most_weth():
    fixture = load("v3_arb")
    pools = {(V3_FACTORY, fee): "0x" + f"{fee:040x}" for fee in (100, 500, 3000, 10_000)}
    pools[("0xf1d7cc64fb4452f05c498126312ebe29f30fbcf9", None)] = "0x" + "a" * 40
    balances = {
        "0x" + f"{100:040x}": 1,
        "0x" + f"{500:040x}": 500,
        "0x" + f"{3000:040x}": 0,
        "0x" + f"{10_000:040x}": 300,
        "0x" + "a" * 40: 400,
    }
    rpc = FakeRpc(fixture, pools=pools, balances=balances)
    amount, found, notes = await simulator_for(rpc)._discover(None, fixture["token"])
    assert amount == fixture["amount"]
    assert [(pool.route, pool.address) for pool in found] == [
        ("v3", "0x" + f"{500:040x}"),
        ("uniswap-v2", "0x" + "a" * 40),
        ("v3", "0x" + f"{10_000:040x}"),
    ]
    assert len(found) == MAX_POOLS
    assert f"v3 pool {'0x' + f'{3000:040x}'} holds no WETH" in notes
    assert f"v3 pool {'0x' + f'{100:040x}'} not simulated (cap of {MAX_POOLS} pools)" in notes


@pytest.mark.asyncio
async def test_a_token_without_a_weth_pool_is_not_simulated():
    fixture = load("v3_arb")
    rpc = FakeRpc(fixture, pools={})
    result = await simulator_for(rpc).simulate(fixture["token"])
    assert all(result[field] is None for field in FIELDS)
    assert "No supported pool found" in result["reason"]
    assert not any(method == "eth_simulateV1" for calls in rpc.calls for method, _ in calls)


@pytest.mark.asyncio
async def test_weth_itself_is_not_simulated():
    result = await ArbitrumSimulator("https://rpc.invalid").simulate(WETH)
    assert all(result[field] is None for field in FIELDS)
    assert "WETH is the asset" in result["reason"]


# --- the adapter and the honeypot check ---------------------------------------------------------


def test_the_adapter_simulates_through_publicnode_unless_configured(monkeypatch):
    monkeypatch.delenv("ARBITRUM_SIMULATION_RPC_URL", raising=False)
    adapter = ArbitrumAdapter(rpc_url="https://rpc.invalid")
    assert (
        adapter._simulator._rpc_url
        == SIMULATION_RPC_URL
        == "https://arbitrum-one-rpc.publicnode.com"
    )
    assert adapter.supports_honeypot_simulation is True
    assert adapter.capabilities()["sell_simulation"] == "eth_simulateV1"
    monkeypatch.setenv("ARBITRUM_SIMULATION_RPC_URL", "https://sim.invalid")
    assert (
        ArbitrumAdapter(rpc_url="https://rpc.invalid")._simulator._rpc_url == "https://sim.invalid"
    )


def _service_with(fixture, **fake):
    adapter = ArbitrumAdapter(rpc_url="https://rpc.invalid")
    adapter._simulator._request = FakeRpc(fixture, **fake)
    client = Web3Client.__new__(Web3Client)
    client._adapters = {42161: adapter}
    return HoneypotService(client)


@pytest.mark.asyncio
async def test_an_arbitrum_token_scan_now_completes_from_the_simulation():
    fixture = load("v3_arb")
    service = _service_with(fixture)
    with (
        fresh_addresses(fixture),
        patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock()) as goplus,
    ):
        data = await service.fetch_honeypot_data(fixture["token"], chain_id=42161)
        result = await HoneypotAnalyzer(service).analyze(
            AnalysisContext(fixture["token"], chain_id=42161)
        )
    goplus.assert_not_awaited()
    assert data["status"] == "ok"
    assert data["field_providers"] == {field: "eth_simulateV1" for field in FIELDS}
    assert result.data["status"] == "ok"
    assert result.score == 0


@pytest.mark.asyncio
async def test_a_failed_arbitrum_simulation_still_falls_back_to_goplus_and_stays_unknown():
    fixture = load("v3_arb")
    service = _service_with(
        fixture,
        simulate=lambda index: _row(
            index, error={"code": -32603, "message": "method handler crashed"}
        ),
    )
    # A complete, clean GoPlus answer: what GoPlus says of a honeypot it cannot see (ARBROKER included).
    goplus = AsyncMock(
        return_value={
            "status": "ok",
            "reason": None,
            "observed_at": 0,
            "data": {
                "is_honeypot": "0",
                "cannot_buy": "0",
                "cannot_sell_all": "0",
                "transfer_pausable": "0",
                "buy_tax": "0",
                "sell_tax": "0",
            },
        }
    )
    with fresh_addresses(fixture), patch.object(ScamDatabase, "fetch_token_security", new=goplus):
        data = await service.fetch_honeypot_data(fixture["token"], chain_id=42161)
        result = await HoneypotAnalyzer(service).analyze(
            AnalysisContext(fixture["token"], chain_id=42161)
        )
    goplus.assert_awaited()
    assert data["status"] == result.data["status"] == "unknown"
    assert data["can_sell"] is None
    assert "Honeypot simulation could not run (unresolved)" in data["reason"]
    assert result.score == 0
    # The honeypot analyzer alone at full weight decides the verdict, as beside clean other analyzers.
    risk = RiskEngine().compute_from_results([dataclasses.replace(result, weight=1.0)])
    assert risk["status"] == "unknown"
    assert risk["risk_level"] != "LOW"
    assert format_extension_alert(risk)["risk_classification"] != "SAFE"


@pytest.mark.asyncio
async def test_an_arbitrum_simulation_the_rpc_could_not_run_is_unknown_scores_nothing_and_counts_failed(
    monkeypatch,
):
    ledger = UnknownLedger()
    monkeypatch.setattr("services.arbitrum_simulation.unknown_ledger", ledger)
    fixture = load("v3_arb")
    service = _service_with(
        fixture,
        simulate=lambda index: _row(
            index, error={"code": -32603, "message": "method handler crashed"}
        ),
    )
    # GoPlus's answer for a new Arbitrum token: no buy or sell tax, so it cannot say the token sells.
    goplus = AsyncMock(
        return_value={
            "status": "ok",
            "reason": None,
            "observed_at": 0,
            "data": {
                "is_honeypot": "0",
                "cannot_buy": "0",
                "buy_tax": "",
                "sell_tax": "",
                "transfer_pausable": "0",
            },
        }
    )
    with fresh_addresses(fixture), patch.object(ScamDatabase, "fetch_token_security", new=goplus):
        result = await HoneypotAnalyzer(service).analyze(
            AnalysisContext(fixture["token"], chain_id=42161)
        )
    goplus.assert_awaited()
    assert result.data["status"] == "unknown"
    assert result.data["can_sell"] is None
    assert result.data["simulation_failed"] is False
    assert "eth_simulateV1 failed (JSON-RPC error -32603)" in result.data["reason"]
    assert result.score == 0
    assert not any("treat as suspicious" in flag for flag in result.flags)
    counts = ledger.for_chain(CHAIN_ID)["eth_simulateV1"]
    assert (counts["answered"], counts["unknown"], counts["failed"]) == (0, 0, 1)


@pytest.mark.asyncio
async def test_a_honeypot_is_simulation_failure_still_scores_as_suspicious():
    # honeypot.is (Ethereum, BNB Chain, Base) ran its own simulation of the token and could not finish it.
    adapter = EvmAdapter.__new__(EvmAdapter)
    adapter._chain_id = 56
    adapter._honeypot_chain_id = 56
    adapter._chain_name = "BSC"
    adapter._honeypot_is_replies = {}
    client = Web3Client.__new__(Web3Client)
    client._adapters = {56: adapter}
    response = AsyncMock(status=200)
    response.json.return_value = {"simulationSuccess": False}
    session = MagicMock()
    session.get.return_value.__aenter__.return_value = response
    unavailable = AsyncMock(return_value={"status": "unknown", "reason": "GoPlus has no data", "data": {}})
    with (
        patch("adapters.evm_base.aiohttp.ClientSession") as http,
        patch.object(ScamDatabase, "fetch_token_security", new=unavailable),
    ):
        http.return_value.__aenter__.return_value = session
        result = await HoneypotAnalyzer(HoneypotService(client)).analyze(
            AnalysisContext("0x" + "ab" * 20, chain_id=56)
        )
    assert result.data["simulation_failed"] is True
    assert result.data["field_providers"]["simulation_failed"] == "honeypot.is"
    assert any("treat as suspicious" in flag for flag in result.flags)
    assert result.score == 40


@pytest.mark.asyncio
async def test_a_real_arbitrum_honeypot_is_flagged_although_goplus_reports_it_clean():
    fixture = load("v2_honeypot")
    confirmation = load("v2_honeypot_confirmation")
    service = _service_with(
        fixture,
        pools={(V2_ROUTES["uniswap-v2"][0], None): fixture["pool"]},
        confirmation=confirmation,
    )
    addresses = [fixture["buyer"], fixture["receiver"]]
    addresses += [confirmation["buyer"], confirmation["receiver"], confirmation["payer"]]
    # GoPlus's answer for this token on 2026-09-29: not a honeypot, sellability unreported, taxes empty.
    goplus = AsyncMock(
        return_value={
            "status": "ok",
            "reason": None,
            "observed_at": 0,
            "data": {
                "is_honeypot": "0",
                "cannot_buy": "0",
                "buy_tax": "",
                "sell_tax": "",
                "transfer_pausable": "0",
            },
        }
    )
    with (
        patch("services.arbitrum_simulation._fresh_address", side_effect=addresses),
        patch.object(ScamDatabase, "fetch_token_security", new=goplus),
    ):
        result = await HoneypotAnalyzer(service).analyze(
            AnalysisContext(fixture["token"], chain_id=42161)
        )
    assert result.data["is_honeypot"] is True
    assert result.data["can_sell"] is False
    assert "reproduced by a re-run whose buy a separate address paid" in result.data["reason"]
    assert result.data["field_providers"]["is_honeypot"] == "eth_simulateV1"
    assert result.data["field_providers"]["can_sell"] == "eth_simulateV1"
    assert "Honeypot detected" in result.flags and "Cannot sell token" in result.flags


def _pools_answering(*answers):
    """Two fee tiers resolving to the recorded v3_arb pool, each eth_simulateV1 answered in turn; the
    deepest (first) pool is the 0.05% tier, as discovery keeps candidate order for equal WETH."""
    fixture = load("v3_arb")
    pools = {(V3_FACTORY, 500): fixture["pool"], (V3_FACTORY, 3000): fixture["pool"]}
    return fixture, _answering(fixture, *answers, pools=pools)


@pytest.mark.asyncio
async def test_a_shallower_pool_refusing_the_sell_leaves_the_token_unknown_when_the_deepest_pool_sold():
    clean = load("v3_arb")
    trapped = failed_sell(clean, error_string("STF"))
    fixture, rpc = _pools_answering(clean, trapped, as_confirmation(trapped))
    with run_addresses(fixture, "run", "run", "confirm"):
        result = await simulator_for(rpc).simulate(fixture["token"])
    # Neither a honeypot (a holder can sell in the deepest pool) nor safe (the shallower pool may trap
    # whoever buys there).
    assert (result["is_honeypot"], result["can_sell"]) == (None, None)
    assert (
        f"not counted as a trap because the pool holding the most WETH, {fixture['pool']}, sold "
        "(sell tax 0%), so sellability is left unknown"
    ) in result["reason"]
    # The trap is evidence: the simulation did not settle the token, so GoPlus cannot settle it
    # instead. The trapped pool's sell tax was never measured, so the deepest pool's 0% is unproven.
    assert result["simulation_failed"] is True
    assert result["sell_tax"] is None


@pytest.mark.asyncio
async def test_a_pool_the_rpc_could_not_simulate_leaves_the_token_unknown_beside_a_clean_pool():
    crashed = {
        "response": {"jsonrpc": "2.0", "error": {"code": -32603, "message": "method handler crashed"}}
    }
    fixture, rpc = _pools_answering(load("v3_arb"), crashed)
    with fresh_addresses(fixture):
        result = await simulator_for(rpc).simulate(fixture["token"])
    # The pool nobody observed may be the one that traps; only the clean pool's buy stands.
    assert {field: result[field] for field in FIELDS} == {
        "is_honeypot": None,
        "buy_tax": None,
        "sell_tax": None,
        "can_buy": True,
        "can_sell": None,
    }
    assert "simulation_failed" not in result
    assert "eth_simulateV1 failed (JSON-RPC error -32603)" in result["reason"]


def _sell_taxed(fixture, percent):
    """The pool's Swap event on the sell shows it received `percent`% less than the seller sent."""
    fixture = copy.deepcopy(fixture)
    sent = int(calls_by_label(fixture)["delivered"]["returnData"], 16)
    for log in calls_by_label(fixture)["sell"]["logs"]:
        if log["address"].lower() == fixture["pool"]:
            data = bytes.fromhex(log["data"][2:])
            words = [data[i : i + 32] for i in range(0, len(data), 32)]
            words[0 if fixture["token"] < WETH else 1] = (sent * (100 - percent) // 100).to_bytes(
                32, "big", signed=True
            )
            log["data"] = "0x" + b"".join(words).hex()
    return fixture


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "percent,verdict",
    # The honeypot analyzer's extreme sell tax line is above 50%.
    [(50, (None, None)), (51, (True, False)), (99, (True, False))],
)
async def test_only_a_deepest_pool_selling_at_no_more_than_half_tax_clears_another_pools_trap(
    percent, verdict
):
    clean = load("v3_arb")
    assert evaluate(_sell_taxed(clean, percent))["sell_tax"] == float(percent)
    trapped = failed_sell(clean, error_string("STF"))
    fixture, rpc = _pools_answering(_sell_taxed(clean, percent), trapped, as_confirmation(trapped))
    with run_addresses(fixture, "run", "run", "confirm"):
        result = await simulator_for(rpc).simulate(fixture["token"])
    assert (result["is_honeypot"], result["can_sell"]) == verdict
    assert result.get("simulation_failed", False) is (verdict == (None, None))


@pytest.mark.asyncio
async def test_a_trapped_deepest_pool_is_not_cleared_by_a_shallower_clean_one():
    clean = load("v3_arb")
    trapped = failed_sell(clean, error_string("STF"))
    fixture, rpc = _pools_answering(trapped, as_confirmation(trapped), clean)
    with run_addresses(fixture, "run", "confirm", "run"):
        result = await simulator_for(rpc).simulate(fixture["token"])
    assert (result["is_honeypot"], result["can_sell"]) == (True, False)
    assert "simulation_failed" not in result


@pytest.mark.asyncio
async def test_only_a_clean_deepest_pool_clears_another_pools_trap():
    clean = load("v3_arb")
    buy_reverted = copy.deepcopy(clean)
    make_revert(calls_by_label(buy_reverted)["buy"], error_string("STF"))
    trapped = failed_sell(clean, error_string("STF"))
    fixture, rpc = _pools_answering(buy_reverted, trapped, as_confirmation(trapped))
    with run_addresses(fixture, "run", "run", "confirm"):
        result = await simulator_for(rpc).simulate(fixture["token"])
    assert (result["is_honeypot"], result["can_sell"]) == (True, False)
    assert "simulation_failed" not in result


# --- a trap is confirmed by one re-run --------------------------------------------------------------


def _confirmation_request(rpc):
    """The params of the simulator's one confirmation eth_simulateV1 request."""
    (params,) = [
        params
        for calls in rpc.calls
        for method, params in calls
        if method == "eth_simulateV1" and len(params[0]["blockStateCalls"]) == 2
    ]
    return params


@pytest.mark.parametrize("name", ["v3_arb", "v2_honeypot"])
def test_a_confirmation_has_a_separate_address_pay_for_the_buy_and_sells_an_hour_later(name):
    fixture = load(name)
    args = (
        pool_of(fixture),
        fixture["token"],
        fixture["amount"],
        fixture["buyer"],
        fixture["receiver"],
        fixture["sell_amount"],
    )
    (plain,) = build_simulation_request(*args)["blockStateCalls"]
    confirmation = build_simulation_request(*args, (PAYER, TIMESTAMP + 3600))
    buy, sell = confirmation["blockStateCalls"]
    # Only the buy's sender changes: the router still delivers to the buyer, who sells.
    assert buy == {
        "stateOverrides": {**plain["stateOverrides"], PAYER: {"balance": hex(100 * 10**18)}},
        "calls": [{**plain["calls"][0], "from": PAYER}, plain["calls"][1]],
    }
    assert sell == {"blockOverrides": {"time": hex(TIMESTAMP + 3600)}, "calls": plain["calls"][2:]}
    assert confirmation["validation"] is False


def test_a_confirmation_is_read_from_two_blocks_and_a_plain_run_from_one():
    trapped = failed_sell(load("v3_arb"), error_string("STF"))
    args = (pool_of(trapped), trapped["token"], trapped["amount"], trapped["buyer"])
    one_block = trapped["response"]["result"]
    two_blocks = as_confirmation(trapped)["response"]["result"]
    confirmed = evaluate_simulation(*args, two_blocks, confirmation=True)
    assert (confirmed["is_honeypot"], confirmed["trap"]) == (True, evaluate(trapped)["trap"])
    for result, confirmation in ((one_block, True), (two_blocks, False)):
        outcome = evaluate_simulation(*args, result, confirmation=confirmation)
        assert (outcome["reason"], outcome["rpc_failed"]) == ("Malformed eth_simulateV1 result", True)


@pytest.mark.asyncio
async def test_a_trap_the_confirmation_reproduces_is_a_honeypot():
    trapped = failed_sell(load("v3_arb"), error_string("STF"))
    rpc = _answering(trapped, trapped, as_confirmation(trapped))
    with run_addresses(trapped, "run", "confirm"):
        result = await simulator_for(rpc).simulate(trapped["token"])
    assert (result["is_honeypot"], result["can_buy"], result["can_sell"]) == (True, True, False)
    assert "reproduced by a re-run whose buy a separate address paid" in result["reason"]
    request, block = _confirmation_request(rpc)
    buy, sell = request["blockStateCalls"]
    assert buy["calls"][0]["from"] == PAYER
    assert sell["blockOverrides"] == {"time": hex(TIMESTAMP + 3600)}
    assert block == trapped["request"][1]


def _unreadable(fixture):
    fixture = copy.deepcopy(fixture)
    calls_by_label(fixture)["delivered"]["returnData"] = "0x"
    return fixture


def _buy_reverted(fixture):
    fixture = copy.deepcopy(fixture)
    make_revert(calls_by_label(fixture)["buy"], error_string("STF"))
    return fixture


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rerun",
    [
        lambda clean: clean,
        lambda clean: failed_sell(clean, error_string("Too little received")),
        lambda clean: _zero_sell_output(clean, 0),
        _buy_reverted,
        _unreadable,
    ],
    ids=["sold", "unattributed-revert", "another-trap", "buy-reverted", "unreadable"],
)
async def test_a_trap_the_confirmation_does_not_reproduce_is_unknown_never_clean(rerun):
    clean = load("v3_arb")
    trapped = failed_sell(clean, error_string("STF"))
    confirmation = rerun(clean)
    rpc = _answering(trapped, trapped, as_confirmation(confirmation))
    with run_addresses(trapped, "run", "confirm"):
        result = await simulator_for(rpc).simulate(trapped["token"])
    assert (result["is_honeypot"], result["can_sell"], result["sell_tax"]) == (None, None, None)
    # The first run's buy evidence stands.
    assert (result["can_buy"], result["buy_tax"]) == (True, 0.0)
    # A trap seen once is a failed simulation: scored as suspicious, and no GoPlus answer completes it.
    assert result["simulation_failed"] is True
    assert "the trap did not reproduce" in result["reason"]
    assert evaluate(trapped)["reason"] in result["reason"]
    assert evaluate(confirmation)["reason"] in result["reason"]


@pytest.mark.asyncio
async def test_a_confirmation_the_rpc_could_not_run_leaves_the_first_runs_trap_standing():
    trapped = failed_sell(load("v3_arb"), error_string("STF"))
    crashed = {
        "response": {"jsonrpc": "2.0", "error": {"code": -32603, "message": "method handler crashed"}}
    }
    rpc = _answering(trapped, trapped, crashed)
    with run_addresses(trapped, "run", "confirm"):
        result = await simulator_for(rpc).simulate(trapped["token"])
    assert (result["is_honeypot"], result["can_sell"]) == (True, False)
    assert "could not run (eth_simulateV1 failed (JSON-RPC error -32603))" in result["reason"]
    assert "rpc_failed" not in result and "simulation_failed" not in result


@pytest.mark.asyncio
async def test_a_zero_output_trap_is_confirmed_as_a_refused_sell_is():
    clean = load("v3_arb")
    trapped = _zero_sell_output(clean, 0)
    assert (evaluate(trapped)["trap"], evaluate(trapped)["sell_tax"]) == ("zero output", 0.0)
    # Reproduced, the trap and its measured tax stand; not reproduced, neither does.
    for rerun, verdict in ((trapped, (True, False, 0.0)), (clean, (None, None, None))):
        rpc = _answering(trapped, trapped, as_confirmation(rerun))
        with run_addresses(trapped, "run", "confirm"):
            result = await simulator_for(rpc).simulate(trapped["token"])
        assert (result["is_honeypot"], result["can_sell"], result["sell_tax"]) == verdict


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "order,verdict",
    [
        ("unconfirmed-then-clean", (None, None)),
        ("clean-then-unconfirmed", (None, None)),
        ("confirmed-then-unconfirmed", (True, False)),
    ],
)
async def test_a_trap_the_confirmation_did_not_reproduce_keeps_another_pool_from_clearing_the_token(
    order, verdict
):
    clean = load("v3_arb")
    trapped = failed_sell(clean, error_string("STF"))
    unconfirmed = [trapped, as_confirmation(clean)]
    answers, runs = {
        "unconfirmed-then-clean": ([*unconfirmed, clean], ("run", "confirm", "run")),
        "clean-then-unconfirmed": ([clean, *unconfirmed], ("run", "run", "confirm")),
        "confirmed-then-unconfirmed": (
            [trapped, as_confirmation(trapped), *unconfirmed],
            ("run", "confirm", "run", "confirm"),
        ),
    }[order]
    fixture, rpc = _pools_answering(*answers)
    with run_addresses(fixture, *runs):
        result = await simulator_for(rpc).simulate(fixture["token"])
    # The trap one run showed may still catch whoever buys in that pool: never clean, and a confirmed
    # trap elsewhere still stands.
    assert (result["is_honeypot"], result["can_sell"]) == verdict
    assert "the trap did not reproduce" in result["reason"]


@pytest.mark.asyncio
async def test_a_trap_found_by_the_sized_follow_up_is_confirmed_selling_the_same_amount():
    first = load("v2_fee_on_transfer")
    sized = failed_sell(
        load("v2_fee_on_transfer_sized"), error_string("TransferHelper: TRANSFER_FROM_FAILED")
    )
    pools = {(V2_ROUTES["uniswap-v2"][0], None): first["pool"]}
    rpc = _answering(first, first, sized, as_confirmation(sized), pools=pools)
    addresses = [first["buyer"], first["receiver"], sized["buyer"], sized["receiver"]]
    addresses += [sized["buyer"], sized["receiver"], PAYER]
    with patch("services.arbitrum_simulation._fresh_address", side_effect=addresses):
        result = await simulator_for(rpc).simulate(first["token"])
    assert (result["is_honeypot"], result["can_sell"], result["buy_tax"]) == (True, False, 2.0)
    assert "reproduced by a re-run" in result["reason"]
    labels = call_labels(pool_of(sized))
    request, _ = _confirmation_request(rpc)
    confirmed_sell = dict(zip(labels[2:], request["blockStateCalls"][1]["calls"]))["sell"]
    (plain,) = build_simulation_request(
        pool_of(sized),
        sized["token"],
        sized["amount"],
        sized["buyer"],
        sized["receiver"],
        sized["sell_amount"],
    )["blockStateCalls"]
    assert confirmed_sell == dict(zip(labels, plain["calls"]))["sell"]
