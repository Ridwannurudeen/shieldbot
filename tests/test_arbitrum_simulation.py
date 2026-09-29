"""Arbitrum One (42161) buy/sell simulation: encoding, verdicts on recorded live simulations, attributable and
unattributable sell failures, RPC failures, pool discovery and the adapter's integration."""

import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from eth_abi import encode
from eth_utils import keccak

from adapters.arbitrum import SIMULATION_RPC_URL, ArbitrumAdapter
from analyzers.honeypot import HoneypotAnalyzer
from core.analyzer import AnalysisContext
from services.arbitrum_simulation import (
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


class FakeRpc:
    """Answers the simulator's JSON-RPC batches: discovery from tables, then the recorded simulation."""

    def __init__(self, fixture, pools=None, balances=None, simulate=None):
        self.fixture = fixture
        self.pools = pools if pools is not None else {(V3_FACTORY, fixture["fee"]): fixture["pool"]}
        self.balances = balances if balances is not None else {fixture["pool"]: 10**20}
        self.simulate = simulate
        self.calls = []

    async def __call__(self, session, calls):
        self.calls.append(calls)
        rows = []
        for index, (method, params) in enumerate(calls):
            if method == "eth_getBlockByNumber":
                rows.append(_row(index, {"number": self.fixture["request"][1]}))
            elif method == "eth_simulateV1":
                rows.append(
                    self.simulate(index)
                    if self.simulate
                    else {**self.fixture["response"], "id": index}
                )
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
    assert result["simulation_failed"] is True
    assert "eth_simulateV1 failed (JSON-RPC error -32603)" in result["reason"]


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
    goplus.assert_awaited()
    assert data["status"] == "unknown"
    assert data["can_sell"] is None
    assert "Honeypot simulation failed (unresolved)" in data["reason"]


@pytest.mark.asyncio
async def test_a_real_arbitrum_honeypot_is_flagged_although_goplus_reports_it_clean():
    fixture = load("v2_honeypot")
    service = _service_with(fixture, pools={(V2_ROUTES["uniswap-v2"][0], None): fixture["pool"]})
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
    with fresh_addresses(fixture), patch.object(ScamDatabase, "fetch_token_security", new=goplus):
        result = await HoneypotAnalyzer(service).analyze(
            AnalysisContext(fixture["token"], chain_id=42161)
        )
    assert result.data["is_honeypot"] is True
    assert result.data["can_sell"] is False
    assert result.data["field_providers"]["is_honeypot"] == "eth_simulateV1"
    assert result.data["field_providers"]["can_sell"] == "eth_simulateV1"
    assert "Honeypot detected" in result.flags and "Cannot sell token" in result.flags


def _pools_answering(*answers):
    """Two fee tiers resolving to the recorded v3_arb pool, each eth_simulateV1 answered in turn; the
    deepest (first) pool is the 0.05% tier, as discovery keeps candidate order for equal WETH."""
    fixture = load("v3_arb")
    replies = iter(answers)
    rpc = FakeRpc(
        fixture,
        pools={(V3_FACTORY, 500): fixture["pool"], (V3_FACTORY, 3000): fixture["pool"]},
        simulate=lambda index: {**next(replies)["response"], "id": index},
    )
    return fixture, rpc


@pytest.mark.asyncio
async def test_a_shallower_pool_refusing_the_sell_leaves_the_token_unknown_when_the_deepest_pool_sold():
    clean = load("v3_arb")
    fixture, rpc = _pools_answering(clean, failed_sell(clean, error_string("STF")))
    with fresh_addresses(fixture):
        result = await simulator_for(rpc).simulate(fixture["token"])
    # Neither a honeypot (a holder can sell in the deepest pool) nor safe (the shallower pool may trap
    # whoever buys there).
    assert (result["is_honeypot"], result["can_sell"]) == (None, None)
    assert (
        f"not counted as a trap because the pool holding the most WETH, {fixture['pool']}, sold "
        "(sell tax 0%), so sellability is left unknown"
    ) in result["reason"]


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
async def test_a_deepest_pool_selling_at_an_extreme_tax_clears_no_other_pools_trap():
    clean = load("v3_arb")
    assert evaluate(_sell_taxed(clean, 99))["sell_tax"] == 99.0
    fixture, rpc = _pools_answering(_sell_taxed(clean, 99), failed_sell(clean, error_string("STF")))
    with fresh_addresses(fixture):
        result = await simulator_for(rpc).simulate(fixture["token"])
    assert (result["is_honeypot"], result["can_sell"]) == (True, False)


@pytest.mark.asyncio
async def test_a_trapped_deepest_pool_is_not_cleared_by_a_shallower_clean_one():
    clean = load("v3_arb")
    fixture, rpc = _pools_answering(failed_sell(clean, error_string("STF")), clean)
    with fresh_addresses(fixture):
        result = await simulator_for(rpc).simulate(fixture["token"])
    assert (result["is_honeypot"], result["can_sell"]) == (True, False)


@pytest.mark.asyncio
async def test_only_a_clean_deepest_pool_clears_another_pools_trap():
    clean = load("v3_arb")
    buy_reverted = copy.deepcopy(clean)
    make_revert(calls_by_label(buy_reverted)["buy"], error_string("STF"))
    fixture, rpc = _pools_answering(buy_reverted, failed_sell(clean, error_string("STF")))
    with fresh_addresses(fixture):
        result = await simulator_for(rpc).simulate(fixture["token"])
    assert (result["is_honeypot"], result["can_sell"]) == (True, False)
