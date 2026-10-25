"""BOT Chain (677) BDEX buy/sell simulation: the contracts and limits, pool aware sizing, discovery, RPC
failures and the lane."""

import ast
import asyncio
import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from eth_abi import encode
from eth_utils import keccak

import services.botchain_simulation as botchain_simulation
from adapters.robinhood import SIMULATION_PROVIDER
from services.botchain_simulation import (
    BUY_CAP_WEI,
    CHAIN_ID,
    EXACT_SINGLE,
    MAX_POOLS,
    MIN_POOL_DEPTH_WEI,
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
    _pool_swap,
    buy_amount,
)
from services.robinhood_simulation import SIM_RPC_TIMEOUT_SECONDS

FIELDS = ("is_honeypot", "buy_tax", "sell_tax", "can_buy", "can_sell")
ZERO_WORD = "0x" + "0" * 64
BASE_BLOCK = 0x1AA4E80
BASE_TIME = 1792938251
COW = "0x5af9a0e7472134a6a5ad02a7d327e83ddd24b337"


def _word(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def _address_word(address: str) -> str:
    return "0x" + "0" * 24 + address[2:]


def simulator_for(post, **kwargs):
    simulator = BotChainSimulator(**kwargs)
    simulator._post = post
    return simulator


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


# --- RPC failures: Unknown, with a note naming them, and no retry ----------------------------------


@pytest.mark.asyncio
async def test_a_discovery_timeout_is_unknown_and_not_retried():
    post = AsyncMock(side_effect=asyncio.TimeoutError())
    result = await simulator_for(post).simulate(COW)
    assert all(result[field] is None for field in FIELDS)
    assert result["rpc_failed"] is True
    assert result["reason"] == f"RPC request timed out after {RPC_TIMEOUT_SECONDS} s"
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
