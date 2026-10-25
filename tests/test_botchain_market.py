"""BOT Chain (677) market data from BDEX: the full pool inventory from the factory logs, API and on
chain amounts, prices, liquidity, volume, pair age and fdv, and every failure read as Unknown.

fixtures/botchain_market/ holds live replies recorded on 2026-10-25 at block 0x1aa49ea
(RECORDING.md). The stub below serves them by URL and by JSON-RPC request; any request it holds no
reply for is a 404 or a JSON-RPC error, so nothing here touches the network.
"""

import asyncio
import copy
import inspect
import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import aiohttp
import pytest

import services.botchain_market as botchain_market
from analyzers.market import MarketAnalyzer
from core.analyzer import AnalysisContext
from services.botchain_market import (
    POOL_CREATED_TOPIC,
    PAIR_CREATED_TOPIC,
    REQUIRED,
    USDT,
    V2_FACTORY,
    V3_FACTORY,
    BotChainMarket,
    parse_price_reply,
)
from services.dex_service import DexService

FIXTURES = Path(__file__).parent / "fixtures" / "botchain_market"
API = "https://dex-wallet.botchain.ai/api/v1"
RPC = "https://rpc.botchain.ai"
WBOT = "0xd5452816194a3784dba983426cce7c122f4abd30"
COW = "0x5af9a0e7472134a6a5ad02a7d327e83ddd24b337"
COW_WBOT = "0x27bfc83a0fc9352a03ac92096c3dde1fcf3f6542"
COW_USDT = "0x8cdd0050c7ba9231c9ca65dac73f3375086acad2"
USDT_WBOT_V3 = "0x64f418471a1a7932a190e10da5a8551db5abec05"
LK2E = "0x04bbf9ec920e8996bb96e5c451f621e5df6d9999"
LK2E_PAIR = "0xc47bf4f4f34ee9cb19e0bd3c39ad981e4b745221"
KKFJ = "0x4a287f66aba5f6219463312a79319ec2b7ff65c5"
NQDA = "0x94566c45bbd0cfb286a7b1402ac6f43e2368dce1"
OMITTED_V3 = "0x7453653eb8bfaf4e78e46df3466bcaeb4dd0db27"
ZERO = "0x" + "0" * 40
# A recorded block timestamp plus a fixed offset, so pair ages are exact.
NOW = 1792930000.0


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


POOLS = {1: load("api_pools_page1.json"), 2: load("api_pools_page2.json")}
PAIRS = load("api_pairs_all.json")
PRICES = load("api_price.json")
PAIR_LOGS = load("logs_pair_created.json")
POOL_LOGS = load("logs_pool_created.json")
CALLS = {
    (row["to"], row["data"]): row["reply"] for row in load("eth_call.json")["calls"]
}
BLOCKS = load("blocks.json")
UNSUPPORTED = load("rpc_unsupported.json")


def listed(pool):
    return next(row for row in POOLS[1]["data"] if row["poolId"] == pool)


def call_result(to, data):
    return CALLS[(to, data)]["result"]


def block_time(pool_block):
    return int(BLOCKS[pool_block]["result"]["timestamp"], 16)


class Clock:
    def __init__(self):
        self.now = NOW
        self.mono = 1000.0

    def time(self):
        return self.now

    def monotonic(self):
        return self.mono

    def advance(self, seconds):
        self.now += seconds
        self.mono += seconds


class Response:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    async def json(self, content_type="application/json"):
        if isinstance(self._body, Exception):
            raise self._body
        return copy.deepcopy(self._body)


class Request:
    def __init__(self, server, response):
        self._server = server
        self._response = response

    async def __aenter__(self):
        self._server.active += 1
        self._server.peak = max(self._server.peak, self._server.active)
        await asyncio.sleep(0)
        self._server.active -= 1
        if isinstance(self._response, BaseException):
            raise self._response
        return self._response

    async def __aexit__(self, *exc):
        return False


class Server:
    """Serves the recorded replies. ``get_fault`` and ``rpc_fault`` may answer a request instead:
    they return a Response, an exception to raise, or None to serve the recording."""

    def __init__(
        self, pools=POOLS, prices=PRICES, pair_logs=PAIR_LOGS, pool_logs=POOL_LOGS
    ):
        self.pools = pools
        self.prices = prices
        self.pair_logs = pair_logs
        self.pool_logs = pool_logs
        self.gets = []
        self.posts = []
        self.timeouts = []
        self.active = 0
        self.peak = 0
        self.get_fault = None
        self.rpc_fault = None

    def session(self):
        session = MagicMock()
        session.get.side_effect = self.get
        session.post.side_effect = self.post
        client = MagicMock()
        client.return_value.__aenter__.return_value = session
        client.return_value.__aexit__.return_value = False
        return client

    def get(self, url, timeout=None, params=None, **kwargs):
        self.timeouts.append(timeout)
        self.gets.append((url, dict(params or {})))
        fault = self.get_fault(url, params or {}) if self.get_fault else None
        if fault is not None:
            return Request(self, fault)
        if url == f"{API}/pools" and params["page_num"] in self.pools:
            return Request(self, Response(200, self.pools[params["page_num"]]))
        if url == f"{API}/price" and params["token"] in self.prices:
            return Request(self, Response(200, self.prices[params["token"]]))
        return Request(self, Response(404, None))

    def post(self, url, timeout=None, json=None, **kwargs):
        self.timeouts.append(timeout)
        self.posts.append(json)
        assert url == RPC
        fault = self.rpc_fault(json) if self.rpc_fault else None
        if fault is not None:
            return Request(self, fault)
        return Request(self, Response(200, [self.answer(row) for row in json]))

    def answer(self, row):
        method, params = row["method"], row["params"]
        reply = None
        if method == "eth_getLogs":
            reply = {V2_FACTORY: self.pair_logs, V3_FACTORY: self.pool_logs}.get(
                params[0]["address"]
            )
        elif method == "eth_call":
            reply = CALLS.get((params[0]["to"], params[0]["data"]))
        elif method == "eth_getBlockByNumber":
            reply = BLOCKS.get(params[0])
        if reply is None:
            reply = {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "not recorded"},
            }
        return {**copy.deepcopy(reply), "id": row["id"]}

    def methods(self):
        return [row["method"] for body in self.posts for row in body]

    def prices_asked(self):
        return [params["token"] for url, params in self.gets if url == f"{API}/price"]


@pytest.fixture
def clock(monkeypatch):
    fake = Clock()
    monkeypatch.setattr(botchain_market, "time", fake)
    monkeypatch.setattr(botchain_market, "RETRY_BACKOFF_SECONDS", 0)
    return fake


async def scan(token, server=None, market=None):
    server = server or Server()
    market = market or BotChainMarket(RPC)
    with patch("services.botchain_market.aiohttp.ClientSession", server.session()):
        result = await market.token_market(token)
    return result, server


def inventory_pools():
    pairs = [("0x" + log["data"][26:66], "v2") for log in PAIR_LOGS["result"]]
    pools = [("0x" + log["data"][-40:], "v3") for log in POOL_LOGS["result"]]
    return pairs, pools


# Inventory (M8)


@pytest.mark.asyncio
async def test_inventory_finds_every_pair_and_pool_from_the_factory_logs(clock):
    market = BotChainMarket(RPC)
    server = Server()
    with patch("services.botchain_market.aiohttp.ClientSession", server.session()):
        async with aiohttp.ClientSession() as session:
            inventory, fresh, note = await market._read_inventory(session)

    assert fresh is True and note is None
    v2 = {pool.address for pool in inventory if pool.kind == "v2"}
    v3 = {pool.address for pool in inventory if pool.kind == "v3"}
    pairs, pools = inventory_pools()
    assert len(v2) == 83 and v2 == {address for address, _ in pairs}
    assert len(v3) == 24 and v3 == {address for address, _ in pools}
    # Two log queries, each filtered by its factory and its event over the full range.
    queries = [row["params"][0] for body in server.posts for row in body]
    assert queries == [
        {
            "address": V2_FACTORY,
            "topics": [PAIR_CREATED_TOPIC],
            "fromBlock": "0x0",
            "toBlock": "latest",
        },
        {
            "address": V3_FACTORY,
            "topics": [POOL_CREATED_TOPIC],
            "fromBlock": "0x0",
            "toBlock": "latest",
        },
    ]
    assert PAIR_CREATED_TOPIC == PAIR_LOGS["result"][0]["topics"][0]
    assert POOL_CREATED_TOPIC == POOL_LOGS["result"][0]["topics"][0]


def test_the_api_lists_53_of_the_107_pools_and_each_maps_onto_the_logs():
    pairs, pools = inventory_pools()
    inventory = dict(pairs + pools)
    api = {row["poolId"]: row["poolType"] for row in POOLS[1]["data"]}
    assert POOLS[1]["meta"]["total"] == 53 and POOLS[2]["data"] == []
    assert {row["pair"] for row in PAIRS["data"]} == set(api)
    assert all(inventory[pool] == kind for pool, kind in api.items())
    omitted = set(inventory) - set(api)
    assert sum(inventory[pool] == "v2" for pool in omitted) == 53
    assert {pool for pool in omitted if inventory[pool] == "v3"} == {OMITTED_V3}


@pytest.mark.asyncio
async def test_every_omitted_v2_pair_of_a_token_is_read_on_chain(clock):
    result, server = await scan(WBOT)

    calls = {
        (row["params"][0]["to"], row["params"][0]["data"])
        for body in server.posts
        for row in body
        if row["method"] == "eth_call"
    }
    api = {row["poolId"] for row in POOLS[1]["data"]}
    wbot_pairs = [
        log for log in PAIR_LOGS["result"] if WBOT[2:] in "".join(log["topics"])
    ]
    omitted = {"0x" + log["data"][26:66] for log in wbot_pairs} - api
    assert len(wbot_pairs) == 67 and len(omitted) == 53
    assert {(pair, "0x0902f1ac") for pair in omitted} <= calls
    assert not any(to in api and data == "0x0902f1ac" for to, data in calls)
    # WBOT's on chain batch is larger than one request's limit.
    assert sum(1 for body in server.posts if body[0]["method"] == "eth_call") >= 2
    assert all(len(body) <= botchain_market.RPC_BATCH_SIZE for body in server.posts)


@pytest.mark.asyncio
async def test_the_v3_pool_the_api_omits_is_read_on_chain(clock):
    result, server = await scan(NQDA)

    calls = {
        (row["params"][0]["to"], row["params"][0]["data"])
        for body in server.posts
        for row in body
        if row["method"] == "eth_call"
    }
    assert (OMITTED_V3, "0x1a686502") in calls
    for side in (NQDA, WBOT):
        assert (side, "0x70a08231" + OMITTED_V3[2:].rjust(64, "0")) in calls
    # liquidity() is 0 and both balances are 0: the pool is measured empty.
    assert int(call_result(OMITTED_V3, "0x1a686502"), 16) == 0
    assert result["liquidity_usd"] == 0.0
    assert result["low_liquidity_flag"] is True
    assert result["price_usd"] is None
    assert result["volume_24h"] is None
    assert result["pair_age_hours"] == round((NOW - block_time("0x18944dd")) / 3600, 1)
    assert result["status"] == "unknown"


# Tokens with recorded markets


@pytest.mark.asyncio
async def test_cow_liquidity_and_age_come_from_its_wbot_pair_and_its_usdt_pair_is_valued(
    clock,
):
    result, server = await scan(COW)

    cow_price = float(PRICES[COW]["data"]["price"])
    wbot_price = float(PRICES[WBOT]["data"]["price"])
    wbot_pool, usdt_pool = listed(COW_WBOT), listed(COW_USDT)
    wbot_value = (
        float(wbot_pool["token0Amount"]) * cow_price
        + float(wbot_pool["token1Amount"]) * wbot_price
    )
    usdt_value = float(usdt_pool["token0Amount"]) * cow_price + float(
        usdt_pool["token1Amount"]
    )
    assert wbot_value > usdt_value
    assert result["liquidity_usd"] == pytest.approx(wbot_value)
    assert result["liquidity_usd"] == pytest.approx(188.19, abs=0.01)
    # The API's own value of the pool agrees within 1%.
    assert result["liquidity_usd"] == pytest.approx(
        float(wbot_pool["fdvUsd"]), rel=0.01
    )
    assert result["pair_age_hours"] == round((NOW - block_time("0xb7c6d4")) / 3600, 1)
    assert result["price_usd"] == cow_price
    assert result["volume_24h"] == 0.0
    assert result["token_name"] == "Cow Coin" and result["token_symbol"] == "COW"
    assert result["low_liquidity_flag"] is True
    assert result["new_pair_flag"] is False
    assert result["wash_trade_flag"] is False
    assert result["status"] == "ok"
    assert all(result["coverage"].values())
    assert result["reason"] == "Missing BDEX fields: price_change_24h"
    assert sorted(server.prices_asked()) == sorted([COW, WBOT])
    assert server.methods().count("eth_getBlockByNumber") == 1


@pytest.mark.asyncio
async def test_fdv_is_total_supply_times_price_never_the_apis_pool_value(clock):
    result, _ = await scan(COW)

    supply = int(call_result(COW, "0x18160ddd"), 16) / 10 ** int(
        call_result(COW, "0x313ce567"), 16
    )
    assert result["fdv"] == pytest.approx(supply * float(PRICES[COW]["data"]["price"]))
    assert result["fdv"] not in {
        float(listed(COW_WBOT)["fdvUsd"]),
        float(listed(COW_USDT)["fdvUsd"]),
    }


@pytest.mark.asyncio
async def test_usdt_deepest_pool_is_the_v3_3000_pool_and_usdt_is_one_dollar(clock):
    result, server = await scan(USDT)

    pool = listed(USDT_WBOT_V3)
    assert pool["poolType"] == "v3" and pool["feeTier"] == "3000"
    expected = float(pool["token0Amount"]) + float(pool["token1Amount"]) * float(
        PRICES[WBOT]["data"]["price"]
    )
    assert result["liquidity_usd"] == pytest.approx(expected)
    assert result["liquidity_usd"] > 31_000_000
    assert result["pair_age_hours"] == round((NOW - block_time("0x104427")) / 3600, 1)
    assert result["price_usd"] == 1.0
    assert USDT not in server.prices_asked()
    assert result["fdv"] == pytest.approx(73_960_200.0)


# Volume (M8)


@pytest.mark.asyncio
async def test_one_pool_without_volume_makes_the_tokens_volume_unknown(clock):
    pools = copy.deepcopy(POOLS)
    row = next(row for row in pools[1]["data"] if row["poolId"] == COW_USDT)
    del row["volumeUsd24"]
    result, _ = await scan(COW, Server(pools=pools))

    assert result["volume_24h"] is None
    assert result["wash_trade_flag"] is None
    assert result["coverage"]["volume_24h"] is False
    assert result["status"] == "unknown"
    assert "24h volume unknown: no BDEX volume for 1 of 2 pools" in result["reason"]


@pytest.mark.asyncio
async def test_an_omitted_pool_has_no_volume_so_wbots_volume_is_unknown(clock):
    result, _ = await scan(WBOT)

    assert result["volume_24h"] is None
    assert "24h volume unknown: no BDEX volume for 54 of 86 pools" in result["reason"]


# Prices (m1)


@pytest.mark.parametrize(
    "token,expected",
    [
        (WBOT, float(PRICES[WBOT]["data"]["price"])),
        (COW, float(PRICES[COW]["data"]["price"])),
        (USDT, 1.0),
        (LK2E, None),
        (ZERO, None),
        (KKFJ, None),
    ],
)
def test_recorded_price_replies(token, expected):
    assert parse_price_reply(PRICES[token], token) == expected


def test_usdt_path_of_length_one_is_one_dollar_and_lk2e_is_unpriced():
    assert PRICES[USDT]["data"]["path"] == [USDT]
    assert PRICES[LK2E]["data"]["price"] == "0" and PRICES[LK2E]["data"]["path"] == []
    assert PRICES[LK2E]["success"] is True


def mutated(**changes):
    answer = copy.deepcopy(PRICES[WBOT])
    answer["data"].update(changes)
    return answer


@pytest.mark.parametrize(
    "answer",
    [
        mutated(token=COW),
        mutated(path=[WBOT]),
        mutated(path=[]),
        mutated(path="0xababc7ddc03e501d190c676bf3d92ef0e6e87a3c"),
        mutated(price="0"),
        mutated(price="-1"),
        mutated(price="NaN"),
        mutated(price="inf"),
        mutated(price=True),
        mutated(price=None),
        mutated(price="twelve"),
        {**PRICES[WBOT], "success": False},
        {"success": True, "data": None},
        None,
        [],
    ],
)
def test_price_reply_fails_closed(answer):
    assert parse_price_reply(answer, WBOT) is None


@pytest.mark.asyncio
async def test_an_unpriced_token_has_no_price_and_its_pool_no_liquidity(clock):
    result, _ = await scan(KKFJ)

    reserves = call_result("0x24d27a096cbedcb71f4953ea0592e64108044b3d", "0x0902f1ac")
    assert int(reserves[2:66], 16) > 0
    assert result["price_usd"] is None
    assert result["liquidity_usd"] is None
    assert result["low_liquidity_flag"] is None
    assert result["fdv"] is None
    assert (
        "Price unknown: BDEX prices no route from this token to USDT"
        in result["reason"]
    )
    assert "1 of 1 BDEX pools could not be valued" in result["reason"]


@pytest.mark.asyncio
async def test_an_empty_pair_is_worth_nothing_without_a_price_request(clock):
    result, server = await scan(LK2E)

    assert int(call_result(LK2E_PAIR, "0x0902f1ac")[2:130], 16) == 0
    assert server.prices_asked() == [LK2E]
    assert result["price_usd"] is None
    assert result["liquidity_usd"] == 0.0
    assert result["pair_age_hours"] == round((NOW - block_time("0x1a43f3d")) / 3600, 1)


@pytest.mark.asyncio
async def test_a_token_in_no_pool_is_the_no_pairs_unknown(clock):
    result, _ = await scan(ZERO)

    assert result["status"] == "unknown"
    assert result["reason"] == "No BDEX pools for this token on BOT Chain"
    assert result["coverage"] == {field: False for field in REQUIRED}
    assert all(result[field] is None for field in botchain_market.METRICS)


# Failures read as Unknown, never raised


@pytest.mark.asyncio
async def test_api_down_leaves_price_liquidity_and_volume_unknown(clock):
    server = Server()
    server.get_fault = lambda url, params: Response(503, None)
    result, _ = await scan(COW, server)

    assert result["price_usd"] is None
    assert result["liquidity_usd"] is None
    assert result["volume_24h"] is None
    assert result["fdv"] is None
    # The inventory and the on chain reads still answered.
    assert result["pair_age_hours"] is None
    assert result["status"] == "unknown"
    assert "BDEX pools list unavailable: BDEX pools API HTTP 503" in result["reason"]
    assert "Price unknown: BDEX price API HTTP 503" in result["reason"]


@pytest.mark.asyncio
async def test_pools_list_down_reads_the_amounts_on_chain(clock):
    server = Server()
    server.get_fault = lambda url, params: (
        Response(503, None) if url.endswith("/pools") else None
    )
    result, server = await scan(COW, server)

    reserves = call_result(COW_WBOT, "0x0902f1ac")
    on_chain = int(reserves[2:66], 16) / 1e18 * float(PRICES[COW]["data"]["price"]) + (
        int(reserves[66:130], 16) / 1e18 * float(PRICES[WBOT]["data"]["price"])
    )
    assert result["liquidity_usd"] == pytest.approx(on_chain)
    assert result["liquidity_usd"] == pytest.approx(
        float(listed(COW_WBOT)["fdvUsd"]), rel=0.01
    )
    assert result["volume_24h"] is None
    assert result["price_usd"] is not None


@pytest.mark.asyncio
async def test_a_pools_page_that_adds_no_pool_ends_the_read(clock):
    pools = copy.deepcopy(POOLS)
    pools[1]["meta"]["total"] = 200
    pools[2] = pools[1]
    pools[3] = pools[1]
    result, server = await scan(COW, Server(pools=pools))

    assert sum(url.endswith("/pools") for url, _ in server.gets) == 2
    assert result["volume_24h"] is None
    assert "BDEX pools list unavailable: BDEX pools API listed 53 of 200 pools" in result["reason"]


@pytest.mark.asyncio
async def test_rpc_timeout_is_unknown_and_not_asked_again(clock):
    server = Server()
    server.rpc_fault = lambda body: asyncio.TimeoutError()
    result, server = await scan(COW, server)

    assert result["liquidity_usd"] is None
    assert result["pair_age_hours"] is None
    assert result["fdv"] is None
    assert result["price_usd"] == float(PRICES[COW]["data"]["price"])
    assert result["status"] == "unknown"
    assert "BDEX pool list unavailable: BOT Chain RPC timed out" in result["reason"]
    # Two log queries and one metadata batch, none repeated.
    assert len(server.posts) == 3


@pytest.mark.asyncio
async def test_a_429_is_asked_once_more_then_answers(clock):
    server = Server()
    seen = []

    def once(url, params):
        if url.endswith("/pools") and not seen:
            seen.append(url)
            return Response(429, None)
        return None

    server.get_fault = once
    result, server = await scan(COW, server)

    assert result["status"] == "ok"
    assert sum(url.endswith("/pools") for url, _ in server.gets) == 2


@pytest.mark.asyncio
async def test_a_429_twice_is_rate_limited_unknown(clock):
    server = Server()
    server.get_fault = lambda url, params: (
        Response(429, None) if url.endswith("/price") else None
    )
    result, server = await scan(COW, server)

    assert result["price_usd"] is None
    assert "Price unknown: BDEX price API rate limited (HTTP 429)" in result["reason"]
    assert server.prices_asked().count(COW) == 2


@pytest.mark.asyncio
async def test_a_connection_error_is_asked_once_more(clock):
    server = Server()
    failures = []

    def drop(body):
        if not failures:
            failures.append(body)
            return aiohttp.ClientConnectionError("reset")
        return None

    server.rpc_fault = drop
    result, server = await scan(COW, server)

    assert result["status"] == "ok"
    assert server.posts.count(failures[0]) == 2


@pytest.mark.asyncio
async def test_an_unsupported_log_method_is_unknown(clock):
    server = Server()

    def unsupported(body):
        if body[0]["method"] == "eth_getLogs":
            return Response(200, [{**UNSUPPORTED, "id": row["id"]} for row in body])
        return None

    server.rpc_fault = unsupported
    result, _ = await scan(COW, server)

    assert result["liquidity_usd"] is None
    assert result["volume_24h"] is None
    assert (
        "BDEX pool list unavailable: BOT Chain RPC does not support eth_getLogs"
        in result["reason"]
    )


@pytest.mark.asyncio
async def test_an_unexpected_error_is_unknown_not_raised(clock):
    client = MagicMock(side_effect=RuntimeError("boom"))
    with patch("services.botchain_market.aiohttp.ClientSession", client):
        result = await BotChainMarket(RPC).token_market(COW)

    assert result["status"] == "unknown"
    assert result["reason"] == "BDEX market read failed: RuntimeError"
    assert result["coverage"] == {field: False for field in REQUIRED}


# Caches and bounds (M9, F4)


@pytest.mark.asyncio
async def test_warm_caches_skip_the_logs_the_pools_list_and_the_dating(clock):
    market = BotChainMarket(RPC)
    _, cold = await scan(COW, market=market)
    clock.advance(30)
    warm_result, warm = await scan(COW, market=market)

    assert cold.methods().count("eth_getLogs") == 2
    assert sum(url.endswith("/pools") for url, _ in cold.gets) == 1
    assert len(cold.gets) + len(cold.posts) == 7
    assert warm.methods().count("eth_getLogs") == 0
    assert "eth_getBlockByNumber" not in warm.methods()
    assert not any(url.endswith("/pools") for url, _ in warm.gets)
    assert len(warm.gets) + len(warm.posts) == 3
    assert warm_result["status"] == "ok"

    clock.advance(31)
    _, later = await scan(COW, market=market)
    assert sum(url.endswith("/pools") for url, _ in later.gets) == 1
    assert later.methods().count("eth_getLogs") == 0


@pytest.mark.asyncio
async def test_a_failed_refresh_keeps_the_old_pool_list_and_dates_nothing_new(clock):
    market = BotChainMarket(RPC)
    await scan(COW, market=market)
    clock.advance(601)
    server = Server()
    server.rpc_fault = lambda body: (
        Response(503, None) if body[0]["method"] == "eth_getLogs" else None
    )

    cow, server = await scan(COW, server, market=market)
    assert cow["liquidity_usd"] == pytest.approx(188.19, abs=0.01)
    assert cow["pair_age_hours"] is not None
    assert (
        "BDEX pool list refresh failed (BOT Chain RPC HTTP 503); using the list read 10 min earlier"
        in cow["reason"]
    )

    usdt, server = await scan(USDT, server, market=market)
    assert usdt["liquidity_usd"] > 31_000_000
    assert usdt["pair_age_hours"] is None
    assert (
        "Pair age unknown: the pool was not dated before the pool list refresh failed"
        in usdt["reason"]
    )
    assert "eth_getBlockByNumber" not in server.methods()


@pytest.mark.asyncio
async def test_every_request_has_a_10_second_timeout_and_two_run_at_once(clock):
    _, server = await scan(USDT)

    assert server.timeouts and all(timeout.total == 10 for timeout in server.timeouts)
    assert server.peak == 2


# Shape and honesty (m2, B1, M13)


@pytest.mark.asyncio
async def test_the_result_has_dex_services_keys_and_the_analyzer_reads_it(clock):
    with patch("services.dex_service.get_dexscreener_slug", return_value=None):
        dexscreener = await DexService().fetch_token_market_data(COW, 677)
    result, _ = await scan(COW)

    assert set(result) == set(dexscreener)
    assert set(result["coverage"]) == set(dexscreener["coverage"])

    service = MagicMock()

    async def fetch(address, chain_id):
        return result

    service.fetch_token_market_data = fetch
    analysis = await MarketAnalyzer(service).analyze(
        AnalysisContext(address=COW, chain_id=677, is_token=True)
    )
    assert "Low liquidity (<$10k)" in analysis.flags
    assert analysis.data["notes"] == [
        "Volatility unknown: 24h price change unavailable"
    ]


@pytest.mark.asyncio
async def test_no_field_comes_from_holder_data(clock):
    _, server = await scan(USDT)

    assert all(url.startswith(API) for url, _ in server.gets)
    assert not any("holder" in url for url, _ in server.gets)
    assert "holders" not in inspect.getsource(botchain_market).lower().replace(
        "no holder data", ""
    )
    assert "scan.botchain.ai" not in inspect.getsource(botchain_market)


@pytest.mark.asyncio
async def test_no_string_says_safe(clock):
    scenarios = []
    for token in (COW, USDT, LK2E, KKFJ, ZERO, NQDA):
        scenarios.append((await scan(token))[0])
    down = Server()
    down.get_fault = lambda url, params: Response(503, None)
    down.rpc_fault = lambda body: asyncio.TimeoutError()
    scenarios.append((await scan(COW, down))[0])

    for result in scenarios:
        assert "safe" not in json.dumps(result).lower()
    literals = re.findall(r"[\"']([^\"']*)[\"']", inspect.getsource(botchain_market))
    assert not any("safe" in literal.lower() for literal in literals)
