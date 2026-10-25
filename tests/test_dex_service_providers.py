"""DexService's per chain provider hook: BOT Chain (677) reads BDEX through BotChainMarket, and every
chain with a DexScreener slug still reads DexScreener exactly as before.

The BDEX replies are the recorded fixtures served by tests/test_botchain_market.py's stub; the
DexScreener replies are tests/fixtures/dexscreener_replies.json. Nothing touches the network.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import services.botchain_market as botchain_market
import services.dex_service as dex_service
from core.unknown_ledger import UnknownLedger
from services.botchain_market import BotChainMarket
from services.dex_service import MARKET_PROVIDERS, DexService
from tests.test_botchain_market import API, COW, PRICES, RPC, ZERO, Clock, Response, Server
from utils.chain_info import CHAIN_INFO

REPLIES = json.loads(
    (Path(__file__).parent / "fixtures" / "dexscreener_replies.json").read_text(
        encoding="utf-8"
    )
)
DEXSCREENER_CHAINS = sorted(
    chain for chain, info in CHAIN_INFO.items() if info["dexscreener_slug"]
)
USDT_ETHEREUM = "0xdAC17F958D2ee523a2206206994597C13D831ec7"


@pytest.fixture
def ledger(monkeypatch):
    fresh = UnknownLedger()
    monkeypatch.setattr("services.dex_service.unknown_ledger", fresh)
    return fresh


@pytest.fixture
def clock(monkeypatch):
    fake = Clock()
    monkeypatch.setattr(botchain_market, "time", fake)
    monkeypatch.setattr(botchain_market, "RETRY_BACKOFF_SECONDS", 0)
    return fake


def dexscreener_session(replies=REPLIES):
    """A DexScreener that serves ``replies`` by URL and 404 for any other URL."""
    session = MagicMock()

    def get(url, **kwargs):
        response = MagicMock(status=200 if url in replies else 404)
        response.json = AsyncMock(return_value=replies.get(url))
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=response)
        context.__aexit__ = AsyncMock(return_value=False)
        return context

    session.get.side_effect = get
    client = MagicMock()
    client.return_value.__aenter__ = AsyncMock(return_value=session)
    client.return_value.__aexit__ = AsyncMock(return_value=False)
    return client, session


async def botchain(service, address, server=None):
    # Both modules share one aiohttp, so the stub sees every request either of them sends.
    server = server or Server()
    with patch("services.botchain_market.aiohttp.ClientSession", server.session()):
        result = await service.fetch_token_market_data(address, chain_id=677)
    return result, server


def test_the_provider_map_names_only_bot_chain():
    assert MARKET_PROVIDERS == {677: BotChainMarket}
    assert CHAIN_INFO[677]["dexscreener_slug"] is None
    assert 677 not in DEXSCREENER_CHAINS and len(DEXSCREENER_CHAINS) == 8


@pytest.mark.asyncio
async def test_bot_chain_reads_bdex_not_dexscreener(clock, ledger):
    result, server = await botchain(DexService(), COW)

    assert server.gets and all(url.startswith(API) for url, _ in server.gets)
    assert not any("dexscreener" in url for url, _ in server.gets)
    assert result["price_usd"] == float(PRICES[COW]["data"]["price"])
    assert result["liquidity_usd"] == pytest.approx(188.19, abs=0.01)
    assert result["status"] == "ok"
    assert "DexScreener" not in json.dumps(result)
    assert ledger.for_chain(677)["bdex"]["answered"] == 1
    assert "dexscreener" not in ledger.for_chain(677)


@pytest.mark.asyncio
async def test_bot_chain_token_in_no_pool_counts_as_unknown(clock, ledger):
    result, _ = await botchain(DexService(), ZERO)

    assert result["reason"] == "No BDEX pools for this token on BOT Chain"
    entry = ledger.for_chain(677)["bdex"]
    assert (entry["answered"], entry["unknown"], entry["failed"]) == (0, 1, 0)


@pytest.mark.asyncio
async def test_bot_chain_with_every_source_down_counts_as_failed(clock, ledger):
    server = Server()
    server.get_fault = lambda url, params: Response(503, None)
    server.rpc_fault = lambda body: Response(503, None)
    result, _ = await botchain(DexService(), COW, server)

    assert result["status"] == "unknown"
    assert not any(result["coverage"].values())
    entry = ledger.for_chain(677)["bdex"]
    assert (entry["answered"], entry["unknown"], entry["failed"]) == (0, 0, 1)


@pytest.mark.asyncio
async def test_one_provider_serves_every_scan_so_its_caches_hold(clock, ledger):
    service = DexService()
    _, cold = await botchain(service, COW)
    clock.advance(30)
    _, warm = await botchain(service, COW)

    assert cold.methods().count("eth_getLogs") == 2
    assert warm.methods().count("eth_getLogs") == 0
    assert warm.gets == []


@pytest.mark.asyncio
async def test_the_bot_chain_rpc_url_comes_from_the_environment(clock, monkeypatch):
    monkeypatch.setenv("BOTCHAIN_RPC_URL", "http://127.0.0.1:8545")
    service = DexService()
    with patch.object(
        BotChainMarket,
        "token_market",
        AsyncMock(
            return_value={
                "coverage": {"price_usd": True},
                "reason": None,
            }
        ),
    ):
        await service.fetch_token_market_data(COW, chain_id=677)
    assert service._providers[677]._rpc_url == "http://127.0.0.1:8545"

    monkeypatch.delenv("BOTCHAIN_RPC_URL")
    default = DexService()
    with patch.object(
        BotChainMarket,
        "token_market",
        AsyncMock(
            return_value={
                "coverage": {"price_usd": True},
                "reason": None,
            }
        ),
    ):
        await default.fetch_token_market_data(COW, chain_id=677)
    assert default._providers[677]._rpc_url == RPC


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", DEXSCREENER_CHAINS)
async def test_every_other_chain_still_reads_dexscreener(chain_id, ledger):
    client, session = dexscreener_session()
    with (
        patch("services.dex_service.aiohttp.ClientSession", client),
        patch.object(
            BotChainMarket,
            "token_market",
            AsyncMock(side_effect=AssertionError("BDEX asked")),
        ),
    ):
        service = DexService()
        result = await service.fetch_token_market_data(USDT_ETHEREUM, chain_id=chain_id)

    slug = CHAIN_INFO[chain_id]["dexscreener_slug"]
    (url,), kwargs = session.get.call_args
    assert url == dex_service.DEX_API_URL.format(chain=slug, address=USDT_ETHEREUM)
    assert kwargs["timeout"].total == 10
    assert service._providers == {}
    assert "bdex" not in ledger.for_chain(chain_id)
    assert "dexscreener" in ledger.for_chain(chain_id)
    assert result["reason"] is None or "DexScreener" in result["reason"]


@pytest.mark.asyncio
async def test_usdt_on_ethereum_reads_the_same_as_before_the_hook(ledger):
    client, _ = dexscreener_session()
    with patch("services.dex_service.aiohttp.ClientSession", client):
        result = await DexService().fetch_token_market_data(USDT_ETHEREUM, 1)

    # The figures tests/test_dexscreener_pairs.py pins for the same recorded reply.
    assert result["liquidity_usd"] == 50152955.91
    assert result["low_liquidity_flag"] is False
    assert ledger.for_chain(1)["dexscreener"]["answered"] == 1
