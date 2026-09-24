"""DexService reads a token's market from its own pools on the requested chain.

fixtures/dexscreener_replies.json holds replies served by https://api.dexscreener.com on
2026-09-24 (GET, no key), keyed by URL. Each list of pairs is trimmed to a few pairs, kept in the
order served, and to the fields DexService reads. The latest/dex/tokens replies are what the
unscoped route served for the same tokens, so a return to it fails here on the data that caused
the bug.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.unknown_ledger import UnknownLedger
from services.dex_service import DexService

REPLIES = json.loads(
    (Path(__file__).parent / "fixtures" / "dexscreener_replies.json").read_text(encoding="utf-8")
)
API = "https://api.dexscreener.com"
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
# The approved token in the landing page's honeypot capture; DexScreener lists no pair for it.
HONEYPOT = "0xdbda907a02750f79cbf0414f7112eabe5091c286"


@pytest.fixture
def ledger(monkeypatch):
    fresh = UnknownLedger()
    monkeypatch.setattr("services.dex_service.unknown_ledger", fresh)
    return fresh


def counts(ledger, chain_id):
    entry = ledger.for_chain(chain_id)["dexscreener"]
    return {outcome: entry[outcome] for outcome in ("answered", "unknown", "failed")}


async def market(address, chain_id, replies=REPLIES):
    """The market data DexService reads from a DexScreener that serves ``replies`` by URL and 404
    for any other URL, with the URLs it asked."""
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
    with patch("services.dex_service.aiohttp.ClientSession", client):
        result = await DexService().fetch_token_market_data(address, chain_id)
    return result, [call.args[0] for call in session.get.call_args_list]


@pytest.mark.asyncio
async def test_usdt_on_ethereum_is_read_from_its_ethereum_pools(ledger):
    # Asked by address alone, DexScreener served 30 pairs from every chain, 28 of them on
    # PulseChain, whose genesis copied Ethereum's state so the same address is another token
    # there. The two Ethereum pairs left held under $1,000, so USDT read as low liquidity.
    result, asked = await market(USDT, 1)

    assert result["liquidity_usd"] == 50152955.91
    assert result["low_liquidity_flag"] is False
    assert asked == [f"{API}/token-pairs/v1/ethereum/{USDT}"]
    assert counts(ledger, 1) == {"answered": 1, "unknown": 0, "failed": 0}


@pytest.mark.asyncio
async def test_a_token_without_pools_on_the_chain_stays_unknown(ledger):
    result, asked = await market(HONEYPOT, 56)

    assert asked == [f"{API}/token-pairs/v1/bsc/{HONEYPOT}"]
    assert result["status"] == "unknown"
    assert result["reason"] == "No DexScreener pairs on requested chain (bsc)"
    assert result["liquidity_usd"] is None
    assert result["low_liquidity_flag"] is None
    assert counts(ledger, 56) == {"answered": 0, "unknown": 1, "failed": 0}


@pytest.mark.asyncio
async def test_the_deepest_pool_without_a_creation_time_leaves_pair_age_unknown(ledger):
    # WBNB's deepest BSC pool, $80M of WBNB/USDT, carries no pairCreatedAt.
    result, _ = await market(WBNB, 56)

    assert result["liquidity_usd"] == 79985391.73
    assert result["pair_age_hours"] is None
    assert result["new_pair_flag"] is None
    assert result["status"] == "unknown"
    assert result["reason"] == "Missing DexScreener fields: pair_age_hours"
    assert counts(ledger, 56) == {"answered": 1, "unknown": 0, "failed": 0}
