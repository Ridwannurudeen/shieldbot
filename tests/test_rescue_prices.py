"""Rescue prices a token only from DexScreener pairs on the chain being scanned."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.rescue_service import RescueService

TOKEN = "0x" + "a" * 40
BSC_USDT = "0x55d398326f99059ff775485246999027b3197955"
# Replies served by https://api.dexscreener.com on 2026-09-24, keyed by URL.
REPLIES = json.loads(
    (Path(__file__).parent / "fixtures" / "dexscreener_replies.json").read_text(encoding="utf-8")
)
WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
CAKE = "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"
SI = "0x16dEa77364B4A9Cc7bfcb9414Ccf37Ae1beBf5F5"


def pair(chain, address, price, liquidity):
    return {
        "chainId": chain,
        "baseToken": {"address": address},
        "priceUsd": str(price),
        "liquidity": {"usd": liquidity},
    }


async def prices(tokens, chain_id, pairs):
    session = MagicMock()
    session.get.return_value.__aenter__.return_value.json = AsyncMock(return_value=pairs)
    with patch("services.rescue_service.aiohttp.ClientSession") as factory:
        factory.return_value.__aenter__.return_value = session
        return await RescueService(MagicMock())._fetch_prices(tokens, chain_id), session


@pytest.mark.asyncio
async def test_price_comes_from_a_pair_on_the_scanned_chain_even_when_another_chain_is_deeper():
    result, _ = await prices(
        [TOKEN], 204, [pair("ethereum", TOKEN, 5.0, 9_000_000), pair("opbnb", TOKEN, 0.2, 1_000)]
    )
    assert result == {TOKEN: 0.2}


@pytest.mark.asyncio
async def test_token_traded_only_on_other_chains_stays_unpriced():
    result, _ = await prices([TOKEN], 8453, [pair("bsc", TOKEN, 3.0, 50_000)])
    assert result == {}


@pytest.mark.asyncio
async def test_a_stablecoin_address_is_one_dollar_only_on_its_own_chain():
    on_bsc, bsc_session = await prices([BSC_USDT], 56, [])
    elsewhere, _ = await prices([BSC_USDT], 8453, [])

    assert on_bsc == {BSC_USDT: 1.0}
    bsc_session.get.assert_not_called()
    assert elsewhere == {}


@pytest.mark.asyncio
async def test_every_token_in_a_batch_is_priced_from_its_own_pair_on_the_chain():
    # Asked for all three at once, the unscoped latest/dex/tokens route served 30 pairs, every one
    # of them CAKE's, so WBNB and SI went unpriced. tokens/v1/bsc answers one pair per token.
    session = MagicMock()

    def get(url, **kwargs):
        response = MagicMock()
        response.json = AsyncMock(return_value=REPLIES[url])
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=response)
        context.__aexit__ = AsyncMock(return_value=False)
        return context

    session.get.side_effect = get
    with patch("services.rescue_service.aiohttp.ClientSession") as factory:
        factory.return_value.__aenter__.return_value = session
        result = await RescueService(MagicMock())._fetch_prices([WBNB, CAKE, SI], 56)

    assert result == {WBNB: 778.26, CAKE: 2.68, SI: 0.001339}
    assert [call.args[0] for call in session.get.call_args_list] == [
        f"https://api.dexscreener.com/tokens/v1/bsc/{WBNB},{CAKE},{SI}"
    ]
