"""Rescue prices a token only from DexScreener pairs on the chain being scanned."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.rescue_service import RescueService

TOKEN = "0x" + "a" * 40
BSC_USDT = "0x55d398326f99059ff775485246999027b3197955"


def pair(chain, address, price, liquidity):
    return {
        "chainId": chain,
        "baseToken": {"address": address},
        "priceUsd": str(price),
        "liquidity": {"usd": liquidity},
    }


async def prices(tokens, chain_id, pairs):
    session = MagicMock()
    session.get.return_value.__aenter__.return_value.json = AsyncMock(return_value={"pairs": pairs})
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
