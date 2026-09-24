"""DexService reads a token's market from its own pools on the requested chain.

fixtures/dexscreener_replies.json holds replies served by https://api.dexscreener.com on
2026-09-24 (GET, no key), keyed by URL. Each list of pairs is trimmed to a few pairs, kept in the
order served, and to the fields DexService reads. The latest/dex/tokens replies are what the
unscoped route served for the same tokens, so a return to it fails here on the data that caused
the bug.
"""

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from analyzers.market import MarketAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.extension_formatter import format_extension_alert
from core.risk_engine import RiskEngine
from core.unknown_ledger import UnknownLedger
from services.dex_service import DexService
from utils.ai_analyzer import AIAnalyzer

REPLIES = json.loads(
    (Path(__file__).parent / "fixtures" / "dexscreener_replies.json").read_text(encoding="utf-8")
)
API = "https://api.dexscreener.com"
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
USDT_BSC = "0x55d398326f99059fF775485246999027B3197955"
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address, chain_id, expected",
    [
        (
            USDT,
            1,
            {
                "token_name": "Tether USD",
                "token_symbol": "USDT",
                "price_usd": 0.9996,
                "price_change_24h": -0.01,
                "fdv": 88274266419,
                "liquidity_usd": 50152955.91,
                "status": "ok",
            },
        ),
        (
            USDC,
            8453,
            {
                "token_name": "USD Coin",
                "token_symbol": "USDC",
                "price_usd": 0.9999,
                # USDC's deepest own pair, USDC/USDbC on Aerodrome, reports no 24h change.
                "price_change_24h": None,
                "fdv": 4262511047,
                "liquidity_usd": 37153848.31,
                "status": "ok",
            },
        ),
    ],
    ids=["usdt-ethereum", "usdc-base"],
)
async def test_the_token_is_described_only_by_pairs_it_is_the_base_token_of(
    ledger, address, chain_id, expected
):
    # A pair's price, 24h change and FDV are its base token's. USDT is the quote token of its
    # deepest Ethereum pool (USDS/USDT) and USDC of its deepest Base pool (AERO/USDC), whose
    # liquidity is still theirs; read from those pairs, USDC was Aerodrome at $0.72.
    result, _ = await market(address, chain_id)

    assert {key: result[key] for key in expected} == expected
    assert counts(ledger, chain_id) == {"answered": 1, "unknown": 0, "failed": 0}


@pytest.mark.asyncio
async def test_a_token_that_is_only_ever_the_quote_token_has_no_price(ledger):
    url = f"{API}/token-pairs/v1/ethereum/{USDT}"
    quoted = [pair for pair in REPLIES[url] if pair["baseToken"]["address"] != USDT]
    result, _ = await market(USDT, 1, {url: quoted})

    assert result["liquidity_usd"] == 50152955.91
    assert result["token_symbol"] is None
    assert result["price_usd"] is None
    assert result["price_change_24h"] is None
    assert result["fdv"] is None
    assert result["status"] == "unknown"
    assert result["reason"] == "Missing DexScreener fields: price_usd, price_change_24h, fdv"
    assert counts(ledger, 1) == {"answered": 1, "unknown": 0, "failed": 0}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address, chain_id, liquidity",
    [(USDC, 8453, 37153848.31), (USDT_BSC, 56, 57471149.27)],
    ids=["usdc-base", "usdt-bsc"],
)
async def test_a_missing_24h_change_leaves_only_the_volatility_flag_unknown(
    ledger, address, chain_id, liquidity
):
    # The deepest pair each stablecoin is the base token of reports no 24h change: DexScreener
    # leaves it out of many flat pairs. It feeds only the volatility flag, which stays unknown,
    # named in the reason, and cannot fire; every field that decides the status is known.
    result, _ = await market(address, chain_id)

    assert result["liquidity_usd"] == liquidity
    assert result["price_change_24h"] is None
    assert result["volatility_flag"] is None
    assert result["reason"] == "Missing DexScreener fields: price_change_24h"
    assert result["status"] == "ok"
    assert all(result["coverage"].values())
    assert counts(ledger, chain_id) == {"answered": 1, "unknown": 0, "failed": 0}


async def scan(market_data):
    """The risk output and extension alert for a fully covered token with this market data."""
    service = SimpleNamespace(fetch_token_market_data=AsyncMock(return_value=market_data))
    results = [
        AnalyzerResult(
            name="structural",
            weight=0.40,
            score=0,
            data={
                "status": "ok",
                "is_contract": True,
                "is_verified": True,
                "contract_age_days": 400,
                "scam_matches": [],
                "coverage": {"scam_database": True, "is_verified": True, "contract_age_days": True},
            },
        ),
        await MarketAnalyzer(service).analyze(AnalysisContext(address=USDC, chain_id=8453)),
        AnalyzerResult(name="behavioral", weight=0.20, score=0, data={"status": "ok"}),
        AnalyzerResult(
            name="honeypot",
            weight=0.15,
            score=0,
            data={
                "status": "ok",
                "is_honeypot": False,
                "can_buy": True,
                "can_sell": True,
                "buy_tax": 0,
                "sell_tax": 0,
            },
        ),
    ]
    risk = RiskEngine().compute_from_results(results)
    return risk, format_extension_alert(risk)


@pytest.mark.asyncio
async def test_a_missing_24h_change_is_named_and_scores_like_a_flat_one(ledger):
    url = f"{API}/token-pairs/v1/base/{USDC}"
    flat_reply = copy.deepcopy(REPLIES[url])
    for pair in flat_reply:
        pair["priceChange"] = {"h24": 0}
    missing, _ = await market(USDC, 8453)
    flat, _ = await market(USDC, 8453, {url: flat_reply})
    assert flat["volatility_flag"] is False

    risk, alert = await scan(missing)
    flat_risk, flat_alert = await scan(flat)

    marker = "Volatility unknown: 24h price change unavailable"
    assert risk["coverage"]["market"] == 1
    assert alert["risk_classification"] == flat_alert["risk_classification"] == "SAFE"
    assert risk["rug_probability"] == flat_risk["rug_probability"]
    assert risk["risk_level"] == flat_risk["risk_level"]
    assert risk["category_scores"] == flat_risk["category_scores"]
    assert risk["status"] == alert["status"] == "ok"
    assert marker in risk["critical_flags"]
    assert marker in alert["top_flags"]
    assert marker not in flat_risk["critical_flags"]


@pytest.mark.asyncio
async def test_the_forensic_prompt_reads_a_missing_24h_change_as_unknown(ledger):
    result, _ = await market(USDC, 8453)
    assert result["status"] == "ok"

    context = AIAnalyzer.__new__(AIAnalyzer)._build_forensic_context(
        USDC, {"dex": result}, "token"
    )

    assert "Price Change 24h: Unknown" in context
