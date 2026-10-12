"""Official Robinhood Chain tokens are not judged by the checks that cannot apply to them.

The canonical WETH and USDG are funding assets, so DexScreener prices no pair in them and the sell
simulator buys with them. Official stocks are simulated when the route resolves and retain the skip note
when it does not. The market analyzer continues to skip official addresses; other analyzers run, and a token
at any other address, or a stock token while the published list is unavailable, gets the full scan. A swap
through a trusted router judges each token the same way.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from web3 import Web3

from analyzers.honeypot import HoneypotAnalyzer
from analyzers.market import MarketAnalyzer
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
from core.policy import PolicyEngine
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine
from core.verdict_evidence import Verdict, build_evidence, verdict_for
from core.verdicts import HIGH, LOW
from services.robinhood_assets import RobinhoodAssets, check_token, with_impostor_check
from services.robinhood_simulation import USDG, WETH
from tests.test_robinhood_assets import LISTED, NVDA, OTHER
from tests.test_universal_router_path import (
    MSG_SENDER,
    NATIVE,
    SENDER,
    SETTLE_ALL,
    SWAP_EXACT_IN,
    SWAP_EXACT_IN_SINGLE,
    TAKE,
    V4_SWAP,
    execute,
    multi,
    settle_all,
    single,
    take,
    v4_input,
)
from utils.calldata_decoder import CalldataDecoder
from utils.web3_client import Web3Client

CHAIN = 4663
ROUTER = "0x204faca1764b154221e35c0d20abb3c525710498"
ROUTER_NAME = "Uniswap Universal Router V2.1.2"
MARKET_UNKNOWN = "Missing DexScreener fields: price_usd, price_change_24h, fdv"
HONEYPOT_UNKNOWN = "No supported pool found; Unknown fields: is_honeypot, can_sell"
# A structural analyzer that answered everything: the evidence a verdict is left with.
CLEAN_STRUCTURAL = {
    "is_contract": True,
    "is_verified": True,
    "contract_age_days": 400,
    "ownership_renounced": True,
    "scam_matches": [],
    "status": "ok",
    "coverage": {"is_verified": True, "contract_age_days": True, "scam_database": True, "bytecode": True},
}
BLACKLISTED = {
    "type": "Local Blacklist",
    "reason": "Confirmed scam address",
    "source": "ShieldBot",
    "severity": "block",
}
IMPOSTOR_FLAG = f"Impersonates official NVDA token (Robinhood-issued); official contract {NVDA}"


def note(symbol, finding, canonical=True):
    if canonical:
        return f"Canonical {symbol} of Robinhood Chain (exact address): {finding}"
    return (
        f"Official Robinhood Chain asset {symbol} (exact address on Robinhood's published list): "
        f"{finding}"
    )


def assets(listed=LISTED):
    """The official-token service with the list in hand, or without one (None), fetching nothing."""
    service = RobinhoodAssets("http://rpc.invalid")
    service.listed = AsyncMock(return_value=listed)
    return service


def market_service():
    """DexScreener as it answers for a quote token: a deep pair, but no price, change or FDV."""
    return MagicMock(
        fetch_token_market_data=AsyncMock(
            return_value={
                "status": "unknown",
                "reason": MARKET_UNKNOWN,
                "liquidity_usd": 5_000_000,
                "volume_24h": 20_000,
                "pair_age_hours": 400,
                "price_usd": None,
                "price_change_24h": None,
                "fdv": None,
                "coverage": {
                    "price_usd": False,
                    "liquidity_usd": True,
                    "volume_24h": True,
                    "fdv": False,
                    "pair_age_hours": True,
                },
            }
        )
    )


def honeypot_service():
    """The simulator as it answers for a token in hookless USDG pools: no supported route, no sell."""
    return MagicMock(
        fetch_honeypot_data=AsyncMock(
            return_value={
                "is_honeypot": None,
                "can_buy": True,
                "can_sell": None,
                "buy_tax": 0,
                "sell_tax": None,
                "status": "unknown",
                "reason": HONEYPOT_UNKNOWN,
            }
        )
    )


class Structural(Analyzer):
    def __init__(self, data):
        self._data = data

    @property
    def name(self):
        return "structural"

    @property
    def weight(self):
        return 0.4

    async def analyze(self, ctx):
        return AnalyzerResult(self.name, self.weight, 0, data=self._data)


def registry(official, structural=CLEAN_STRUCTURAL, market=None, honeypot=None):
    analyzers = AnalyzerRegistry()
    analyzers.register(Structural(structural))
    analyzers.register(MarketAnalyzer(market or market_service(), official))
    analyzers.register(HoneypotAnalyzer(honeypot or honeypot_service(), official))
    return analyzers


# --- the analyzers -------------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address, symbol, canonical",
    [(USDG, "USDG", True), (WETH, "WETH", True), (NVDA, "NVDA", False)],
)
async def test_canonical_tokens_and_unresolved_official_stocks_keep_the_skip_note(
    address, symbol, canonical
):
    market, honeypot, official = market_service(), honeypot_service(), assets()
    ctx = AnalysisContext(address=Web3.to_checksum_address(address), chain_id=CHAIN)

    results = [
        await MarketAnalyzer(market, official).analyze(ctx),
        await HoneypotAnalyzer(honeypot, official).analyze(ctx),
    ]

    market.fetch_token_market_data.assert_not_awaited()
    if canonical:
        honeypot.fetch_honeypot_data.assert_not_awaited()
    else:
        honeypot.fetch_honeypot_data.assert_awaited_once_with(
            Web3.to_checksum_address(address), chain_id=CHAIN
        )
    market_note = note(symbol, "market-pair checks do not apply", canonical)
    sell_note = note(symbol, "sell simulation does not apply", canonical)
    assert [(result.score, result.flags, result.data) for result in results] == [
        (0, [], {"skipped": True, "reason": market_note, "notes": [market_note]}),
        (0, [], {"skipped": True, "reason": sell_note, "notes": [sell_note]}),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["rpc_failed", "simulation_failed"])
async def test_a_failed_official_stock_simulation_is_unknown_not_skipped(failure):
    honeypot = MagicMock(
        fetch_honeypot_data=AsyncMock(
            return_value={
                "is_honeypot": None,
                "can_buy": True,
                "can_sell": None,
                "buy_tax": 0,
                "sell_tax": None,
                "status": "unknown",
                "reason": HONEYPOT_UNKNOWN,
                failure: True,
            }
        )
    )

    result = await HoneypotAnalyzer(honeypot, assets()).analyze(
        AnalysisContext(address=Web3.to_checksum_address(NVDA), chain_id=CHAIN)
    )

    assert not result.data.get("skipped")
    assert result.data["status"] == "unknown"
    assert result.data["coverage"]["can_sell"] is False
    assert result.score == 0
    assert not any("suspicious" in flag.lower() for flag in result.flags)


@pytest.mark.asyncio
async def test_an_undecided_official_stock_simulation_keeps_the_skip_note():
    honeypot = MagicMock(
        fetch_honeypot_data=AsyncMock(
            return_value={
                "is_honeypot": None,
                "can_buy": True,
                "can_sell": None,
                "buy_tax": 0,
                "sell_tax": None,
                "status": "unknown",
                "reason": HONEYPOT_UNKNOWN,
                "undecided": True,
            }
        )
    )

    result = await HoneypotAnalyzer(honeypot, assets()).analyze(
        AnalysisContext(address=Web3.to_checksum_address(NVDA), chain_id=CHAIN)
    )

    sell_note = note("NVDA", "sell simulation does not apply", canonical=False)
    assert result.data == {"skipped": True, "reason": sell_note, "notes": [sell_note]}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "is_honeypot, can_sell, expected_score",
    [(False, True, 0), (True, False, 100)],
)
async def test_a_resolved_official_stock_uses_the_simulation_result(
    is_honeypot, can_sell, expected_score
):
    honeypot = MagicMock(
        fetch_honeypot_data=AsyncMock(
            return_value={
                "is_honeypot": is_honeypot,
                "can_buy": True,
                "can_sell": can_sell,
                "buy_tax": 0,
                "sell_tax": 0,
                "status": "ok",
            }
        )
    )
    result = await HoneypotAnalyzer(honeypot, assets()).analyze(
        AnalysisContext(address=Web3.to_checksum_address(NVDA), chain_id=CHAIN)
    )

    honeypot.fetch_honeypot_data.assert_awaited_once_with(
        Web3.to_checksum_address(NVDA), chain_id=CHAIN
    )
    assert not result.data.get("skipped")
    assert (result.score, result.data["is_honeypot"], result.data["can_sell"]) == (
        expected_score,
        is_honeypot,
        can_sell,
    )
    assert result.data["coverage"]["is_honeypot"] is True
    assert result.data["coverage"]["can_sell"] is True


@pytest.mark.asyncio
async def test_the_verdict_comes_from_the_analyzers_that_apply():
    results = await registry(assets()).run_all(AnalysisContext(address=USDG, chain_id=CHAIN))
    output = PolicyEngine("BALANCED").apply(results, RiskEngine().compute_from_results(results))

    assert (output["status"], output["risk_level"], output["partial"]) == ("ok", LOW, False)
    assert output["coverage"] == {"structural": 1, "market": 1, "honeypot": 1}
    assert (output["coverage_reasons"], output["failed_sources"]) == ({}, [])
    assert output["critical_flags"] == []
    # Covered, but never silently: each skipped check is named.
    assert output["notes"] == [note("USDG", "market-pair checks do not apply"), note("USDG", "sell simulation does not apply")]


@pytest.mark.asyncio
async def test_an_official_address_is_not_a_clean_bill_of_health():
    # The skip removes two checks that cannot apply; what the others find still decides.
    blacklisted = {**CLEAN_STRUCTURAL, "scam_matches": [BLACKLISTED]}
    results = await registry(assets(), blacklisted).run_all(
        AnalysisContext(address=USDG, chain_id=CHAIN)
    )
    output = RiskEngine().compute_from_results(results)

    assert (output["status"], output["risk_level"], output["rug_probability"]) == ("ok", HIGH, 90)


@pytest.mark.asyncio
async def test_an_official_stock_rpc_failure_is_unknown_in_the_risk_engine():
    honeypot = honeypot_service()
    honeypot.fetch_honeypot_data.return_value = {
        "is_honeypot": None,
        "can_buy": True,
        "can_sell": None,
        "buy_tax": 0,
        "sell_tax": None,
        "status": "unknown",
        "reason": HONEYPOT_UNKNOWN,
        "rpc_failed": True,
    }
    results = await registry(assets(), honeypot=honeypot).run_all(
        AnalysisContext(address=Web3.to_checksum_address(NVDA), chain_id=CHAIN)
    )

    output = RiskEngine().compute_from_results(results)

    assert output["status"] == "unknown"
    assert output["risk_level"] != LOW


@pytest.mark.asyncio
async def test_a_telegram_scan_of_an_official_token_now_publishes_the_computed_verdict():
    # bot.py publishes every 4663 scan with the honeypot analyzer's data as its evidence. A scan that
    # was Unknown, and so recorded UNKNOWN in the verdict registry, now records what the remaining
    # analyzers found; the evidence names the check that did not apply in place of a sell.
    results = await registry(assets()).run_all(AnalysisContext(address=USDG, chain_id=CHAIN))
    output = RiskEngine().compute_from_results(results)
    honeypot = next(result.data for result in results if result.name == "honeypot")

    assert verdict_for(output, honeypot) is Verdict.LOW
    evidence = build_evidence(CHAIN, USDG, output, honeypot)
    assert (evidence["verdict"], evidence["status"], evidence["observed_block"]) == ("LOW", "ok", 0)
    assert evidence["honeypot"] == {"reason": note("USDG", "sell simulation does not apply")}
    assert evidence["coverage"] == {"structural": 1, "market": 1, "honeypot": 1}


@pytest.mark.asyncio
async def test_a_token_that_only_calls_itself_official_gets_the_full_scan_and_its_impostor_flag():
    market, honeypot, official = market_service(), honeypot_service(), assets()
    ctx = AnalysisContext(address=OTHER, chain_id=CHAIN)

    results = [
        await MarketAnalyzer(market, official).analyze(ctx),
        await HoneypotAnalyzer(honeypot, official).analyze(ctx),
    ]

    market.fetch_token_market_data.assert_awaited_once_with(OTHER, chain_id=CHAIN)
    honeypot.fetch_honeypot_data.assert_awaited_once_with(OTHER, chain_id=CHAIN)
    assert [result.data["status"] for result in results] == ["unknown", "unknown"]
    assert not any(result.data.get("skipped") for result in results)
    # The check the bot and the agent add to the scan still leads with the name it borrows.
    assert check_token(OTHER, "USDG", "Global Dollar", LISTED)["status"] == "impostor"
    labelled = with_impostor_check(
        {"critical_flags": ["New pair (<24h)"]}, check_token(OTHER, "NVDA", "NVIDIA", LISTED)
    )
    assert labelled["critical_flags"] == [IMPOSTOR_FLAG, "New pair (<24h)"]


@pytest.mark.asyncio
async def test_while_the_list_is_unavailable_a_stock_token_keeps_the_full_scan():
    market, honeypot, official = market_service(), honeypot_service(), assets(listed=None)

    for address in (NVDA, USDG):
        ctx = AnalysisContext(address=address, chain_id=CHAIN)
        await MarketAnalyzer(market, official).analyze(ctx)
        await HoneypotAnalyzer(honeypot, official).analyze(ctx)

    # The canonical tokens are known without the list; the stock token is not, so it is scanned.
    market.fetch_token_market_data.assert_awaited_once_with(NVDA, chain_id=CHAIN)
    honeypot.fetch_honeypot_data.assert_awaited_once_with(NVDA, chain_id=CHAIN)


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [1, 56, 8453, 42161])
async def test_other_chains_never_ask_about_official_tokens(chain_id):
    market, honeypot, official = market_service(), honeypot_service(), assets()
    ctx = AnalysisContext(address=USDG, chain_id=chain_id)

    await MarketAnalyzer(market, official).analyze(ctx)
    await HoneypotAnalyzer(honeypot, official).analyze(ctx)

    official.listed.assert_not_awaited()
    market.fetch_token_market_data.assert_awaited_once_with(USDG, chain_id=chain_id)
    honeypot.fetch_honeypot_data.assert_awaited_once_with(USDG, chain_id=chain_id)


@pytest.mark.asyncio
async def test_without_the_official_token_service_every_token_gets_the_full_scan():
    market, honeypot = market_service(), honeypot_service()
    ctx = AnalysisContext(address=USDG, chain_id=CHAIN)

    await MarketAnalyzer(market).analyze(ctx)
    await HoneypotAnalyzer(honeypot).analyze(ctx)

    market.fetch_token_market_data.assert_awaited_once_with(USDG, chain_id=CHAIN)
    honeypot.fetch_honeypot_data.assert_awaited_once_with(USDG, chain_id=CHAIN)


@pytest.mark.asyncio
async def test_a_confirmed_non_token_is_skipped_before_the_list_is_asked_for():
    official = assets()
    ctx = AnalysisContext(address=USDG, chain_id=CHAIN, is_token=False)

    result = await MarketAnalyzer(market_service(), official).analyze(ctx)

    assert result.data == {"skipped": True, "reason": "non-token contract"}
    official.listed.assert_not_awaited()


# --- a swap through a trusted router ---------------------------------------------------------------


def swap_single(currency_in, currency_out):
    return execute(
        [V4_SWAP],
        [
            v4_input(
                [SWAP_EXACT_IN_SINGLE, SETTLE_ALL, TAKE],
                [
                    single(currency_in, currency_out, True),
                    settle_all(currency_in),
                    take(currency_out, MSG_SENDER),
                ],
            )
        ],
    )


def swap_multi(head, *hops):
    return execute(
        [V4_SWAP],
        [
            v4_input(
                [SWAP_EXACT_IN, SETTLE_ALL, TAKE],
                [multi(head, *hops), settle_all(head), take(hops[-1], MSG_SENDER)],
            )
        ],
    )


async def router_swap(monkeypatch, official, calldata, market=None, honeypot=None):
    import api as api_module

    chain_registry = Web3Client.__new__(Web3Client)
    chain_registry._adapters = {CHAIN: SimpleNamespace()}
    monkeypatch.setattr(
        api_module,
        "container",
        SimpleNamespace(
            registry=registry(official, market=market, honeypot=honeypot),
            policy_engine=PolicyEngine("BALANCED"),
        ),
    )
    monkeypatch.setattr(api_module, "risk_engine", RiskEngine())
    monkeypatch.setattr(api_module, "calldata_decoder", CalldataDecoder())
    monkeypatch.setattr(
        api_module,
        "web3_client",
        SimpleNamespace(
            validate_chain_id=chain_registry.validate_chain_id,
            is_valid_address=Web3.is_address,
            to_checksum_address=Web3.to_checksum_address,
            is_verified_contract=AsyncMock(return_value=(True, None)),
        ),
    )
    monkeypatch.setattr(api_module, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    req = api_module.FirewallRequest(
        to=ROUTER, sender=SENDER, value=hex(10**15), data=calldata, chainId=CHAIN
    )
    return await api_module._analyze_router_swap(
        req, ROUTER, SENDER, CalldataDecoder().decode(calldata), ROUTER_NAME, 0.001
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "calldata, tokens",
    [
        (swap_single(NATIVE, USDG), [("USDG", USDG, True)]),
        (swap_single(WETH, USDG), [("WETH", WETH, True), ("USDG", USDG, True)]),
        (swap_single(NATIVE, NVDA), [("NVDA", NVDA, False)]),
        (swap_multi(NATIVE, USDG, NVDA), [("USDG", USDG, True), ("NVDA", NVDA, False)]),
    ],
    ids=["eth-usdg", "weth-usdg", "eth-nvda", "eth-usdg-nvda"],
)
async def test_a_swap_into_official_tokens_is_judged_not_unknown(monkeypatch, calldata, tokens):
    market, honeypot = market_service(), honeypot_service()

    resp = await router_swap(monkeypatch, assets(), calldata, market, honeypot)

    market.fetch_token_market_data.assert_not_awaited()
    if any(not canonical for _, _, canonical in tokens):
        honeypot.fetch_honeypot_data.assert_awaited_once_with(
            Web3.to_checksum_address(NVDA), chain_id=CHAIN
        )
    else:
        honeypot.fetch_honeypot_data.assert_not_awaited()
    assert (resp["status"], resp["classification"], resp["partial"]) == ("ok", "SAFE", False)
    assert "Unknown" not in resp["verdict"]
    assert resp["danger_signals"] == []
    checksummed = [Web3.to_checksum_address(address) for _, address, _ in tokens]
    assert resp["coverage"] == {
        f"{address}:{analyzer}": 1
        for address in checksummed
        for analyzer in ("structural", "market", "honeypot")
    }
    assert resp["coverage_reasons"] == {}
    assert resp["notes"] == [
        f"{address}: {note(symbol, test, canonical)}"
        for (symbol, _, canonical), address in zip(tokens, checksummed)
        for test in ("market-pair checks do not apply", "sell simulation does not apply")
    ]
    assert [(item["address"], item["status"]) for item in resp["raw_checks"]["tokens_analyzed"]] == [
        (address, "ok") for address in checksummed
    ]


@pytest.mark.asyncio
async def test_an_unknown_token_behind_usdg_is_still_fully_scanned_and_still_unknown(monkeypatch):
    market, honeypot = market_service(), honeypot_service()
    usdg, other = Web3.to_checksum_address(USDG), Web3.to_checksum_address(OTHER)

    resp = await router_swap(monkeypatch, assets(), swap_multi(NATIVE, USDG, OTHER), market, honeypot)

    market.fetch_token_market_data.assert_awaited_once_with(other, chain_id=CHAIN)
    honeypot.fetch_honeypot_data.assert_awaited_once_with(other, chain_id=CHAIN)
    assert (resp["status"], resp["classification"], resp["partial"]) == ("unknown", "CAUTION", True)
    assert resp["coverage"][f"{usdg}:market"] == 1 and resp["coverage"][f"{other}:market"] == 0.6
    assert resp["coverage_reasons"] == {
        f"{other}:market": MARKET_UNKNOWN,
        f"{other}:honeypot": HONEYPOT_UNKNOWN,
    }
    assert "Unknown" in resp["verdict"]
    assert resp["plain_english"].startswith(f"Unknown: {MARKET_UNKNOWN}; {HONEYPOT_UNKNOWN}")
    assert resp["notes"] == [
        f"{usdg}: {note('USDG', 'market-pair checks do not apply')}",
        f"{usdg}: {note('USDG', 'sell simulation does not apply')}",
    ]
    assert [(item["address"], item["status"]) for item in resp["raw_checks"]["tokens_analyzed"]] == [
        (usdg, "ok"),
        (other, "unknown"),
    ]


@pytest.mark.asyncio
async def test_a_swap_into_a_stock_token_falls_back_to_the_full_scan_without_the_list(monkeypatch):
    market, honeypot = market_service(), honeypot_service()
    nvda = Web3.to_checksum_address(NVDA)

    resp = await router_swap(
        monkeypatch, assets(listed=None), swap_multi(NATIVE, USDG, NVDA), market, honeypot
    )

    market.fetch_token_market_data.assert_awaited_once_with(nvda, chain_id=CHAIN)
    honeypot.fetch_honeypot_data.assert_awaited_once_with(nvda, chain_id=CHAIN)
    assert (resp["status"], resp["classification"]) == ("unknown", "CAUTION")
    assert set(resp["coverage_reasons"]) == {f"{nvda}:market", f"{nvda}:honeypot"}
