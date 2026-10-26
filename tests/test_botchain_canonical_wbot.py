"""WBOT, BOT Chain's wrapped native coin, is not judged by the checks that cannot apply to it.

Every BDEX pool is priced in WBOT: the sell simulation buys with it (services/botchain_simulation.py
reads no pool for it) and the market-pair checks judge a token against it, so for WBOT itself they say
nothing. Its explorer verification and age are not evidence either. Each skip is named in a note, as
canonical WETH's is on Robinhood Chain; any other address on 677, and WBOT's address on any other
chain, gets the full scan. A swap through the BDEX Universal Router judges WBOT the same way, so a
native BOT to USDT swap is decided by USDT alone.
"""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_abi import encode
from web3 import Web3

from adapters.botchain import USDT, WBOT, WHITELISTED_ROUTERS
from analyzers.honeypot import HoneypotAnalyzer
from analyzers.market import MarketAnalyzer
from analyzers.structural import HOLDERS_UNKNOWN, StructuralAnalyzer
from core.analyzer import AnalysisContext
from core.policy import PolicyEngine
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine
from services.contract_service import ContractService
from tests.test_robinhood_known_tokens import CLEAN_STRUCTURAL, Structural
from tests.test_universal_router_path import (
    ADDRESS_THIS,
    SENDER,
    V3_SWAP_EXACT_IN,
    WRAP_ETH,
    execute,
    v3_input,
)
from utils.calldata_decoder import CalldataDecoder
from utils.scam_db import ScamMatches
from utils.web3_client import Web3Client

CHAIN = 677
ROUTER = Web3.to_checksum_address("0xae6ae8630f7a888dec0b9195c85f7515d5887655")
ROUTER_NAME = WHITELISTED_ROUTERS[ROUTER.lower()]
WBOT_CHECKSUMMED = Web3.to_checksum_address(WBOT)
USDT_CHECKSUMMED = Web3.to_checksum_address(USDT)
MARKET_NOTE = (
    "Canonical WBOT of BOT Chain (exact address): market-pair checks do not apply"
)
SELL_NOTE = (
    "Canonical WBOT of BOT Chain (exact address): sell simulation does not apply"
)
EXEMPTION = "canonical BOT Chain token WBOT (exact address)"
SCAM_NOTE = (
    "Scam check: GoPlus address labels checked for the token. "
    "GoPlus token security does not cover BOT Chain."
)


def market_service():
    return MagicMock(
        fetch_token_market_data=AsyncMock(
            return_value={
                "status": "ok",
                "reason": None,
                "price_usd": 1.0,
                "liquidity_usd": 31_000_000,
                "volume_24h": 20_000,
                "price_change_24h": 0.0,
                "fdv": 74_000_000,
                "pair_age_hours": 4000,
                "volatility_flag": False,
                "low_liquidity_flag": False,
                "wash_trade_flag": False,
                "new_pair_flag": False,
                "coverage": {
                    "price_usd": True,
                    "liquidity_usd": True,
                    "volume_24h": True,
                    "fdv": True,
                    "pair_age_hours": True,
                },
            }
        )
    )


def honeypot_service():
    return MagicMock(
        fetch_honeypot_data=AsyncMock(
            return_value={
                "is_honeypot": False,
                "can_buy": True,
                "can_sell": True,
                "buy_tax": 0,
                "sell_tax": 0,
                "status": "ok",
                "reason": None,
            }
        )
    )


# --- the analyzers -------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wbot_skips_the_market_and_sell_checks_with_a_note():
    market, honeypot = market_service(), honeypot_service()
    ctx = AnalysisContext(address=WBOT_CHECKSUMMED, chain_id=CHAIN)

    results = [
        await MarketAnalyzer(market).analyze(ctx),
        await HoneypotAnalyzer(honeypot).analyze(ctx),
    ]

    assert [(result.score, result.flags, result.data) for result in results] == [
        (0, [], {"skipped": True, "reason": MARKET_NOTE, "notes": [MARKET_NOTE]}),
        (0, [], {"skipped": True, "reason": SELL_NOTE, "notes": [SELL_NOTE]}),
    ]
    market.fetch_token_market_data.assert_not_awaited()
    honeypot.fetch_honeypot_data.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address, chain_id",
    [(USDT_CHECKSUMMED, CHAIN), (WBOT_CHECKSUMMED, 56), (WBOT_CHECKSUMMED, 4663)],
    ids=["usdt-on-677", "wbot-address-on-bsc", "wbot-address-on-robinhood"],
)
async def test_every_other_token_gets_the_full_scan(address, chain_id):
    market, honeypot = market_service(), honeypot_service()
    ctx = AnalysisContext(address=address, chain_id=chain_id)

    await MarketAnalyzer(market).analyze(ctx)
    await HoneypotAnalyzer(honeypot).analyze(ctx)

    market.fetch_token_market_data.assert_awaited_once_with(address, chain_id=chain_id)
    honeypot.fetch_honeypot_data.assert_awaited_once_with(address, chain_id=chain_id)


@pytest.mark.asyncio
async def test_wbot_needs_no_explorer_lookup_and_no_creator_lookup(mock_web3_client):
    scam_db = MagicMock(
        check_address=AsyncMock(return_value=ScamMatches(observed_at=time.time())),
        fetch_address_security=AsyncMock(),
    )
    analyzer = StructuralAnalyzer(ContractService(mock_web3_client, scam_db))

    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        result = await analyzer.analyze(
            AnalysisContext(
                WBOT_CHECKSUMMED, CHAIN, extra={"deadline": time.monotonic() + 5}
            ),
        )

    mock_web3_client.is_verified_contract.assert_not_awaited()
    mock_web3_client.get_contract_creation_info.assert_not_awaited()
    scam_db.fetch_address_security.assert_not_awaited()
    # The fast checks still run.
    mock_web3_client.get_ownership_info.assert_awaited_once()
    mock_web3_client.get_bytecode.assert_awaited_once()
    assert result.data["status"] == "ok"
    assert result.data["coverage_exemptions"] == {
        "is_verified": EXEMPTION,
        "contract_age_days": EXEMPTION,
    }
    assert "coverage_reasons" not in result.data
    assert result.data["creator_address_status"] == "not_needed"
    assert result.data["notes"] == [
        SCAM_NOTE,
        f"Explorer verification and contract age not needed: {EXEMPTION}",
        HOLDERS_UNKNOWN,
    ]
    assert RiskEngine().compute_from_results([result])["coverage"]["structural"] == 1


@pytest.mark.asyncio
async def test_usdt_on_677_still_gets_its_explorer_and_creator_lookups(
    mock_web3_client,
):
    mock_web3_client.get_contract_creation_info.return_value = {
        "creator": "0x" + "c1" * 20,
        "age_days": 400,
    }
    scam_db = MagicMock(
        check_address=AsyncMock(return_value=ScamMatches(observed_at=time.time())),
        fetch_address_security=AsyncMock(
            return_value={"status": "ok", "reason": None, "data": {}}
        ),
    )

    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        data = await ContractService(mock_web3_client, scam_db).fetch_contract_data(
            USDT_CHECKSUMMED,
            chain_id=CHAIN,
            deadline=time.monotonic() + 5,
        )

    mock_web3_client.is_verified_contract.assert_awaited_once()
    mock_web3_client.get_contract_creation_info.assert_awaited_once()
    scam_db.fetch_address_security.assert_awaited_once()
    assert "coverage_exemptions" not in data
    assert data["creator_address_status"] == "ok"


# --- a swap through the BDEX Universal Router -----------------------------------------------------


def wrap_and_swap(amount, *tokens):
    """WRAP_ETH into the router, then a V3 swap of the wrapped amount along `tokens` to the sender."""
    return execute(
        [WRAP_ETH, V3_SWAP_EXACT_IN],
        [encode(["address", "uint256"], [ADDRESS_THIS, amount]), v3_input(*tokens)],
    )


async def router_swap(monkeypatch, calldata, market, honeypot):
    import api as api_module

    analyzers = AnalyzerRegistry()
    analyzers.register(Structural(CLEAN_STRUCTURAL))
    analyzers.register(MarketAnalyzer(market))
    analyzers.register(HoneypotAnalyzer(honeypot))
    chain_registry = Web3Client.__new__(Web3Client)
    chain_registry._adapters = {CHAIN: SimpleNamespace()}
    monkeypatch.setattr(
        api_module,
        "container",
        SimpleNamespace(registry=analyzers, policy_engine=PolicyEngine("BALANCED")),
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
        ),
    )
    monkeypatch.setattr(
        api_module, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False)
    )
    req = api_module.FirewallRequest(
        to=ROUTER, sender=SENDER, value=hex(35 * 10**15), data=calldata, chainId=CHAIN
    )
    return await api_module._analyze_router_swap(
        req, ROUTER, SENDER, CalldataDecoder().decode(calldata), ROUTER_NAME, 0.035
    )


@pytest.mark.asyncio
async def test_a_native_bot_to_usdt_swap_is_judged_by_usdt_alone(monkeypatch):
    market, honeypot = market_service(), honeypot_service()

    resp = await router_swap(
        monkeypatch, wrap_and_swap(35 * 10**15, WBOT, USDT), market, honeypot
    )

    market.fetch_token_market_data.assert_awaited_once_with(
        USDT_CHECKSUMMED, chain_id=CHAIN
    )
    honeypot.fetch_honeypot_data.assert_awaited_once_with(
        USDT_CHECKSUMMED, chain_id=CHAIN
    )
    assert (resp["status"], resp["classification"], resp["partial"]) == (
        "ok",
        "SAFE",
        False,
    )
    assert "Unknown" not in resp["verdict"]
    assert resp["danger_signals"] == []
    assert resp["coverage"] == {
        f"{address}:{analyzer}": 1
        for address in (WBOT_CHECKSUMMED, USDT_CHECKSUMMED)
        for analyzer in ("structural", "market", "honeypot")
    }
    assert resp["coverage_reasons"] == {}
    assert resp["notes"] == [
        f"{WBOT_CHECKSUMMED}: {MARKET_NOTE}",
        f"{WBOT_CHECKSUMMED}: {SELL_NOTE}",
    ]
    assert resp["transaction_impact"]["sending"] == "0.035 BOT"
    assert resp["transaction_impact"]["granting_access"] == "None"
    assert [
        (item["address"], item["status"])
        for item in resp["raw_checks"]["tokens_analyzed"]
    ] == [
        (WBOT_CHECKSUMMED, "ok"),
        (USDT_CHECKSUMMED, "ok"),
    ]
