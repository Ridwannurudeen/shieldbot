"""Tests for router swap analysis to ensure no whitelist bypass."""

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from eth_abi import encode

from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine
from utils.calldata_decoder import CalldataDecoder
from utils.web3_client import Web3Client


@pytest.mark.asyncio
async def test_router_swap_analysis_blocks_high_risk_token():
    import api as api_module

    # Build calldata for swapExactTokensForTokens with address[] path
    addr1 = "0x1111111111111111111111111111111111111111"
    addr2 = "0x2222222222222222222222222222222222222222"
    recipient = "0x3333333333333333333333333333333333333333"
    payload = encode(
        ["uint256", "uint256", "address[]", "address", "uint256"],
        [1, 1, [addr1, addr2], recipient, 123],
    ).hex()
    calldata = "0x38ed1739" + payload

    decoded = CalldataDecoder().decode(calldata)

    class DummyRegistry:
        async def run_all(self, ctx):
            return [
                AnalyzerResult(
                    name="structural",
                    weight=1.0,
                    score=90.0,
                    flags=["High risk"],
                    data={"is_verified": False},
                )
            ]

    class DummyPolicy:
        def apply(self, results, risk_output, mode_override=None):
            return risk_output

    api_module.container = SimpleNamespace(
        registry=DummyRegistry(),
        policy_engine=DummyPolicy(),
    )
    api_module.risk_engine = RiskEngine()
    chain_registry = Web3Client.__new__(Web3Client)
    chain_registry._adapters = {56: SimpleNamespace()}
    api_module.web3_client = SimpleNamespace(
        validate_chain_id=chain_registry.validate_chain_id,
        is_valid_address=lambda a: True,
        to_checksum_address=lambda a: a,
        is_verified_contract=AsyncMock(return_value=False),
    )
    api_module.tenderly_simulator = SimpleNamespace(is_enabled=lambda: False)

    req = api_module.FirewallRequest(
        to="0xrouter",
        sender="0xfrom",
        value="0x0",
        data=calldata,
        chainId=56,
    )

    resp = await api_module._analyze_router_swap(
        req=req,
        to_addr="0xrouter",
        from_addr="0xfrom",
        decoded=decoded,
        whitelisted="Router",
        value_bnb=0.0,
    )

    assert resp is not None
    assert resp["classification"] == "BLOCK_RECOMMENDED"


WBNB = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
TOKEN = "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"


def _swap_results(contract_age_known):
    structural = {
        "is_contract": True, "is_verified": True, "contract_age_days": 900 if contract_age_known else None,
        "ownership_renounced": True, "scam_matches": [],
        "coverage": {"is_verified": True, "contract_age_days": contract_age_known, "scam_database": True},
    }
    # DexScreener gave liquidity but no pair age or price change: informational gaps.
    market = {
        "liquidity_usd": 5_000_000, "pair_age_hours": None, "price_change_24h": None, "status": "unknown",
        "reason": "Incomplete DexScreener data",
        "coverage": {"liquidity_usd": True, "pair_age_hours": False, "price_change_24h": False},
    }
    honeypot = {
        "is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0, "status": "ok",
        "coverage": {field: True for field in ("is_honeypot", "can_buy", "can_sell", "buy_tax", "sell_tax")},
    }
    return [
        AnalyzerResult("structural", 0.32, 0, data=structural),
        AnalyzerResult("market", 0.20, 0, data=market),
        AnalyzerResult("behavioral", 0.16, 0, data={"reputation_score": 50}),
        AnalyzerResult("honeypot", 0.12, 0, data=honeypot),
        AnalyzerResult("intent", 0.12, 0, data={"status": "ok", "coverage": {"selector_verification": True}}),
        AnalyzerResult("signature", 0.08, 0, data={"has_typed_data": False}),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("contract_age_known, blocked", [(True, False), (False, True)])
async def test_strict_router_swap_blocks_only_on_a_required_gap(monkeypatch, contract_age_known, blocked):
    import api as api_module
    from core.policy import PolicyEngine

    class Registry:
        async def run_all(self, ctx):
            # WBNB is complete everywhere; the token's contract age is what the case varies.
            return _swap_results(ctx.address != TOKEN or contract_age_known)

    chain_registry = Web3Client.__new__(Web3Client)
    chain_registry._adapters = {56: SimpleNamespace()}
    monkeypatch.setattr(api_module, "container", SimpleNamespace(
        registry=Registry(), policy_engine=PolicyEngine("BALANCED"),
    ))
    monkeypatch.setattr(api_module, "risk_engine", RiskEngine())
    monkeypatch.setattr(api_module, "web3_client", SimpleNamespace(
        validate_chain_id=chain_registry.validate_chain_id,
        is_valid_address=lambda a: True,
        to_checksum_address=lambda a: a,
        is_verified_contract=AsyncMock(return_value=(True, None)),
    ))
    monkeypatch.setattr(api_module, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    payload = encode(["uint256", "address[]", "address", "uint256"], [1, [WBNB, TOKEN], "0x" + "3" * 40, 123])
    calldata = "0x7ff36ab5" + payload.hex()
    req = api_module.FirewallRequest(to="0x" + "1" * 40, sender="0x" + "2" * 40, value=hex(10**17), data=calldata)

    resp = await api_module._analyze_router_swap(
        req, req.to, req.sender, CalldataDecoder().decode(calldata), "PancakeSwap V2 Router", 0.1,
        policy_override="STRICT",
    )

    assert (resp["classification"] == "BLOCK_RECOMMENDED") is blocked
    assert resp["policy_mode"] == "STRICT"
    assert resp["failed_sources"] == (["structural"] if blocked else [])
