"""Tests for router swap analysis to ensure no whitelist bypass."""

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from eth_abi import encode

from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine
from utils.calldata_decoder import CalldataDecoder


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
    api_module.web3_client = SimpleNamespace(
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
