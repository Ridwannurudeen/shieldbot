"""A honeypot.is honeypot verdict stands on a verified contract with low taxes.

Verifying source is free, so it cannot clear a failed sell; the doubt is flagged instead.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from adapters.bsc import BscAdapter
from analyzers.honeypot import HoneypotAnalyzer
from core.analyzer import AnalysisContext
from core.risk_engine import RiskEngine
from services.honeypot_service import HoneypotService
from utils.scam_db import ScamDatabase
from utils.web3_client import Web3Client

TOKEN = "0x" + "ab" * 20
LOW_TAX_HONEYPOT = {
    "simulationSuccess": True,
    "honeypotResult": {"isHoneypot": True, "honeypotReason": "TRANSFER_FAILED"},
    "simulationResult": {"buyTax": 1, "sellTax": 2},
}


def _adapter(verified):
    response = MagicMock(status=200)
    response.json = AsyncMock(return_value=LOW_TAX_HONEYPOT)
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    adapter = BscAdapter(rpc_url="https://rpc.invalid")
    adapter.is_verified_contract = AsyncMock(return_value=(verified, None))
    return adapter, session


@pytest.mark.asyncio
async def test_verified_low_tax_honeypot_stays_a_honeypot_with_the_doubt_flagged():
    adapter, session = _adapter(verified=True)
    with patch("adapters.evm_base.aiohttp.ClientSession") as client:
        client.return_value.__aenter__ = AsyncMock(return_value=session)
        result = await adapter.check_honeypot(TOKEN)
    assert result["is_honeypot"] is True
    assert result["status"] == "ok"
    assert result["likely_false_positive"] is True
    assert "low_tax_honeypot" not in result
    assert result["reason"] == "Flagged but verified with normal taxes (buy:1.0% sell:2.0%)"


@pytest.mark.asyncio
async def test_unverified_low_tax_honeypot_is_unchanged():
    adapter, session = _adapter(verified=None)
    with patch("adapters.evm_base.aiohttp.ClientSession") as client:
        client.return_value.__aenter__ = AsyncMock(return_value=session)
        result = await adapter.check_honeypot(TOKEN)
    assert result["is_honeypot"] is True
    assert result["low_tax_honeypot"] is True
    assert result["reason"] == "TRANSFER_FAILED (taxes low: buy:1.0% sell:2.0%)"


@pytest.mark.asyncio
async def test_verified_low_tax_honeypot_scores_as_a_honeypot():
    adapter, session = _adapter(verified=True)
    web3_client = Web3Client()
    web3_client.register_adapter(adapter)
    with (
        patch("adapters.evm_base.aiohttp.ClientSession") as client,
        patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock()),
    ):
        client.return_value.__aenter__ = AsyncMock(return_value=session)
        result = await HoneypotAnalyzer(HoneypotService(web3_client)).analyze(
            AnalysisContext(TOKEN)
        )
    assert result.data["is_honeypot"] is True
    assert "Honeypot detected" in result.flags
    assert result.score >= 80
    contract = {
        "is_contract": True,
        "is_verified": True,
        "contract_age_days": 400,
        "ownership_renounced": True,
    }
    market = {"liquidity_usd": 50_000, "pair_age_hours": 100, "fdv": 200_000, "volume_24h": 2_000}
    risk = RiskEngine().compute_composite_risk(
        contract, result.data, market, {"reputation_score": 80}
    )
    assert risk["risk_level"] == "HIGH"
