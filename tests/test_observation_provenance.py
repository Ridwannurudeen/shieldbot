"""Measurement ages survive provider caches and the scan scoring boundary."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import utils.scam_db as scam_module
from adapters.robinhood import RobinhoodAdapter
from analyzers.honeypot import HoneypotAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine
from core.verdict_evidence import build_evidence
from services.contract_service import ContractService
from services.honeypot_service import HoneypotService
from tests.test_robinhood_simulation import adapter_with, client_with, fresh_addresses, load, rpc_for
from utils.scam_db import ScamDatabase


TOKEN = "0x" + "12" * 20
GOPLUS_TOKEN = {
    "is_honeypot": "0", "cannot_buy": "0", "cannot_sell_all": "0",
    "transfer_pausable": "0", "buy_tax": "0", "sell_tax": "0",
}


@pytest.mark.asyncio
async def test_goplus_cached_observation_survives_both_scan_components(mock_web3_client):
    scam_module._GOPLUS_CACHE.clear()
    response = MagicMock(status=200)
    response.json = AsyncMock(return_value={"code": 1, "result": {TOKEN: GOPLUS_TOKEN}})
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    session.get.return_value.__aexit__ = AsyncMock(return_value=False)
    try:
        with patch("utils.scam_db.aiohttp.ClientSession") as factory, patch(
            "utils.scam_db.time.time", return_value=1000
        ):
            factory.return_value.__aenter__ = AsyncMock(return_value=session)
            factory.return_value.__aexit__ = AsyncMock(return_value=False)
            first = await ScamDatabase.fetch_token_security(TOKEN, 4663)
        with patch("utils.scam_db.time.time", return_value=1020), patch(
            "services.contract_service.BSCSCAN_DELAY", 0
        ):
            cached = await ScamDatabase.fetch_token_security(TOKEN, 4663)
            structural = await ContractService(mock_web3_client, ScamDatabase()).fetch_contract_data(
                TOKEN, 4663
            )
            mock_web3_client.get_supported_chain_ids.return_value = [4663]
            mock_web3_client.check_honeypot.return_value = {}
            mock_web3_client.get_tax_info.return_value = {}
            honeypot = await HoneypotService(mock_web3_client).fetch_honeypot_data(TOKEN, 4663)
        assert first["observed_at"] == cached["observed_at"] == 1000
        assert structural["observed_at"] == honeypot["observed_at"] == 1000
        assert session.get.call_count == 1
    finally:
        scam_module._GOPLUS_CACHE.clear()


@pytest.mark.asyncio
async def test_cached_simulation_age_survives_adapter_service_and_scoring():
    adapter = object.__new__(RobinhoodAdapter)
    adapter._simulator = MagicMock(simulate=AsyncMock(return_value={
        "is_honeypot": False, "can_buy": True, "can_sell": True,
        "buy_tax": 0, "sell_tax": 0, "simulation_block": 123,
        "reason": None, "observed_at": 1000,
    }))
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [4663]
    async def check(address, chain_id):
        return await adapter.check_honeypot(address)

    async def tax(address, chain_id):
        return await adapter.get_tax_info(address)

    client.check_honeypot = AsyncMock(side_effect=check)
    client.get_tax_info = AsyncMock(side_effect=tax)
    registry = AnalyzerRegistry()
    registry.register(HoneypotAnalyzer(HoneypotService(client)))
    with patch("time.time", return_value=1050):
        results = await registry.run_all(AnalysisContext(TOKEN, chain_id=4663))
    assert results[0].data["observed_at"] == 1000
    assert RiskEngine().compute_from_results(results)["observed_at"] == 1000


@pytest.mark.parametrize("legacy", [False, True])
def test_oldest_measurement_sets_scan_observation_time(legacy):
    data = [
        {"observed_at": 1020, "is_verified": True, "contract_age_days": 20},
        {"observed_at": 1000, "is_honeypot": False, "can_sell": True, "buy_tax": 0, "sell_tax": 0},
        {"observed_at": 1040, "liquidity_usd": 200000},
        {"observed_at": 1030, "reputation_score": 80},
    ]
    engine = RiskEngine()
    if legacy:
        result = engine.compute_composite_risk(*data)
    else:
        result = engine.compute_from_results([
            AnalyzerResult(name, .25, 0, data=value)
            for name, value in zip(("structural", "honeypot", "market", "behavioral"), data)
        ])
    assert result["observed_at"] == 1000


@pytest.mark.asyncio
async def test_pinned_source_and_cached_measurement_reach_canonical_evidence():
    fixture = load("v2_router02")
    source_block = int(fixture["response"]["result"][0]["number"], 16) - 1
    rpc = rpc_for(fixture, head=source_block)
    adapter = adapter_with(rpc)
    service = HoneypotService(client_with(adapter))
    registry = AnalyzerRegistry()
    registry.register(HoneypotAnalyzer(service))
    with fresh_addresses(fixture), patch("time.time", return_value=1000):
        await adapter._simulator.simulate(fixture["token"])
    with patch("time.time", return_value=1050), patch.object(
        ScamDatabase, "fetch_token_security", new_callable=AsyncMock
    ) as goplus:
        results = await registry.run_all(AnalysisContext(fixture["token"], chain_id=4663))
        risk = RiskEngine().compute_from_results(results)
        evidence = build_evidence(4663, fixture["token"], risk, results[0].data)
    goplus.assert_not_awaited()
    assert evidence["observed_block"] == source_block
    assert evidence["honeypot"]["simulation_block"] == source_block
    assert evidence["observed_at"] == evidence["scanned_at"] == 1000
    simulations = [params for calls in rpc.requests for method, params in calls if method == "eth_simulateV1"]
    assert len(simulations) == 1
    assert simulations[0][1] == hex(source_block)
