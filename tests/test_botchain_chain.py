import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests

from adapters.botchain import (
    KNOWN_LOCKERS,
    KNOWN_SPENDERS,
    ROUTER_V2_FACTORIES,
    V2_FACTORY,
    WBOT,
    WHITELISTED_ROUTERS,
    BotChainAdapter,
)
from tests.test_api import client as api_client  # noqa: F401 (pytest fixture)
from tests.test_bot_app import bot_module  # noqa: F401 (pytest fixture)

TOKEN = "0x" + "ab" * 20


def test_botchain_adapter_configuration():
    adapter = BotChainAdapter()
    assert adapter.chain_id == 677
    assert adapter.chain_name == "BOT Chain"
    assert adapter.w3.provider.endpoint_uri == "https://rpc.botchain.ai"
    assert adapter._honeypot_chain_id is None
    assert adapter._quote_tokens == [("WBOT", WBOT)]
    assert adapter._factory_address == V2_FACTORY
    assert adapter.get_known_lockers() == KNOWN_LOCKERS
    assert adapter.get_whitelisted_routers() == WHITELISTED_ROUTERS
    assert adapter.get_known_spenders() == KNOWN_SPENDERS
    assert adapter._router_v2_factories == ROUTER_V2_FACTORIES
    assert not set(WHITELISTED_ROUTERS) & set(KNOWN_SPENDERS)


def test_botchain_rpc_url_can_be_configured(monkeypatch):
    monkeypatch.setenv("BOTCHAIN_RPC_URL", "https://rpc.invalid")
    assert BotChainAdapter().w3.provider.endpoint_uri == "https://rpc.invalid"
    assert BotChainAdapter("https://override.invalid").w3.provider.endpoint_uri == "https://override.invalid"


@pytest.mark.asyncio
async def test_botchain_token_info_retries_a_transient_429():
    adapter = BotChainAdapter("https://rpc.invalid")
    adapter.w3 = MagicMock()
    functions = adapter.w3.eth.contract.return_value.functions
    name_call = functions.name.return_value.call
    name_call.side_effect = [
        requests.exceptions.HTTPError(response=MagicMock(status_code=429)),
        "Token",
    ]
    functions.symbol.return_value.call.return_value = "TKN"
    functions.decimals.return_value.call.return_value = 18
    functions.totalSupply.return_value.call.return_value = 100 * 10**18

    with patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock) as sleep:
        info = await adapter.get_token_info(TOKEN)

    assert info == {"name": "Token", "symbol": "TKN", "decimals": 18, "total_supply": 100.0}
    assert name_call.call_count == 2
    assert [call.args[0] for call in sleep.await_args_list] == [1.0]


@pytest.mark.asyncio
async def test_botchain_honeypot_fields_are_unknown_without_a_provider():
    adapter = BotChainAdapter("https://rpc.invalid")
    with patch("adapters.evm_base.aiohttp.ClientSession") as session:
        honeypot = await adapter.check_honeypot(TOKEN)
        taxes = await adapter.get_tax_info(TOKEN)
    session.assert_not_called()
    assert honeypot["status"] == taxes["status"] == "unknown"
    assert honeypot["reason"] == taxes["reason"] == (
        "Sellability unknown: no sell simulation on BOT Chain yet"
    )
    assert adapter.capabilities()["sell_simulation"] == "none"


@pytest.mark.asyncio
async def test_bot_token_returns_still_running_unknown_at_the_request_deadline(monkeypatch, bot_module):
    from analyzers.honeypot import HoneypotAnalyzer, STILL_RUNNING
    from core.analyzer import AnalyzerResult
    from core.registry import AnalyzerRegistry

    pending_result = asyncio.get_running_loop().create_future()

    async def never_finishes(*args, **kwargs):
        return await pending_result

    service = MagicMock(fetch_honeypot_data=AsyncMock(side_effect=never_finishes))
    registry = AnalyzerRegistry()
    structural_result = AnalyzerResult(
        name="structural", weight=0.4, score=0, data={"status": "ok"},
    )
    structural = MagicMock()
    structural.name = "structural"
    structural.weight = 0.4
    structural.analyze = AsyncMock(return_value=structural_result)
    registry.register(structural)
    registry.register(HoneypotAnalyzer(service))
    bot_module.container.registry = registry
    bot_module._get_token_info_with_timeout = AsyncMock(return_value={})
    captured = []

    def compute(results):
        captured.extend(results)
        return {
            "status": "unknown", "risk_level": "unknown",
            "coverage": {"honeypot": 0}, "coverage_reasons": {"honeypot": STILL_RUNNING},
        }

    bot_module.risk_engine = SimpleNamespace(compute_from_results=compute)
    monkeypatch.setattr(bot_module, "format_full_report", lambda *args, **kwargs: "report")
    monkeypatch.setattr("core.registry.RUN_ALL_DEADLINE_SECONDS", 0.1)
    clock_now = time.monotonic()
    monkeypatch.setattr(
        bot_module, "time", SimpleNamespace(
            monotonic=lambda: clock_now - 24.95, time=time.time,
        ),
    )
    status = SimpleNamespace(delete=AsyncMock())
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock(return_value=status)))

    await bot_module.check_token(update, TOKEN, chain_id=677)
    pending_result.set_result({"status": "unknown"})
    await asyncio.sleep(0)

    structural_row, honeypot_row = captured
    assert structural_row is structural_result
    assert honeypot_row.name == "honeypot"
    assert honeypot_row.error is None
    assert honeypot_row.data["status"] == "unknown"
    assert honeypot_row.data["reason"] == STILL_RUNNING
    service.fetch_honeypot_data.assert_awaited_once_with(TOKEN, chain_id=677)
    assert update.message.reply_text.await_args_list[-1].args[0] == "report"


@pytest.mark.asyncio
async def test_bot_contract_scan_passes_a_request_deadline_to_analyzers(monkeypatch, bot_module):
    from core.analyzer import AnalysisContext

    registry = MagicMock(run_all=AsyncMock(return_value=[]))
    bot_module.container.registry = registry
    bot_module._get_token_info_with_timeout = AsyncMock(return_value={})
    bot_module.risk_engine = MagicMock(compute_from_results=MagicMock(return_value={
        "status": "unknown", "risk_level": "unknown",
        "coverage": {}, "coverage_reasons": {},
    }))
    bot_module.ai_analyzer = MagicMock(is_available=MagicMock(return_value=False))
    monkeypatch.setattr(bot_module, "format_full_report", lambda *args, **kwargs: "report")
    status = SimpleNamespace(delete=AsyncMock())
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock(return_value=status)))
    before = time.monotonic()

    await bot_module.scan_contract(update, TOKEN, chain_id=677)

    context = registry.run_all.await_args.args[0]
    assert isinstance(context, AnalysisContext)
    assert context.extra["deadline"] - before == pytest.approx(25, abs=0.1)


@pytest.mark.asyncio
async def test_scan_bot_prefix_runs_analyzers_and_reports_unknown_sellability(monkeypatch, bot_module):
    from analyzers.honeypot import HoneypotAnalyzer
    from core.analyzer import AnalyzerResult
    from core.risk_engine import RiskEngine

    reason = "Sellability unknown: no sell simulation on BOT Chain yet"
    service = SimpleNamespace(fetch_honeypot_data=AsyncMock(return_value={"status": "unknown", "reason": reason}))
    honeypot = HoneypotAnalyzer(service)
    results = [
        AnalyzerResult("structural", 0.4, 0, data={"status": "ok", "is_verified": True}),
        AnalyzerResult("market", 0.25, 0, data={"status": "unknown", "liquidity_usd": None}),
        AnalyzerResult("behavioral", 0.2, 0, data={"status": "ok", "reputation_score": 80}),
    ]

    async def run_all(context):
        assert context.chain_id == 677
        return [*results, await honeypot.analyze(context)]

    registry = SimpleNamespace(run_all=AsyncMock(side_effect=run_all))
    bot_module.container.registry = registry
    bot_module.risk_engine = RiskEngine()
    bot_module._get_token_info_with_timeout = AsyncMock(return_value={})
    bot_module.ai_analyzer = SimpleNamespace(is_available=lambda: False)
    monkeypatch.setattr(bot_module, "_get_cached", lambda *args: None)
    monkeypatch.setattr(bot_module, "_set_cache", lambda *args: None)
    bot_module.web3_client.is_valid_address.return_value = True
    progress = SimpleNamespace(delete=AsyncMock())
    reply_text = AsyncMock(return_value=progress)
    update = SimpleNamespace(message=SimpleNamespace(reply_text=reply_text))

    await bot_module.scan_command(update, SimpleNamespace(args=["bot:" + TOKEN], user_data={}))

    registry.run_all.assert_awaited_once()
    service.fetch_honeypot_data.assert_awaited_once_with(TOKEN, chain_id=677)
    report = reply_text.await_args_list[-1].args[0]
    assert "*Chain:* BOT Chain (677)" in report
    assert reason in report


def test_api_scan_accepts_chain_677(api_client, monkeypatch):
    import api

    result = {
        "address": TOKEN, "is_verified": None, "is_contract": True, "risk_level": "medium",
        "risk_score": 45, "confidence": 60, "checks": {}, "warnings": [], "scam_matches": [],
        "coverage": {}, "coverage_reasons": {}, "is_honeypot": None,
    }
    api.web3_client.validate_chain_id.side_effect = lambda chain_id: chain_id
    api.tx_scanner.scan_address = AsyncMock(return_value=result)

    response = api_client.post("/api/scan", json={"address": TOKEN, "chainId": 677})

    assert response.status_code == 200
    api.web3_client.validate_chain_id.assert_any_call(677)
    api.tx_scanner.scan_address.assert_awaited_once_with(TOKEN, chain_id=677, forensic=False)


def test_counterparty_allowlist_uses_the_botchain_adapter_for_approval_tokens():
    from services.counterparty_service import CounterpartyService

    adapter = BotChainAdapter("https://rpc.invalid")
    web3 = SimpleNamespace(_get_adapter=lambda chain_id: adapter if chain_id == 677 else None)
    service = CounterpartyService(web3, MagicMock())

    assert service.allowlisted_name(next(iter(WHITELISTED_ROUTERS)), 677) == "BDEX V2 Router02"
    assert service.allowlisted_name(next(iter(WHITELISTED_ROUTERS)), 56) is None


@pytest.mark.asyncio
async def test_api_firewall_approval_enrichment_uses_botchain_token_and_spender(monkeypatch):
    import api
    from services.counterparty_service import CounterpartyService

    spender = next(iter(WHITELISTED_ROUTERS))
    adapter = BotChainAdapter("https://rpc.invalid")
    web3 = SimpleNamespace(_get_adapter=lambda chain_id: adapter if chain_id == 677 else None)
    api.container = SimpleNamespace(counterparty_service=CounterpartyService(web3, MagicMock()))
    resolve_token = AsyncMock(return_value={"name": "Token", "symbol": "TKN", "decimals": 18})
    monkeypatch.setattr(api, "_resolve_token", resolve_token)
    decoded = {
        "selector": "095ea7b3", "is_approval": True, "function_name": "approve",
        "params": {"param_0": spender, "param_1": 1},
    }

    await api._enrich_decoded(decoded, TOKEN, chain_id=677)

    resolve_token.assert_awaited_once_with(TOKEN, chain_id=677)
    assert decoded["token_symbol"] == "TKN"
    assert decoded["spender_label"] == "BDEX V2 Router02"


def test_firewall_deadline_follows_adapter_simulation_support(monkeypatch):
    import api

    monkeypatch.setattr(
        api, "web3_client",
        SimpleNamespace(supports_honeypot_simulation=lambda chain_id: chain_id in {42161, 4663}),
    )
    assert api._firewall_deadline(SimpleNamespace(chainId=42161), 100.0) == (
        100.0 + api.FIREWALL_REQUEST_DEADLINE_SECONDS
    )
    assert api._firewall_deadline(SimpleNamespace(chainId=4663), 100.0) == (
        100.0 + api.FIREWALL_REQUEST_DEADLINE_SECONDS
    )
    assert api._firewall_deadline(SimpleNamespace(chainId=56), 100.0) is None


@pytest.mark.parametrize(
    "chain_id, expected, excluded",
    [
        (4663, "sequencer's soft finality, final on the parent chain once the batch is posted", "BOT Chain"),
        (677, "Compare the evidence hash with the BOT Chain transaction's VerdictRecorded event", "sequencer"),
    ],
)
def test_verdict_permalink_verification_copy_is_chain_specific(
    api_client, monkeypatch, chain_id, expected, excluded,
):
    import api

    stored = {
        "chain_id": chain_id, "subject": TOKEN, "verdict": "HIGH", "evidence_hash": "0xabc",
        "observed_block": 1, "canonical": "{}", "created_at": 1.0, "onchain_status": "confirmed",
        "registry": "0x123", "tx_hash": "0x456", "onchain_error": None,
    }
    api.web3_client.validate_chain_id.side_effect = lambda value: value
    api.container = SimpleNamespace(
        db=SimpleNamespace(get_latest_verdict_evidence=AsyncMock(return_value=stored)),
    )

    response = api_client.get(f"/api/verdict/{chain_id}/{TOKEN}")

    assert response.status_code == 200
    verify = response.json()["verify"]
    assert expected in verify
    assert excluded not in verify
