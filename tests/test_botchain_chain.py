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
