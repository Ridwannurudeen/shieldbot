"""The overall per-scan deadline in AnalyzerRegistry.run_all."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import utils.scam_db as scam_db
from agent.tools import AgentTools
from analyzers.honeypot import HoneypotAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.extension_formatter import is_scan_incomplete
from core.registry import BACKGROUND_SCAN_DEADLINE_SECONDS, RUN_ALL_DEADLINE_SECONDS, AnalyzerRegistry
from core.risk_engine import RiskEngine
from services.honeypot_service import HoneypotService
from services.robinhood_simulation import RPC_BACKOFF_SECONDS, RPC_TIMEOUT_SECONDS
from utils.web3_client import UnsupportedChainError

# Provider timeouts on the scan path, in seconds: honeypot.is per request (adapters/evm_base.py
# check_honeypot and get_tax_info), GoPlus per request (utils/scam_db.py), explorer calls
# (services/explorer_service.py), and the extension's firewall request abort (extension/background.js).
HONEYPOT_IS_TIMEOUT = 10
GOPLUS_TIMEOUT = 8
EXPLORER_TIMEOUT = 15
EXTENSION_ABORT = 30
# A healthy 4663 scan's duration: the p90 of the scans measured live on 2026-09-19.
HEALTHY_SCAN_SECONDS = 5.4
# Timing scenarios run at this fraction of real time.
SCALE = 0.04
TOKEN = "0x" + "12" * 20


def analyzer(name, weight, behaviour):
    """An analyzer whose analyze() runs ``behaviour`` (a coroutine function taking ctx)."""
    mock = MagicMock()
    mock.name = name
    mock.weight = weight
    mock.analyze = behaviour
    return mock


def returns(result):
    async def analyze(ctx):
        return result
    return analyze


def raises(error):
    async def analyze(ctx):
        raise error
    return analyze


def hangs(events=None):
    async def analyze(ctx):
        try:
            await asyncio.Event().wait()
        finally:
            if events is not None:
                events.append("cancelled")
    return analyze


def clean(name, weight, **data):
    return AnalyzerResult(name=name, weight=weight, score=0, flags=[], data={"status": "ok", "observed_at": 1000, **data})


def registry_of(*analyzers):
    registry = AnalyzerRegistry()
    for item in analyzers:
        registry.register(item)
    return registry


@pytest.fixture
def short_deadline():
    with patch("core.registry.RUN_ALL_DEADLINE_SECONDS", 0.05):
        yield


@pytest.mark.asyncio
async def test_an_analyzer_running_at_the_deadline_becomes_the_failed_analyzer_result(short_deadline):
    fast = clean("structural", 0.4)
    timed_out = await registry_of(
        analyzer("structural", 0.4, returns(fast)),
        analyzer("honeypot", 0.6, hangs()),
    ).run_all(AnalysisContext(address="0xabc", chain_id=4663))
    failed = await registry_of(
        analyzer("structural", 0.4, returns(clean("structural", 0.4))),
        analyzer("honeypot", 0.6, raises(asyncio.TimeoutError())),
    ).run_all(AnalysisContext(address="0xabc", chain_id=4663))

    assert timed_out == failed
    assert timed_out[0] is fast
    assert timed_out[1] == AnalyzerResult(
        name="honeypot",
        weight=0.6,
        score=50,
        flags=["honeypot analysis unavailable"],
        error="honeypot analysis unavailable (TimeoutError)",
    )


@pytest.mark.asyncio
async def test_a_scan_cut_by_the_deadline_is_incomplete_never_safe(short_deadline):
    results = await registry_of(
        analyzer("structural", 0.4, returns(clean(
            "structural", 0.4, is_contract=True, is_verified=True, contract_age_days=400,
        ))),
        analyzer("market", 0.25, returns(clean("market", 0.25))),
        analyzer("behavioral", 0.2, returns(clean("behavioral", 0.2))),
        analyzer("honeypot", 0.15, hangs()),
    ).run_all(AnalysisContext(address="0xabc", chain_id=56))

    output = RiskEngine().compute_from_results(results)

    assert output["status"] == "unknown"
    assert output["coverage"]["honeypot"] == 0
    assert output["coverage_reasons"]["honeypot"] == "honeypot analysis unavailable (TimeoutError)"
    assert is_scan_incomplete(output)


@pytest.mark.asyncio
async def test_the_timed_out_analyzer_is_cancelled_before_run_all_returns(short_deadline):
    events = []
    await registry_of(analyzer("honeypot", 1.0, hangs(events))).run_all(AnalysisContext(address="0xabc"))

    assert events == ["cancelled"]


@pytest.mark.asyncio
async def test_cancelling_a_scan_cancels_its_running_analyzers():
    events = []
    started = asyncio.Event()

    async def slow(ctx):
        started.set()
        await hangs(events)(ctx)

    scan = asyncio.ensure_future(
        registry_of(analyzer("structural", 1.0, slow)).run_all(AnalysisContext(address="0xabc"))
    )
    await started.wait()
    scan.cancel()
    with pytest.raises(asyncio.CancelledError):
        await scan

    assert events == ["cancelled"]


@pytest.mark.asyncio
async def test_unsupported_chain_still_raises_before_the_deadline(short_deadline):
    error = UnsupportedChainError("unsupported chain")
    with pytest.raises(UnsupportedChainError) as caught:
        await registry_of(
            analyzer("structural", 0.5, raises(error)),
            analyzer("honeypot", 0.5, hangs()),
        ).run_all(AnalysisContext(address="0xabc", chain_id=999))

    assert caught.value is error


async def gather_reference(analyzers, ctx):
    """run_all as it was before the deadline: asyncio.gather with return_exceptions."""
    results = await asyncio.gather(*[a.analyze(ctx) for a in analyzers], return_exceptions=True)
    final = []
    for item, result in zip(analyzers, results):
        if isinstance(result, Exception):
            final.append(AnalyzerResult(
                name=item.name, weight=item.weight, score=50,
                flags=[f"{item.name} analysis unavailable"],
                error=f"{item.name} analysis unavailable ({type(result).__name__})",
            ))
        else:
            final.append(result)
    total = sum(r.weight for r in final)
    if total > 0 and abs(total - 1.0) > 1e-9:
        for r in final:
            r.weight = r.weight / total
    return final


def bsc_analyzers():
    """A fully covered BSC token plus one failing provider, rebuilt fresh for every run."""
    return [
        analyzer("structural", 0.40, returns(AnalyzerResult(
            name="structural", weight=0.40, score=15, flags=["Contract not verified"],
            data={"is_contract": True, "is_verified": False, "contract_age_days": 90, "status": "ok"},
        ))),
        analyzer("market", 0.25, returns(AnalyzerResult(
            name="market", weight=0.25, score=0, flags=[],
            data={"liquidity_usd": 250000, "status": "ok"},
        ))),
        analyzer("behavioral", 0.20, raises(RuntimeError("provider down"))),
        analyzer("honeypot", 0.15, returns(AnalyzerResult(
            name="honeypot", weight=0.15, score=0, flags=[],
            data={"is_honeypot": False, "can_sell": True, "buy_tax": 0, "sell_tax": 0, "status": "ok"},
        ))),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("with_on_result", [False, True])
async def test_results_are_identical_to_gather_when_nothing_times_out(with_on_result):
    ctx = AnalysisContext(address="0xabc", chain_id=56)
    expected = await gather_reference(bsc_analyzers(), ctx)
    received = []
    registry = registry_of(*bsc_analyzers())
    if with_on_result:
        actual = await registry.run_all(ctx, on_result=received.append)
    else:
        actual = await registry.run_all(ctx)

    for previous, current in zip(expected, actual):
        if not current.error:
            assert current.data["observed_at"] > 0
            previous.data["observed_at"] = current.data["observed_at"]
    assert actual == expected
    engine = RiskEngine()
    assert json.dumps(engine.compute_from_results(actual), sort_keys=True) == json.dumps(
        engine.compute_from_results(expected), sort_keys=True
    )
    # Every analyzer that returned was reported, as the same object; the failed one was not.
    if with_on_result:
        assert sorted(result.name for result in received) == ["honeypot", "market", "structural"]
        assert all(any(result is final for final in actual) for result in received)


@pytest.mark.asyncio
async def test_on_result_hears_only_the_analyzers_that_returned(short_deadline):
    fast = clean("structural", 0.5)
    received = []

    results = await registry_of(
        analyzer("structural", 0.5, returns(fast)),
        analyzer("market", 0.2, raises(RuntimeError("provider down"))),
        analyzer("honeypot", 0.3, hangs()),
    ).run_all(AnalysisContext(address="0xabc", chain_id=56), on_result=received.append)

    assert received == [fast]
    assert [result.error for result in results] == [
        None,
        "market analysis unavailable (RuntimeError)",
        "honeypot analysis unavailable (TimeoutError)",
    ]


@pytest.mark.asyncio
async def test_on_result_is_called_while_other_analyzers_still_run():
    release = asyncio.Event()
    fast = clean("structural", 0.5)
    heard = asyncio.Event()

    async def slow(ctx):
        await release.wait()
        return clean("honeypot", 0.5)

    scan = asyncio.ensure_future(registry_of(
        analyzer("structural", 0.5, returns(fast)),
        analyzer("honeypot", 0.5, slow),
    ).run_all(AnalysisContext(address="0xabc", chain_id=56), on_result=lambda result: heard.set()))

    await asyncio.wait_for(heard.wait(), 1)
    assert not scan.done()
    release.set()
    assert [result.name for result in await scan] == ["structural", "honeypot"]


def test_the_deadlines_follow_the_provider_timeout_table():
    # Interactive: both sequential honeypot.is timeouts and the cached GoPlus fallback fit, and so
    # does the longest single call (explorer), before the extension abandons the request.
    assert 2 * HONEYPOT_IS_TIMEOUT < RUN_ALL_DEADLINE_SECONDS < EXTENSION_ABORT
    assert EXPLORER_TIMEOUT < RUN_ALL_DEADLINE_SECONDS
    # Background: one full simulator RPC timeout plus its 1 s and 2 s backoff and a healthy scan's
    # other work, and the whole honeypot.is chain with an uncached GoPlus call.
    assert RPC_TIMEOUT_SECONDS + 3 * RPC_BACKOFF_SECONDS + HEALTHY_SCAN_SECONDS <= BACKGROUND_SCAN_DEADLINE_SECONDS
    assert 2 * HONEYPOT_IS_TIMEOUT + GOPLUS_TIMEOUT < BACKGROUND_SCAN_DEADLINE_SECONDS


@pytest.mark.asyncio
async def test_a_hanging_honeypot_is_still_reaches_the_cached_goplus_answer_within_the_interactive_deadline():
    async def honeypot_is_timeout(address, chain_id=56):
        await asyncio.sleep(HONEYPOT_IS_TIMEOUT * SCALE)
        return {
            "is_honeypot": None, "status": "unknown",
            "reason": "Error checking honeypot.is: TimeoutError", "field_providers": {},
        }

    web3_client = MagicMock()
    web3_client.get_supported_chain_ids.return_value = [56]
    web3_client.check_honeypot = AsyncMock(side_effect=honeypot_is_timeout)
    web3_client.get_tax_info = AsyncMock(side_effect=honeypot_is_timeout)
    # The structural analyzer's scam check has already fetched GoPlus for this token.
    scam_db._GOPLUS_CACHE[(56, TOKEN)] = {"status": "ok", "reason": None, "data": {
        "is_honeypot": "0", "cannot_buy": "0", "cannot_sell_all": "0",
        "transfer_pausable": "0", "buy_tax": "0", "sell_tax": "0",
    }}
    try:
        with patch("core.registry.RUN_ALL_DEADLINE_SECONDS", RUN_ALL_DEADLINE_SECONDS * SCALE):
            (honeypot,) = await registry_of(HoneypotAnalyzer(HoneypotService(web3_client))).run_all(
                AnalysisContext(address=TOKEN, chain_id=56)
            )
    finally:
        del scam_db._GOPLUS_CACHE[(56, TOKEN)]

    assert honeypot.error is None
    assert honeypot.data["status"] == "ok"
    assert honeypot.data["field_providers"]["is_honeypot"] == "goplus"
    assert web3_client.check_honeypot.await_count == web3_client.get_tax_info.await_count == 1


@pytest.mark.asyncio
async def test_a_background_scan_outlasts_a_full_simulator_request_that_an_interactive_scan_cuts():
    async def slow_simulation(ctx):
        await asyncio.sleep(RPC_TIMEOUT_SECONDS * SCALE)
        return clean("honeypot", 1.0, is_honeypot=False, can_sell=True, buy_tax=0, sell_tax=0)

    container = MagicMock(risk_engine=RiskEngine())
    container.registry = registry_of(analyzer("honeypot", 1.0, slow_simulation))
    container.robinhood_assets.check_onchain = AsyncMock(
        return_value={"status": "none", "symbol": None, "official_address": None, "reason": None}
    )
    tools = AgentTools(container)

    with patch("core.registry.RUN_ALL_DEADLINE_SECONDS", RUN_ALL_DEADLINE_SECONDS * SCALE):
        interactive = await tools.scan_contract(TOKEN, chain_id=4663)
        background = await tools.scan_contract(
            TOKEN, chain_id=4663, deadline=BACKGROUND_SCAN_DEADLINE_SECONDS * SCALE
        )

    assert interactive["coverage_reasons"]["honeypot"] == "honeypot analysis unavailable (TimeoutError)"
    assert "honeypot" not in background["coverage_reasons"]
    assert background["coverage"]["honeypot"] == 1
