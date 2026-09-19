"""The overall per-scan deadline in AnalyzerRegistry.run_all."""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

from core.analyzer import AnalysisContext, AnalyzerResult
from core.extension_formatter import is_scan_incomplete
from core.registry import RUN_ALL_DEADLINE_SECONDS, AnalyzerRegistry
from core.risk_engine import RiskEngine
from utils.web3_client import UnsupportedChainError


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
    return AnalyzerResult(name=name, weight=weight, score=0, flags=[], data={"status": "ok", **data})


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
async def test_results_are_identical_to_gather_when_nothing_times_out():
    ctx = AnalysisContext(address="0xabc", chain_id=56)
    expected = await gather_reference(bsc_analyzers(), ctx)
    actual = await registry_of(*bsc_analyzers()).run_all(ctx)

    assert actual == expected
    engine = RiskEngine()
    assert json.dumps(engine.compute_from_results(actual), sort_keys=True) == json.dumps(
        engine.compute_from_results(expected), sort_keys=True
    )


def test_deadline_outlasts_single_provider_timeouts_and_beats_the_extension_abort():
    # 15 s is the longest single provider timeout on the scan path (explorer calls); the
    # extension abandons a firewall request after 30 s.
    assert 15 < RUN_ALL_DEADLINE_SECONDS < 30
