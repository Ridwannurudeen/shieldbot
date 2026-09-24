"""POST /api/firewall with Accept: text/event-stream: an interim verdict while the scan runs, then the
plain response as the final event. The interim is never SAFE, STRICT sends none, the final and every
side effect are exactly the plain route's, and nothing on the path buffers the stream."""

import asyncio
import gc
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.responses import StreamingResponse

from core import verdicts
from core.analyzer import AnalyzerResult
from core.policy import PolicyEngine
from core.registry import FIRST_VERDICT_SECONDS, AnalyzerRegistry
from core.risk_engine import RiskEngine
from tests.test_strict_cache import strict_api  # noqa: F401  (pytest fixture)
from utils.scam_db import ScamDatabase
from utils.web3_client import UnsupportedChainError

TARGET = "0x" + "ab" * 20
CALLER = "0x" + "9f" * 20
TOKEN_A = "0x" + "11" * 20
TOKEN_B = "0x" + "22" * 20
BODY = {"to": TARGET, "from": CALLER, "value": "0", "data": "0x", "chainId": 56}
NOW = 1_790_000_000.0
WEIGHTS = {"structural": 0.40, "market": 0.25, "behavioral": 0.20, "honeypot": 0.15}
ADMIN_MATCH = {"type": "Local Blacklist", "reason": "Confirmed scam address", "source": "ShieldBot", "severity": "block"}
GOPLUS_BLOCK = {"type": "GoPlus Security", "reason": "Airdrop scam token", "source": "gopluslabs.io", "severity": "block"}
GOPLUS_HIGH = {"type": "GoPlus Security", "reason": "Owner can change balance", "source": "gopluslabs.io", "severity": "high"}
COMMUNITY_MATCH = {
    "type": "community_reports",
    "reason": "Reported by 3 users",
    "source": "ShieldBot",
    "severity": "medium",
    "reports": 3,
}
# A complete SAFE verdict for TARGET, stored a minute before the test's clock.
SAFE_ROW = {
    "risk_score": 0,
    "risk_level": "LOW",
    "flags": [],
    "archetype": "legitimate",
    "confidence": 90,
    "scan_count": 1,
    "last_scanned_at": NOW - 60,
    "category_scores": {
        **dict.fromkeys(WEIGHTS, 0),
        "_scan_metadata": {
            "status": "ok",
            "coverage": dict.fromkeys(WEIGHTS, 1),
            "coverage_reasons": {},
            "risk_display": "0%",
            "notes": [],
        },
    },
}
SWAP = {
    "selector": "38ed1739",
    "function_name": "swapExactTokensForTokens",
    "category": "swap",
    "params": {"param_2": [TOKEN_A, TOKEN_B]},
}
# Timing scenarios run at this fraction of real time, as in tests/test_scan_deadline.py.
SCALE = 0.02
# How long any single step may take before the test fails instead of hanging.
TIMEOUT = 5


def result(name, scam_matches=()):
    """A fully covered result; a scam match adds the structural analyzer's points and flag."""
    data = {
        "structural": {
            "is_contract": True,
            "is_verified": True,
            "contract_age_days": 400,
            "coverage": {"is_verified": True, "contract_age_days": True, "scam_database": True},
            "scam_matches": list(scam_matches),
        },
        "market": {"liquidity_usd": 50_000},
        "behavioral": {"reputation_score": 50},
        "honeypot": {"is_honeypot": False, "can_sell": True, "buy_tax": 0, "sell_tax": 0},
    }[name]
    flags = [f"Scam DB match ({len(scam_matches)} sources)"] if scam_matches else []
    return AnalyzerResult(name, WEIGHTS[name], 30 if scam_matches else 0, flags=flags, data={**data, "status": "ok"})


def returns(name, scam_matches=()):
    async def analyze(ctx):
        return result(name, scam_matches)
    return analyze


def held(name, gate, scam_matches=()):
    async def analyze(ctx):
        await gate.wait()
        return result(name, scam_matches)
    return analyze


def registry(**behaviours):
    """A real AnalyzerRegistry of the four target analyzers; `behaviours` replaces some of them."""
    analyzers = AnalyzerRegistry()
    for name in WEIGHTS:
        analyzer = MagicMock()
        analyzer.name = name
        analyzer.weight = WEIGHTS[name]
        analyzer.analyze = behaviours.get(name, returns(name))
        analyzers.register(analyzer)
    return analyzers


class FailingRegistry:
    """A registry whose run_all raises `error` once the gate opens."""

    def __init__(self, gate, error=None):
        self.gate = gate
        self.error = error or RuntimeError("pipeline down")

    def get_all(self):
        return [SimpleNamespace(name=name) for name in WEIGHTS]

    async def run_all(self, ctx, deadline=None, on_result=None):
        await self.gate.wait()
        raise self.error


@pytest.fixture
def stream_api(monkeypatch, mock_web3_client):
    import api

    mock_web3_client.is_token_contract = AsyncMock(return_value=True)
    services = SimpleNamespace(
        web3_client=mock_web3_client,
        db=SimpleNamespace(
            get_contract_score=AsyncMock(return_value=None),
            get_deployer_risk_summary=AsyncMock(return_value=None),
            upsert_contract_score=AsyncMock(),
            insert_scan_evidence=AsyncMock(),
        ),
        registry=registry(),
        policy_engine=PolicyEngine(),
        indexer=MagicMock(),
        threat_graph=SimpleNamespace(enrich_from_scan=AsyncMock()),
        sentinel=SimpleNamespace(on_scan_blocked=AsyncMock()),
        counterparty_service=None,
        auth_manager=None,
        settings=SimpleNamespace(trusted_proxies=[], public_api_url="https://api.example"),
    )
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", mock_web3_client)
    monkeypatch.setattr(
        api,
        "calldata_decoder",
        SimpleNamespace(decode=lambda data: {"selector": None}, is_whitelisted_target=lambda *args, **kwargs: None),
    )
    monkeypatch.setattr(api, "risk_engine", RiskEngine())
    monkeypatch.setattr(api, "scam_db", ScamDatabase())
    monkeypatch.setattr(api, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    monkeypatch.setattr(api, "greenfield_service", None)
    monkeypatch.setattr(api, "ai_analyzer", SimpleNamespace(is_available=lambda: False))
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    monkeypatch.setattr(api, "_token_cache", {})
    return api, services


def blacklist(api):
    """An admin entry for TARGET on every chain: a local match that is a Block-level floor."""
    api.scam_db.known_scams[(None, TARGET)] = {"source": "admin", "reports": 0, "expires_at": None}


def timer(monkeypatch, api, seconds):
    monkeypatch.setattr(api, "FIRST_VERDICT_SECONDS", seconds)


def side_effects(services):
    return {
        "insert_scan_evidence": services.db.insert_scan_evidence.await_count,
        "upsert_contract_score": services.db.upsert_contract_score.await_count,
        "enrich_from_scan": services.threat_graph.enrich_from_scan.call_count,
        "on_scan_blocked": services.sentinel.on_scan_blocked.call_count,
        "enqueue": services.indexer.enqueue.call_count,
    }


def plain_request(**headers):
    return SimpleNamespace(headers=headers, state=SimpleNamespace())


def events_of(api, body=BODY):
    """The stream's events for `body`, driven directly, the handler starting now."""
    return api._firewall_events(api.FirewallRequest(**body), plain_request(), time.monotonic(), "BALANCED")


def parse(text):
    """The (event, data) pairs of a server-sent event stream."""
    events = []
    for block in text.split("\n\n"):
        if block:
            fields = dict(line.split(": ", 1) for line in block.split("\n"))
            events.append((fields["event"], json.loads(fields["data"])))
    return events


async def next_event(events):
    return parse(await asyncio.wait_for(events.__anext__(), TIMEOUT))[0]


async def remaining(events):
    return [pair async for chunk in events for pair in parse(chunk)]


def scan_task():
    (task,) = [task for task in asyncio.all_tasks() if task.get_coro().__qualname__ == "_firewall_response"]
    return task


async def post(api, **headers):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as client:
        return await client.post("/api/firewall", json=BODY, headers=headers)


@pytest.mark.asyncio
@pytest.mark.parametrize("server_mode, header", [("BALANCED", "STRICT"), ("STRICT", None)])
async def test_strict_sends_no_first_and_answers_as_today(strict_api, server_mode, header):  # noqa: F811
    api, services = strict_api
    services.policy_engine = PolicyEngine(server_mode)
    policy = {"X-Policy-Mode": header} if header else {}
    req = api.FirewallRequest(to="0x" + "a" * 40, sender="0x" + "b" * 40)

    with patch("time.time", return_value=NOW):
        today = await api.firewall(req, plain_request(**policy))
        streamed = await api.firewall(req, plain_request(**policy, accept="text/event-stream"))

    assert not isinstance(streamed, StreamingResponse)
    assert streamed == today
    assert (streamed["policy_mode"], streamed["classification"]) == ("STRICT", verdicts.BLOCK_RECOMMENDED)
    assert "final" not in streamed


@pytest.mark.asyncio
async def test_a_strict_stream_request_through_the_app_gets_the_plain_json(stream_api):
    api, services = stream_api
    services.policy_engine = PolicyEngine("STRICT")

    with patch("time.time", return_value=NOW):
        plain = await post(api)
        streamed = await post(api, accept="text/event-stream")

    assert streamed.headers["content-type"] == "application/json"
    assert streamed.content == plain.content
    assert streamed.json()["policy_mode"] == "STRICT"


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked", [False, True])
async def test_the_final_event_is_the_plain_response(stream_api, blocked):
    api, services = stream_api
    if blocked:
        blacklist(api)
        services.registry = registry(structural=returns("structural", [ADMIN_MATCH]))

    with patch("time.time", return_value=NOW):
        plain = await post(api)
        streamed = await post(api, accept="text/event-stream")

    assert streamed.status_code == 200
    assert streamed.headers["content-type"].startswith("text/event-stream")
    assert (streamed.headers["cache-control"], streamed.headers["x-accel-buffering"]) == ("no-cache", "no")
    *interim, (kind, final) = parse(streamed.text)
    assert kind == "final"
    assert all(event == "first" and first["status"] == "unknown" for event, first in interim)
    assert final.pop("final") is True
    assert final == plain.json()
    body = plain.json()
    assert (final["risk_score"], final["status"], final["shield_score"]["risk_level"], final["evidence_hash"]) == (
        body["risk_score"],
        body["status"],
        body["shield_score"]["risk_level"],
        body["evidence_hash"],
    )
    assert final["evidence_hash"] is not None
    assert final["classification"] == (verdicts.BLOCK_RECOMMENDED if blocked else verdicts.SAFE)


@pytest.mark.asyncio
async def test_a_request_without_the_stream_header_is_answered_as_before(stream_api):
    api, _ = stream_api

    with patch("time.time", return_value=NOW):
        plain = await post(api)
        as_json = await post(api, accept="application/json")
        anything = await post(api, accept="*/*")

    assert plain.headers["content-type"] == "application/json"
    assert plain.content == as_json.content == anything.content
    assert "final" not in plain.json()


@pytest.mark.asyncio
async def test_a_server_without_an_analyzer_registry_still_streams(stream_api, monkeypatch):
    api, services = stream_api
    services.registry = None
    # Without a registry the handler falls back to the four services directly, as it always has.
    for name, method, data in (
        ("contract_service", "fetch_contract_data", result("structural").data),
        ("honeypot_service", "fetch_honeypot_data", result("honeypot").data),
        ("dex_service", "fetch_token_market_data", result("market").data),
        ("ethos_service", "fetch_wallet_reputation", {"reputation_score": 50, "status": "ok"}),
    ):
        monkeypatch.setattr(api, name, SimpleNamespace(**{method: AsyncMock(return_value=data)}))

    with patch("time.time", return_value=NOW):
        plain = await post(api)
        streamed = await post(api, accept="text/event-stream")

    kind, final = parse(streamed.text)[-1]
    assert kind == "final" and final.pop("final") is True
    assert final == plain.json()


@pytest.mark.asyncio
async def test_a_target_without_a_local_entry_is_still_answered_from_the_cache(stream_api):
    api, services = stream_api
    services.db.get_contract_score.return_value = SAFE_ROW

    with patch("time.time", return_value=NOW):
        plain = await post(api)
        streamed = await post(api, accept="text/event-stream")

    body = plain.json()
    assert (body["cached"], body["classification"]) == (True, verdicts.SAFE)
    assert services.db.upsert_contract_score.await_count == 0
    # The cached branch answers at once: the stream is the final alone.
    [(kind, final)] = parse(streamed.text)
    assert kind == "final" and final.pop("final") is True
    assert final == body


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "entry, match, classification",
    [
        ({"source": "admin", "reports": 0, "expires_at": None}, ADMIN_MATCH, verdicts.BLOCK_RECOMMENDED),
        ({"source": "community", "reports": 3, "expires_at": None}, COMMUNITY_MATCH, verdicts.CAUTION),
    ],
    ids=["admin", "community"],
)
async def test_a_target_blacklisted_since_its_cached_row_is_scanned_afresh(stream_api, entry, match, classification):
    api, services = stream_api
    services.db.get_contract_score.return_value = SAFE_ROW
    # The entry arrives after the row was written; the target's scan reports it, as check_address does.
    api.scam_db.known_scams[(56, TARGET)] = entry
    services.registry = registry(structural=returns("structural", [match]))

    with patch("time.time", return_value=NOW):
        plain = await post(api)
        streamed = await post(api, accept="text/event-stream")

    body = plain.json()
    assert "cached" not in body
    assert body["classification"] == classification
    assert body["risk_score"] >= verdicts.CAUTION_MIN
    assert services.db.upsert_contract_score.await_count == 2
    kind, final = parse(streamed.text)[-1]
    assert kind == "final" and final.pop("final") is True
    assert final == body


@pytest.mark.asyncio
async def test_side_effects_come_only_from_the_final(stream_api, monkeypatch):
    api, services = stream_api
    blacklist(api)
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS / SCALE)
    gate = asyncio.Event()
    gate.set()
    services.registry = registry(structural=returns("structural", [ADMIN_MATCH]), honeypot=held("honeypot", gate))
    await api.firewall(api.FirewallRequest(**BODY), plain_request())
    today = side_effects(services)
    assert today == dict.fromkeys(today, 1)
    for mock in (
        services.db.insert_scan_evidence,
        services.db.upsert_contract_score,
        services.threat_graph.enrich_from_scan,
        services.sentinel.on_scan_blocked,
        services.indexer.enqueue,
    ):
        mock.reset_mock()
    gate.clear()

    events = events_of(api)
    kind, first = await next_event(events)

    assert kind == "first"
    assert side_effects(services) == dict.fromkeys(today, 0)
    assert not {"evidence_hash", "evidence_url", "cached"} & set(first)
    assert (first["classification"], first["status"], first["final"]) == (verdicts.BLOCK_RECOMMENDED, "unknown", False)
    gate.set()
    kind, final = await next_event(events)
    assert kind == "final"
    assert side_effects(services) == today
    assert final["evidence_hash"] and final["final"] is True
    assert await remaining(events) == []


@pytest.mark.asyncio
async def test_the_first_comes_at_the_timer_while_an_analyzer_hangs(stream_api, monkeypatch, caplog):
    api, services = stream_api
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS * SCALE)
    gate = asyncio.Event()
    services.registry = registry(honeypot=held("honeypot", gate))

    with caplog.at_level("INFO", logger="api"):
        events = events_of(api)
        kind, first = await next_event(events)

        assert kind == "first"
        assert not scan_task().done()
        assert (first["classification"], first["risk_score"], first["risk_display"]) == (
            verdicts.CAUTION,
            0,
            "Unknown (analysis in progress)",
        )
        assert first["pending_sources"] == ["honeypot"]
        assert set(first["coverage"]) == {"structural", "market", "behavioral"}
        assert first["coverage_reasons"] == {"pending": "Full analysis in progress: honeypot"}
        assert first["transaction_impact"]["recipient"] == TARGET
        gate.set()
        kind, final = await next_event(events)
        assert kind == "final" and final["classification"] == verdicts.SAFE
        assert await remaining(events) == []

    [line] = [record.getMessage() for record in caplog.records if record.getMessage().startswith("Firewall stream ")]
    timings = json.loads(line.removeprefix("Firewall stream "))
    assert (timings["chain_id"], timings["first_kind"], timings["pending_at_first"]) == (56, "unknown", ["honeypot"])
    assert timings["first_at_ms"] == first["elapsed_ms"] <= timings["final_at_ms"]


@pytest.mark.asyncio
async def test_an_admin_blacklist_match_sends_the_first_before_the_timer(stream_api, monkeypatch, caplog):
    api, services = stream_api
    blacklist(api)
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS / SCALE)
    gate = asyncio.Event()
    services.registry = registry(structural=held("structural", gate, [ADMIN_MATCH]))

    with caplog.at_level("INFO", logger="api"):
        events = events_of(api)
        kind, first = await next_event(events)

        assert kind == "first"
        assert (first["classification"], first["risk_score"], first["status"]) == (
            verdicts.BLOCK_RECOMMENDED,
            90,
            "unknown",
        )
        assert first["danger_signals"][0] == "Confirmed scam address"
        assert "structural" in first["pending_sources"]
        gate.set()
        kind, final = await next_event(events)
        await remaining(events)

    assert kind == "final"
    # The target's own scan has the same entry (check_address reports it), so the final holds the floor.
    assert final["classification"] == verdicts.BLOCK_RECOMMENDED
    assert '"first_kind": "block"' in caplog.text


@pytest.mark.asyncio
async def test_a_scan_that_finishes_before_the_timer_sends_only_the_final(stream_api, monkeypatch, caplog):
    api, _ = stream_api
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS / SCALE)

    with caplog.at_level("INFO", logger="api"):
        events = await remaining(events_of(api))

    assert [kind for kind, _ in events] == ["final"]
    assert '"first_kind": "none"' in caplog.text


@pytest.mark.asyncio
async def test_a_hanging_pre_step_still_gets_the_first_at_the_timer(stream_api, monkeypatch, mock_web3_client):
    api, _ = stream_api
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS * SCALE)
    gate = asyncio.Event()

    async def verification(*args, **kwargs):
        await gate.wait()
        return (True, None)

    mock_web3_client.is_verified_contract = AsyncMock(side_effect=verification)
    events = events_of(api)
    kind, first = await next_event(events)

    assert kind == "first"
    assert not scan_task().done()
    assert first["pending_sources"] == sorted(WEIGHTS)
    assert (first["coverage"], first["classification"], first["status"]) == ({}, verdicts.CAUTION, "unknown")
    gate.set()
    assert [kind for kind, _ in await remaining(events)] == ["final"]


@pytest.mark.asyncio
async def test_a_signature_request_has_nothing_to_show_before_its_final(stream_api, monkeypatch, mock_web3_client):
    api, _ = stream_api
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS * SCALE)
    gate = asyncio.Event()
    mock_web3_client.is_valid_address = MagicMock(side_effect=lambda value: value.startswith("0x") and len(value) == 42)

    async def analyze(self, ctx):
        await gate.wait()
        return AnalyzerResult("signature", 0.1, 0, data={"sign_method": "personal_sign", "has_typed_data": False})

    monkeypatch.setattr("analyzers.signature.SignaturePermitAnalyzer.analyze", analyze)
    events = events_of(api, {**BODY, "to": "", "signMethod": "personal_sign"})
    pending = asyncio.ensure_future(events.__anext__())
    await asyncio.wait({pending}, timeout=FIRST_VERDICT_SECONDS * SCALE * 3)

    assert not pending.done()
    gate.set()
    kind, final = parse(await asyncio.wait_for(pending, TIMEOUT))[0]
    assert (kind, final["policy_mode"]) == ("final", "SIGNATURE_ONLY")
    assert await remaining(events) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("fails", [False, True])
async def test_a_client_that_leaves_after_the_first_does_not_stop_the_scan(stream_api, monkeypatch, caplog, fails):
    api, services = stream_api
    blacklist(api)
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS / SCALE)
    gate = asyncio.Event()
    if fails:
        services.registry = FailingRegistry(gate)
        monkeypatch.setattr(api, "token_scanner", SimpleNamespace(check_token=AsyncMock(side_effect=RuntimeError("down"))))
    else:
        services.registry = registry(structural=returns("structural", [ADMIN_MATCH]), honeypot=held("honeypot", gate))

    events = events_of(api)
    kind, _ = await next_event(events)
    assert kind == "first"
    scan = scan_task()
    await events.aclose()
    gate.set()
    await asyncio.wait_for(asyncio.wait({scan}), TIMEOUT)

    if fails:
        assert "Fire-and-forget task 'firewall_stream_scan' failed: HTTPException 500" in caplog.text
    else:
        assert services.db.upsert_contract_score.await_count == 1
        assert services.db.insert_scan_evidence.await_count == 1
        assert side_effects(services) == dict.fromkeys(side_effects(services), 1)
    del scan
    gc.collect()
    assert "never retrieved" not in caplog.text


@pytest.mark.asyncio
async def test_a_client_that_leaves_while_the_final_is_awaited_does_not_stop_the_scan(stream_api, monkeypatch, caplog):
    api, services = stream_api
    blacklist(api)
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS / SCALE)
    gate = asyncio.Event()
    services.registry = registry(structural=returns("structural", [ADMIN_MATCH]), honeypot=held("honeypot", gate))

    with caplog.at_level("INFO", logger="api"):
        events = events_of(api)
        kind, _ = await next_event(events)
        assert kind == "first"
        scan = scan_task()
        # The server asks for the next event and the generator waits on the scan, as the response does
        # between the first and the final; then the client disconnects and the response is cancelled.
        waiting = asyncio.ensure_future(events.__anext__())
        await asyncio.sleep(0)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting

        assert not scan.done()
        gate.set()
        await asyncio.wait_for(asyncio.wait({scan}), TIMEOUT)

    assert not scan.cancelled()
    assert services.db.upsert_contract_score.await_count == 1
    assert services.db.insert_scan_evidence.await_count == 1
    [line] = [record.getMessage() for record in caplog.records if record.getMessage().startswith("Firewall stream ")]
    timings = json.loads(line.removeprefix("Firewall stream "))
    assert (timings["first_kind"], timings["final_at_ms"]) == ("block", None)


@pytest.mark.asyncio
async def test_a_router_swap_passes_on_result_through_and_shows_a_token_floor(stream_api, monkeypatch):
    api, services = stream_api
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS / SCALE)
    gate = asyncio.Event()
    monkeypatch.setattr(
        api,
        "calldata_decoder",
        SimpleNamespace(decode=lambda data: dict(SWAP), is_whitelisted_target=lambda *args, **kwargs: "PancakeSwap Router"),
    )

    def per_token(name):
        async def analyze(ctx):
            if ctx.address == TOKEN_B and name == "honeypot":
                await gate.wait()
            return result(name, [GOPLUS_BLOCK] if ctx.address == TOKEN_A and name == "structural" else ())
        return analyze

    services.registry = registry(**{name: per_token(name) for name in WEIGHTS})
    events = events_of(api, {**BODY, "data": "0x38ed1739"})
    kind, first = await next_event(events)

    assert kind == "first"
    assert (first["classification"], first["risk_score"]) == (verdicts.BLOCK_RECOMMENDED, 90)
    assert first["danger_signals"][0] == "Scam DB match (1 sources)"
    gate.set()
    kind, final = await next_event(events)
    assert kind == "final"
    assert final["classification"] == verdicts.BLOCK_RECOMMENDED
    assert final["raw_checks"]["whitelisted_router"] == "PancakeSwap Router"
    assert first["risk_score"] <= final["risk_score"]


@pytest.mark.asyncio
async def test_a_router_swap_first_keys_pending_and_coverage_by_token(stream_api, monkeypatch):
    api, services = stream_api
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS * SCALE)
    gate = asyncio.Event()
    monkeypatch.setattr(
        api,
        "calldata_decoder",
        SimpleNamespace(decode=lambda data: dict(SWAP), is_whitelisted_target=lambda *args, **kwargs: "PancakeSwap Router"),
    )

    def per_token(name):
        async def analyze(ctx):
            if ctx.address == TOKEN_B and name == "honeypot":
                await gate.wait()
            return result(name, [GOPLUS_HIGH] if ctx.address == TOKEN_A and name == "structural" else ())
        return analyze

    services.registry = registry(**{name: per_token(name) for name in WEIGHTS})
    events = events_of(api, {**BODY, "data": "0x38ed1739"})
    kind, first = await next_event(events)

    # Token A is done and token B's honeypot analyzer still runs; the router itself is never scanned.
    assert kind == "first"
    assert first["pending_sources"] == [f"{TOKEN_B}:honeypot"]
    assert set(first["coverage"]) == {f"{TOKEN_A}:{name}" for name in WEIGHTS} | {
        f"{TOKEN_B}:{name}" for name in ("structural", "market", "behavioral")
    }
    assert (first["classification"], first["risk_score"]) == (verdicts.HIGH_RISK, 70)
    gate.set()
    kind, final = await next_event(events)
    assert kind == "final"
    assert set(final["coverage"]) == {f"{token}:{name}" for token in (TOKEN_A, TOKEN_B) for name in WEIGHTS}
    assert first["risk_score"] <= final["risk_score"]
    # Worded as the router swap's final is.
    for field in ("sending", "recipient"):
        assert first["transaction_impact"][field] == final["transaction_impact"][field]
    assert first["transaction_impact"]["recipient"] == f"PancakeSwap Router ({TARGET})"


@pytest.mark.asyncio
async def test_an_error_inside_the_stream_is_an_error_event_and_no_final(stream_api, monkeypatch):
    api, services = stream_api
    blacklist(api)
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS / SCALE)
    gate = asyncio.Event()
    services.registry = FailingRegistry(gate)
    # The pipeline fails, then so does the legacy fallback: the handler answers 500.
    monkeypatch.setattr(api, "token_scanner", SimpleNamespace(check_token=AsyncMock(side_effect=RuntimeError("down"))))

    events = events_of(api)
    kind, _ = await next_event(events)
    assert kind == "first"
    gate.set()

    assert await remaining(events) == [("error", {"status": 500, "detail": "Internal server error"})]
    assert side_effects(services)["insert_scan_evidence"] == 0


@pytest.mark.asyncio
async def test_an_exception_the_handler_does_not_map_still_ends_the_stream_with_an_error(stream_api, monkeypatch):
    api, services = stream_api
    blacklist(api)
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS / SCALE)
    gate = asyncio.Event()
    # _firewall_verdict re-raises an unsupported chain instead of answering 500.
    services.registry = FailingRegistry(gate, UnsupportedChainError("Unsupported chain ID 56"))

    events = events_of(api)
    kind, _ = await next_event(events)
    assert kind == "first"
    gate.set()

    assert await remaining(events) == [("error", {"status": 500, "detail": "Internal server error"})]


@pytest.mark.asyncio
async def test_a_final_that_is_not_json_ends_the_stream_with_an_error(stream_api, monkeypatch, caplog):
    api, services = stream_api
    blacklist(api)
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS / SCALE)
    gate = asyncio.Event()

    async def nan_sell_tax(ctx):
        await gate.wait()
        honeypot = result("honeypot")
        honeypot.data["sell_tax"] = float("nan")
        return honeypot

    services.registry = registry(structural=returns("structural", [ADMIN_MATCH]), honeypot=nan_sell_tax)

    events = events_of(api)
    kind, _ = await next_event(events)
    assert kind == "first"
    gate.set()

    # The plain route cannot render this response either (JSON has no NaN): it answers 500.
    assert await remaining(events) == [("error", {"status": 500, "detail": "Internal server error"})]
    assert "Firewall stream error: ValueError" in caplog.text


@pytest.mark.asyncio
async def test_no_middleware_buffers_the_stream(stream_api, monkeypatch):
    """Through the real app and its middleware chain, the first event reaches the client while the
    scan is held, and the test opens the scan only after it has read the first event's line: a layer
    that buffered the body would hold that line until the scan finished, and the test would time out.

    httpx's ASGITransport (0.25) collects the whole body before it returns a response, so it cannot
    see this; the test drives the ASGI app itself, reading each message as the app sends it. The
    first comes from the admin blacklist floor, not the timer, so no sleep is involved."""
    api, services = stream_api
    blacklist(api)
    timer(monkeypatch, api, FIRST_VERDICT_SECONDS / SCALE)
    gate = asyncio.Event()
    services.registry = registry(structural=returns("structural", [ADMIN_MATCH]), honeypot=held("honeypot", gate))
    body = json.dumps(BODY).encode()
    sent = asyncio.Queue()
    finished = asyncio.Event()
    received = []

    async def receive():
        if not received:
            received.append(body)
            return {"type": "http.request", "body": body, "more_body": False}
        await finished.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        await sent.put(message)
        if message["type"] == "http.response.body" and not message.get("more_body"):
            finished.set()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/firewall",
        "raw_path": b"/api/firewall",
        "root_path": "",
        "query_string": b"",
        "headers": [
            (b"host", b"testserver"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"accept", b"text/event-stream"),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    app = asyncio.ensure_future(api.app(scope, receive, send))

    async def next_message():
        try:
            return await asyncio.wait_for(sent.get(), TIMEOUT)
        except asyncio.TimeoutError:
            app.cancel()
            pytest.fail("the stream was buffered: nothing reached the client while the scan was held")

    start = await next_message()
    assert (start["type"], start["status"]) == ("http.response.start", 200)
    headers = {name.decode(): value.decode() for name, value in start["headers"]}
    assert headers["content-type"].startswith("text/event-stream")
    assert headers["x-accel-buffering"] == "no"
    # The security headers middleware ran on this response.
    assert headers["x-content-type-options"] == "nosniff"

    text = ""
    while "event: first" not in text.split("\n"):
        text += (await next_message())["body"].decode()
    assert not gate.is_set() and not finished.is_set()
    assert services.db.upsert_contract_score.await_count == 0
    gate.set()
    while not finished.is_set():
        text += (await next_message())["body"].decode()
    await asyncio.wait_for(app, TIMEOUT)

    events = parse(text)
    assert [kind for kind, _ in events] == ["first", "final"]
    assert events[0][1]["status"] == "unknown"
    assert events[1][1]["final"] is True
    assert services.db.upsert_contract_score.await_count == 1
