"""Every external data provider on the scan path sits behind a circuit breaker.

An open breaker sends nothing and gives exactly the answer a timeout gives, so the lookup stays
Unknown and is counted as failed in the Unknown ledger. A "no record" answer never opens it.
"""

import asyncio
import dataclasses
import json
import time
from typing import Awaitable, Callable, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import utils.scam_db as scam_db
from adapters.evm_base import EvmAdapter
from analyzers.market import MarketAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.circuit_breaker import CLOSED, FAILURE_THRESHOLD, OPEN, OPEN_SECONDS, provider_breakers
from core.extension_formatter import format_extension_alert
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine
from core.unknown_ledger import unknown_ledger
from services.dex_service import DexService
from services.explorer_service import ExplorerResult, ExplorerService
from services.phishing_service import PhishingService
from services.token_sniffer_service import TokenSnifferService
from utils.scam_db import ScamDatabase


def address(i: int) -> str:
    return "0x" + f"{i + 1:040x}"


def http_client(
    status: int = 200, body=None, error: Optional[BaseException] = None, unreadable: bool = False
):
    """A stand-in for aiohttp.ClientSession, used either as a context manager or held open.

    Every GET gets ``status`` and ``body``, or raises ``error`` before any reply. An unreadable
    reply's body is not JSON.
    """
    session = MagicMock(closed=False)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    if error is not None:
        session.get.side_effect = error
    else:
        response = MagicMock(status=status)
        response.json = AsyncMock(
            side_effect=json.JSONDecodeError("Expecting value", "<html>", 0)
            if unreadable
            else None,
            return_value=body,
        )
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)
        session.get.return_value.__aexit__ = AsyncMock(return_value=False)
    return MagicMock(return_value=session), session


def etherscan_adapter() -> EvmAdapter:
    adapter = EvmAdapter.__new__(EvmAdapter)
    adapter._chain_id = 56
    adapter._chain_name = "BSC"
    adapter._explorer_backend = "etherscan"
    adapter.etherscan_api_url = "https://api.etherscan.io/v2/api"
    adapter.etherscan_api_key = "key"
    adapter._honeypot_chain_id = 56
    adapter._honeypot_is_replies = {}
    adapter._creation_infos = {}
    adapter._creation_inflight = {}
    # Verification asks Sourcify when Etherscan did not verify, and reads the code for the clone
    # check; neither goes through the Etherscan session under test.
    adapter._explorer_service = MagicMock(get_sourcify_verification=AsyncMock(
        return_value=ExplorerResult("unknown", reason="not asked here", provider="sourcify"),
    ))
    adapter.get_bytecode = AsyncMock(return_value="0x6080")
    return adapter


def goplus_token():
    return lambda i: ScamDatabase.fetch_token_security(address(i), 56)


def goplus_phishing():
    service = PhishingService()
    return lambda i: service.check_url(f"https://site{i}.example/")


def sourcify():
    service = ExplorerService()
    return lambda i: service.get_verification_status(address(i), 4663)


def blockscout():
    # Base has a public Blockscout instance, and its contract creation lookup asks Blockscout alone.
    service = ExplorerService()
    return lambda i: service.get_contract_creation_info(address(i), 8453)


def etherscan_verification():
    adapter = etherscan_adapter()
    return lambda i: adapter.is_verified_contract(address(i))


def etherscan_creation():
    adapter = etherscan_adapter()
    return lambda i: adapter.get_contract_creation_info(address(i))


def honeypot_is():
    adapter = etherscan_adapter()
    return lambda i: adapter.check_honeypot(address(i))


def dexscreener():
    service = DexService()
    return lambda i: service.fetch_token_market_data(address(i), 56)


def token_sniffer():
    service = TokenSnifferService(api_key="key")
    return lambda i: service.fetch(address(i), 56)


@dataclasses.dataclass
class Case:
    target: str
    make: Callable[[], Callable[[int], Awaitable]]
    breaker: str
    # (provider, chain) in the Unknown ledger; Token Sniffer is not in it.
    ledger: Optional[tuple]
    no_record: tuple


CASES = {
    "goplus_token": Case(
        "utils.scam_db.aiohttp.ClientSession",
        goplus_token,
        "goplus_token:56",
        ("goplus_token", 56),
        (200, {"code": 1, "result": {}}),
    ),
    "goplus_phishing": Case(
        "services.phishing_service.aiohttp.ClientSession",
        goplus_phishing,
        "goplus_phishing",
        ("goplus_phishing", None),
        (200, {"code": 1, "result": {}}),
    ),
    "sourcify": Case(
        "services.explorer_service.aiohttp.ClientSession",
        sourcify,
        "sourcify:4663",
        ("sourcify", 4663),
        (404, None),
    ),
    "blockscout": Case(
        "services.explorer_service.aiohttp.ClientSession",
        blockscout,
        "blockscout:8453",
        ("blockscout", 8453),
        (404, None),
    ),
    "etherscan_verification": Case(
        "adapters.evm_base.aiohttp.ClientSession",
        etherscan_verification,
        "etherscan:56",
        ("etherscan", 56),
        (200, {"status": "1", "result": [{"SourceCode": ""}]}),
    ),
    "etherscan_creation": Case(
        "adapters.evm_base.aiohttp.ClientSession",
        etherscan_creation,
        "etherscan:56",
        ("etherscan", 56),
        (200, {"status": "0", "message": "No data found", "result": []}),
    ),
    "honeypot.is": Case(
        "adapters.evm_base.aiohttp.ClientSession",
        honeypot_is,
        "honeypot.is:56",
        ("honeypot.is", 56),
        (404, None),
    ),
    "dexscreener": Case(
        "services.dex_service.aiohttp.ClientSession",
        dexscreener,
        "dexscreener",
        ("dexscreener", 56),
        (200, {"pairs": None}),
    ),
    "token_sniffer": Case(
        "services.token_sniffer_service.aiohttp.ClientSession",
        token_sniffer,
        "token_sniffer:56",
        None,
        (404, None),
    ),
}


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    # GoPlus answers are cached per process; Sourcify is the only verification source asked.
    monkeypatch.delenv("BLOCKSCOUT_API_KEY", raising=False)
    scam_db._GOPLUS_CACHE.clear()
    yield
    scam_db._GOPLUS_CACHE.clear()


def failed_count(case: Case) -> int:
    provider, chain_id = case.ledger
    return unknown_ledger.for_chain(chain_id).get(provider, {}).get("failed", 0)


def comparable(result):
    """A lookup's answer without its observation time, with the exception name made neutral."""
    if isinstance(result, ExplorerResult):
        result = dataclasses.asdict(result)
    if isinstance(result, dict):
        result = {key: value for key, value in result.items() if key != "observed_at"}
    return json.loads(json.dumps(result).replace("CircuitOpenError", "TimeoutError"))


@pytest.mark.asyncio
@pytest.mark.parametrize("name", CASES)
async def test_an_open_breaker_sends_nothing_and_answers_like_a_timeout(name):
    case = CASES[name]
    lookup = case.make()
    client, session = http_client(error=asyncio.TimeoutError())
    before = failed_count(case) if case.ledger else None

    with patch(case.target, client):
        timeouts = [await lookup(i) for i in range(FAILURE_THRESHOLD)]
        assert session.get.call_count == FAILURE_THRESHOLD
        assert provider_breakers.states()[case.breaker] == OPEN
        skipped = await lookup(FAILURE_THRESHOLD)

    assert session.get.call_count == FAILURE_THRESHOLD
    assert comparable(skipped) == comparable(timeouts[0])
    if case.ledger:
        assert failed_count(case) == before + FAILURE_THRESHOLD + 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 503])
@pytest.mark.parametrize("name", CASES)
async def test_throttling_and_server_errors_open_the_breaker(name, status):
    case = CASES[name]
    lookup = case.make()
    client, session = http_client(status)
    # GoPlus retries a 429 with backoff before giving up; the retries count as one lookup.
    with patch(case.target, client), patch("utils.scam_db.asyncio.sleep", AsyncMock()):
        for i in range(FAILURE_THRESHOLD):
            await lookup(i)
        sent = session.get.call_count
        await lookup(FAILURE_THRESHOLD)

    assert provider_breakers.states()[case.breaker] == OPEN
    assert session.get.call_count == sent


@pytest.mark.asyncio
@pytest.mark.parametrize("name", CASES)
async def test_a_reply_that_is_not_json_opens_the_breaker(name):
    case = CASES[name]
    lookup = case.make()
    client, session = http_client(200, unreadable=True)
    with patch(case.target, client):
        for i in range(FAILURE_THRESHOLD):
            await lookup(i)
        await lookup(FAILURE_THRESHOLD)

    assert provider_breakers.states()[case.breaker] == OPEN
    assert session.get.call_count == FAILURE_THRESHOLD


@pytest.mark.asyncio
@pytest.mark.parametrize("name", CASES)
async def test_a_no_record_answer_never_opens_the_breaker(name):
    case = CASES[name]
    lookup = case.make()
    client, session = http_client(*case.no_record)

    with patch(case.target, client):
        for i in range(FAILURE_THRESHOLD + 1):
            await lookup(i)

    assert session.get.call_count == FAILURE_THRESHOLD + 1
    assert provider_breakers.states()[case.breaker] == CLOSED


def dexscreener_pair() -> dict:
    return {
        "chainId": "bsc",
        "baseToken": {"name": "Token", "symbol": "TKN"},
        "priceUsd": "1.0",
        "liquidity": {"usd": 500_000},
        "priceChange": {"h24": 1.5},
        "fdv": 2_000_000,
        "volume": {"h24": 150_000},
        "pairCreatedAt": (time.time() - 400 * 86400) * 1000,
    }


@pytest.mark.asyncio
async def test_a_probe_that_gets_an_answer_closes_the_breaker(monkeypatch):
    clock = MagicMock(return_value=1_000.0)
    monkeypatch.setattr(provider_breakers, "_clock", clock)
    lookup = dexscreener()
    failing, _ = http_client(error=asyncio.TimeoutError())
    with patch(CASES["dexscreener"].target, failing):
        for i in range(FAILURE_THRESHOLD):
            await lookup(i)
    assert provider_breakers.states()["dexscreener"] == OPEN

    clock.return_value += OPEN_SECONDS
    answering, session = http_client(200, {"pairs": [dexscreener_pair()]})
    with patch(CASES["dexscreener"].target, answering):
        probe = await lookup(FAILURE_THRESHOLD)
        after = await lookup(FAILURE_THRESHOLD + 1)

    assert provider_breakers.states()["dexscreener"] == CLOSED
    assert probe["status"] == after["status"] == "ok"
    assert session.get.call_count == 2


@pytest.mark.asyncio
async def test_malformed_token_data_never_opens_the_market_breaker():
    # DexScreener answered with JSON; only the token's own numbers could not be read, which is
    # that lookup coming back Unknown, not the provider failing.
    lookup = dexscreener()
    client, session = http_client(200, {"pairs": [{**dexscreener_pair(), "priceUsd": "n/a"}]})
    before = unknown_ledger.for_chain(56).get("dexscreener", {}).get("failed", 0)
    with patch(CASES["dexscreener"].target, client):
        results = [await lookup(i) for i in range(FAILURE_THRESHOLD + 1)]

    assert provider_breakers.states()["dexscreener"] == CLOSED
    assert session.get.call_count == FAILURE_THRESHOLD + 1
    assert {result["status"] for result in results} == {"unknown"}
    after = unknown_ledger.for_chain(56)["dexscreener"]["failed"]
    assert after == before + FAILURE_THRESHOLD + 1

    # Nor does a malformed token count toward the failures in a row that open it.
    failing, _ = http_client(error=asyncio.TimeoutError())
    with patch(CASES["dexscreener"].target, failing):
        for i in range(FAILURE_THRESHOLD - 1):
            await lookup(FAILURE_THRESHOLD + 1 + i)
    assert provider_breakers.states()["dexscreener"] == CLOSED


@pytest.mark.asyncio
async def test_a_blockscout_lookup_queued_on_the_host_lock_sends_nothing_once_the_breaker_opens():
    lookup = blockscout()

    async def times_out_after_a_moment(*args):
        await asyncio.sleep(0.05)
        raise asyncio.TimeoutError()

    client, session = http_client(200)
    session.get.return_value.__aenter__ = AsyncMock(side_effect=times_out_after_a_moment)
    before = unknown_ledger.for_chain(8453).get("blockscout", {}).get("failed", 0)
    with patch(CASES["blockscout"].target, client):
        for i in range(FAILURE_THRESHOLD - 1):
            await lookup(i)
        # The first of these opens the breaker while the second waits for the host's lock.
        first, second = await asyncio.gather(
            lookup(FAILURE_THRESHOLD), lookup(FAILURE_THRESHOLD + 1)
        )

    assert provider_breakers.states()["blockscout:8453"] == OPEN
    assert session.get.call_count == FAILURE_THRESHOLD
    assert first.reason == "TimeoutError"
    assert second.reason == "CircuitOpenError"
    after = unknown_ledger.for_chain(8453)["blockscout"]["failed"]
    assert after == before + FAILURE_THRESHOLD + 1


def analyzer(name: str, weight: float, data: dict):
    mock = MagicMock()
    mock.name = name
    mock.weight = weight

    async def analyze(ctx):
        return AnalyzerResult(
            name=name,
            weight=weight,
            score=0,
            flags=[],
            data={"status": "ok", "observed_at": time.time(), **data},
        )

    mock.analyze = analyze
    return mock


def scan_registry() -> AnalyzerRegistry:
    """A fully covered BSC token whose market data comes from the real DexScreener path."""
    registry = AnalyzerRegistry()
    registry.register(
        analyzer(
            "structural",
            0.40,
            {
                "is_contract": True,
                "is_verified": True,
                "contract_age_days": 400,
                "scam_matches": [],
                "coverage": {"scam_database": True, "is_verified": True, "contract_age_days": True},
            },
        )
    )
    registry.register(MarketAnalyzer(DexService()))
    registry.register(analyzer("behavioral", 0.20, {"reputation_score": 80}))
    registry.register(
        analyzer(
            "honeypot",
            0.15,
            {
                "is_honeypot": False,
                "can_buy": True,
                "can_sell": True,
                "buy_tax": 0,
                "sell_tax": 0,
            },
        )
    )
    return registry


async def classify(token: str) -> dict:
    results = await scan_registry().run_all(AnalysisContext(address=token, chain_id=56))
    return format_extension_alert(RiskEngine().compute_from_results(results))


@pytest.mark.asyncio
async def test_a_scan_with_the_market_breaker_open_is_never_safe():
    answering, _ = http_client(200, {"pairs": [dexscreener_pair()]})
    with patch(CASES["dexscreener"].target, answering):
        # The same scan with DexScreener answering is SAFE, so only the open breaker changes it.
        assert (await classify(address(100)))["risk_classification"] == "SAFE"

    failing, session = http_client(error=asyncio.TimeoutError())
    lookup = dexscreener()
    with patch(CASES["dexscreener"].target, failing):
        for i in range(FAILURE_THRESHOLD):
            await lookup(i)
        alert = await classify(address(100))

    assert session.get.call_count == FAILURE_THRESHOLD
    assert alert["risk_classification"] != "SAFE"
    assert alert["status"] == "unknown"
    assert alert["coverage"]["market"] < 1
    assert "CircuitOpenError" in alert["coverage_reasons"]["market"]
