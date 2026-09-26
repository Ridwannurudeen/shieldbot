"""The Unknown ledger counts, per chain and provider, how often a provider request was answered, came back
unknown or failed, at each provider's call site and never for an answer reused from a cache."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
import requests
from fastapi.testclient import TestClient
from web3.exceptions import ContractLogicError

from core.unknown_ledger import UnknownLedger

TOKEN = "0x" + "ab" * 20


def _counts(answered=0, unknown=0, failed=0):
    return {"answered": answered, "unknown": unknown, "failed": failed}


def _chain_counts(ledger, chain_id):
    return {
        provider: {outcome: entry[outcome] for outcome in ("answered", "unknown", "failed")}
        for provider, entry in ledger.for_chain(chain_id).items()
    }


@pytest.fixture
def ledger(monkeypatch):
    """A fresh ledger in place of the process-wide one at every call site."""
    import adapters.evm_base
    import api
    import services.dex_service
    import services.explorer_service
    import services.phishing_service
    import services.robinhood_simulation
    import utils.scam_db

    fresh = UnknownLedger()
    for module in (
        adapters.evm_base,
        api,
        services.dex_service,
        services.explorer_service,
        services.phishing_service,
        services.robinhood_simulation,
        utils.scam_db,
    ):
        monkeypatch.setattr(module, "unknown_ledger", fresh)
    return fresh


def _aiohttp(module, *replies):
    """Patch `module`'s aiohttp.ClientSession so successive GETs get `replies`: (status, body) or an exception.

    A body that is an exception is raised by the reply's .json().
    """
    session = MagicMock()
    contexts = []
    for reply in replies:
        context = MagicMock()
        if isinstance(reply, Exception):
            context.__aenter__ = AsyncMock(side_effect=reply)
        else:
            status, body = reply
            response = MagicMock(status=status)
            response.json = (
                AsyncMock(side_effect=body) if isinstance(body, Exception) else AsyncMock(return_value=body)
            )
            context.__aenter__ = AsyncMock(return_value=response)
        contexts.append(context)
    session.get.side_effect = contexts
    patcher = patch(f"{module}.aiohttp.ClientSession")
    patcher.start().return_value.__aenter__ = AsyncMock(return_value=session)
    return patcher


# --- The ledger -----------------------------------------------------------------------------


def test_counts_are_kept_per_chain_and_provider_with_the_latest_outcome():
    ledger = UnknownLedger()
    ledger.record("honeypot.is", 56, "answered")
    ledger.record("honeypot.is", 56, "failed")
    ledger.record("honeypot.is", 1, "unknown")
    ledger.record("goplus_phishing", None, "answered")

    bsc = ledger.for_chain(56)
    assert list(bsc) == ["honeypot.is"]
    assert {key: bsc["honeypot.is"][key] for key in ("answered", "unknown", "failed")} == _counts(
        1, 0, 1
    )
    assert bsc["honeypot.is"]["last_outcome"] == "failed"
    assert bsc["honeypot.is"]["last_at"] >= ledger.counting_since
    assert list(ledger.for_chain(None)) == ["goplus_phishing"]
    assert ledger.for_chain(4663) == {}


def test_summary_sums_per_provider_and_per_chain_since_counting_began():
    ledger = UnknownLedger()
    ledger.record("honeypot.is", 56, "answered")
    ledger.record("honeypot.is", 1, "unknown")
    ledger.record("rpc", 56, "failed")
    ledger.record("goplus_phishing", None, "answered")

    summary = ledger.summary()
    assert summary["counting_since"] == ledger.counting_since
    assert summary["by_provider"] == {
        "honeypot.is": _counts(1, 1, 0),
        "rpc": _counts(0, 0, 1),
        "goplus_phishing": _counts(1, 0, 0),
    }
    assert summary["by_chain"] == {56: _counts(1, 0, 1), 1: _counts(0, 1, 0)}


def test_an_outcome_outside_the_three_is_refused():
    with pytest.raises(KeyError):
        UnknownLedger().record("rpc", 56, "ok")


# --- honeypot.is ----------------------------------------------------------------------------

SIMULATED = {
    "simulationSuccess": True,
    "honeypotResult": {"isHoneypot": False},
    "simulationResult": {},
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply, outcome",
    [
        ((200, SIMULATED), "answered"),
        ((200, {"simulationSuccess": False}), "unknown"),
        ((404, None), "unknown"),
        ((500, None), "failed"),
        (aiohttp.ClientConnectionError(), "failed"),
    ],
    ids=["simulated", "inconclusive", "not-found", "server-error", "network-error"],
)
async def test_honeypot_is_counts_each_fetched_reply_once(ledger, reply, outcome):
    from adapters.bsc import BscAdapter

    patcher = _aiohttp("adapters.evm_base", reply, reply)
    try:
        adapter = BscAdapter(rpc_url="https://rpc.invalid")
        await adapter.check_honeypot(TOKEN)
        await adapter.get_tax_info(TOKEN)
    finally:
        patcher.stop()
    # A reply is reused for the tax check; a request that raised is not kept, so it is asked again.
    expected = 2 if isinstance(reply, Exception) else 1
    assert _chain_counts(ledger, 56) == {"honeypot.is": {**_counts(), outcome: expected}}


# --- RPC ------------------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "side_effect, outcome",
    [
        (None, "answered"),
        (ContractLogicError("execution reverted"), "answered"),
        (requests.exceptions.ConnectionError(), "failed"),
    ],
    ids=["reply", "revert", "connection-error"],
)
async def test_rpc_calls_count_a_revert_as_the_node_answering(ledger, side_effect, outcome):
    from adapters.evm_base import EvmAdapter

    adapter = EvmAdapter(4663, "Robinhood Chain", "https://rpc.invalid")
    fn = MagicMock(return_value=b"", side_effect=side_effect)
    if side_effect is None:
        await adapter._call_with_retry(fn)
    else:
        with pytest.raises(type(side_effect)):
            await adapter._call_with_retry(fn)
    assert _chain_counts(ledger, 4663) == {"rpc": {**_counts(), outcome: 1}}


@pytest.mark.asyncio
async def test_rpc_rate_limits_that_outlast_the_retries_count_one_failure(ledger):
    from adapters.evm_base import EvmAdapter

    adapter = EvmAdapter(4663, "Robinhood Chain", "https://rpc.invalid")
    limited = ValueError({"code": -32005, "message": "limit exceeded"})
    with patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(ValueError):
            await adapter._call_with_retry(MagicMock(side_effect=limited), retries=3)
    assert _chain_counts(ledger, 4663) == {"rpc": _counts(failed=1)}


# --- Etherscan ------------------------------------------------------------------------------

SOURCE = {"status": "1", "result": [{"SourceCode": "contract A {}"}]}
CREATION = {"status": "1", "result": [{"txHash": "0x" + "12" * 32, "contractCreator": TOKEN}]}
# Etherscan's reply for an address it holds no creation record for (published in l2beat/l2beat#12965;
# Etherscan's docs say only that status 0 can be an error or a valid request with no records).
NO_RECORD = {"status": "0", "message": "No data found", "result": None}
REFUSED = {
    "status": "0",
    "message": "NOTOK",
    "result": "Free API access is not supported for this chain",
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply, outcome",
    [
        ((200, SOURCE), "answered"),
        ((200, REFUSED), "failed"),
        ((503, None), "failed"),
        (aiohttp.ClientError(), "failed"),
    ],
    ids=["verified", "refused", "server-error", "network-error"],
)
async def test_etherscan_verification_lookups_are_counted(ledger, reply, outcome):
    from adapters.evm_base import EvmAdapter
    from services.explorer_service import ExplorerService

    # Sourcify is asked, after Etherscan, when Etherscan did not verify the contract; it has no
    # match for TOKEN. Both modules share aiohttp, so one session answers both in turn.
    sourcify_404 = {"match": None, "creationMatch": None, "runtimeMatch": None, "chainId": "56", "address": TOKEN}
    patcher = _aiohttp("adapters.evm_base", reply, (404, sourcify_404))
    try:
        adapter = EvmAdapter(56, "BSC", "https://rpc.invalid", etherscan_api_key="test-key")
        adapter._explorer_service = ExplorerService()
        adapter.get_bytecode = AsyncMock(return_value="0x6080")
        await adapter.is_verified_contract(TOKEN)
    finally:
        patcher.stop()
    expected = {"etherscan": {**_counts(), outcome: 1}}
    if outcome != "answered":
        expected["sourcify"] = _counts(unknown=1)
    assert _chain_counts(ledger, 56) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply, outcome",
    [
        ((200, NO_RECORD), "unknown"),
        ((503, None), "failed"),
        (aiohttp.ClientError(), "failed"),
        ((200, ValueError("Expecting value")), "failed"),
        ((200, ["not", "an", "object"]), "failed"),
        ((200, {"message": "OK"}), "failed"),
        ((200, {"status": "1", "result": ["not an object"]}), "failed"),
    ],
    ids=[
        "no-record",
        "server-error",
        "network-error",
        "unreadable-body",
        "non-object-body",
        "no-status",
        "malformed-result",
    ],
)
async def test_etherscan_creation_lookups_that_do_not_answer_are_counted(ledger, reply, outcome):
    from adapters.evm_base import EvmAdapter

    patcher = _aiohttp("adapters.evm_base", reply)
    try:
        adapter = EvmAdapter(56, "BSC", "https://rpc.invalid", etherscan_api_key="test-key")
        assert await adapter.get_contract_creation_info(TOKEN) is None
    finally:
        patcher.stop()
    assert _chain_counts(ledger, 56) == {"etherscan": {**_counts(), outcome: 1}}


@pytest.mark.asyncio
async def test_a_creation_time_rpc_failure_is_the_rpc_s_not_etherscan_s(ledger):
    from adapters.evm_base import EvmAdapter

    patcher = _aiohttp("adapters.evm_base", (200, CREATION))
    try:
        adapter = EvmAdapter(56, "BSC", "https://rpc.invalid", etherscan_api_key="test-key")
        adapter.w3 = MagicMock()
        adapter.w3.eth.get_transaction.side_effect = requests.exceptions.ConnectionError()
        result = await adapter.get_contract_creation_info(TOKEN)
    finally:
        patcher.stop()
    assert result["creator"] == TOKEN and result["age_days"] is None
    assert _chain_counts(ledger, 56) == {"etherscan": _counts(answered=1), "rpc": _counts(failed=1)}


# Sourcify v2's deployment record for a verified contract (fields=deployment); the values are synthetic.
SOURCIFY_DEPLOYMENT = {
    "match": "exact_match", "creationMatch": "exact_match", "runtimeMatch": "exact_match",
    "chainId": "56", "address": TOKEN,
    "deployment": {
        "transactionHash": "0x" + "12" * 32, "blockNumber": "693963", "transactionIndex": "0", "deployer": TOKEN,
    },
}
SOURCIFY_NOT_VERIFIED = {"match": None, "creationMatch": None, "runtimeMatch": None, "chainId": "56", "address": TOKEN}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply, sourcify, rpc",
    [
        ((200, SOURCIFY_DEPLOYMENT), "answered", _counts(answered=1)),
        ((404, SOURCIFY_NOT_VERIFIED), "unknown", None),
        ((503, None), "failed", None),
    ],
    ids=["deployment", "not-verified", "server-error"],
)
async def test_a_refused_creation_lookup_counts_etherscan_s_refusal_and_sourcify_s_answer(
    ledger, reply, sourcify, rpc
):
    from adapters.evm_base import EvmAdapter
    from services.explorer_service import ExplorerService

    # Etherscan's free tier refuses the lookup on BNB Chain, which counts as Etherscan failing;
    # Sourcify's deployment record is asked next, and one it knows is dated from a block header.
    patcher = _aiohttp("adapters.evm_base", (200, REFUSED), reply)
    try:
        adapter = EvmAdapter(56, "BSC", "https://rpc.invalid", etherscan_api_key="test-key")
        adapter._explorer_service = ExplorerService()
        adapter.w3 = MagicMock()
        adapter.w3.eth.get_block.return_value = {"timestamp": 1600753669}
        result = await adapter.get_contract_creation_info(TOKEN)
    finally:
        patcher.stop()
    assert (result is not None) == (rpc is not None)
    expected = {"etherscan": _counts(failed=1), "sourcify": {**_counts(), sourcify: 1}}
    if rpc:
        expected["rpc"] = rpc
    assert _chain_counts(ledger, 56) == expected


# --- Sourcify and Blockscout ------------------------------------------------------------------

BLOCKSCOUT_CONTRACT = {"hash": TOKEN, "is_contract": True, "is_verified": True}


def _sourcify_not_verified(chain_id):
    # Sourcify v2's 404 body for an address with no verified contract.
    return {"match": None, "creationMatch": None, "runtimeMatch": None, "chainId": str(chain_id), "address": TOKEN}


@pytest.mark.asyncio
async def test_explorer_requests_are_counted_per_provider_and_cached_answers_are_not(
    ledger, monkeypatch
):
    from services.explorer_service import ExplorerService

    monkeypatch.setenv("BLOCKSCOUT_API_KEY", "test-key")
    patcher = _aiohttp("services.explorer_service", (404, _sourcify_not_verified(4663)), (200, BLOCKSCOUT_CONTRACT))
    try:
        service = ExplorerService()
        first = await service.get_verification_status(TOKEN, 4663)
        again = await service.get_verification_status(TOKEN, 4663)
    finally:
        patcher.stop()
    assert first.status == again.status == "verified"
    assert _chain_counts(ledger, 4663) == {
        "sourcify": _counts(unknown=1),
        "blockscout": _counts(answered=1),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply, outcome",
    [
        ((404, _sourcify_not_verified(56)), "unknown"),
        ((404, None), "failed"),
        ((404, ValueError("not JSON")), "failed"),
    ],
    ids=["not-verified", "body-not-an-object", "body-not-json"],
)
async def test_a_sourcify_404_is_nothing_found_only_with_a_readable_body(ledger, reply, outcome):
    from services.explorer_service import ExplorerService

    patcher = _aiohttp("services.explorer_service", reply)
    try:
        await ExplorerService().get_sourcify_verification(TOKEN, 56)
    finally:
        patcher.stop()
    assert _chain_counts(ledger, 56) == {"sourcify": _counts(**{outcome: 1})}


@pytest.mark.asyncio
async def test_explorer_error_status_and_network_error_are_failures(ledger):
    from services.explorer_service import ExplorerService

    patcher = _aiohttp("services.explorer_service", (500, None), aiohttp.ClientConnectionError())
    try:
        service = ExplorerService()
        await service.get_contract_creation_info(TOKEN, 8453)
        await service.get_contract_creation_info("0x" + "cd" * 20, 8453)
    finally:
        patcher.stop()
    assert _chain_counts(ledger, 8453) == {"blockscout": _counts(failed=2)}


@pytest.mark.asyncio
async def test_a_blockscout_lookup_never_sent_for_want_of_a_key_is_not_counted(ledger, monkeypatch):
    from services.explorer_service import ExplorerService

    monkeypatch.delenv("BLOCKSCOUT_API_KEY", raising=False)
    await ExplorerService().get_contract_creation_info(TOKEN, 4663)
    assert ledger.for_chain(4663) == {}


# --- GoPlus ---------------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply, outcome",
    [
        ((200, {"code": 1, "result": {TOKEN: {"is_honeypot": "0"}}}), "answered"),
        ((200, {"code": 1, "result": {}}), "unknown"),
        ((200, {"code": 0, "result": None}), "failed"),
        ((500, None), "failed"),
        (aiohttp.ClientConnectionError(), "failed"),
    ],
    ids=["record", "no-record", "unsuccessful", "server-error", "network-error"],
)
async def test_goplus_token_lookups_are_counted_once_per_request(
    ledger, monkeypatch, reply, outcome
):
    import utils.scam_db
    from utils.scam_db import ScamDatabase

    monkeypatch.setattr(utils.scam_db, "_GOPLUS_CACHE", {})
    patcher = _aiohttp("utils.scam_db", reply)
    try:
        await ScamDatabase.fetch_token_security(TOKEN, 56)
        await ScamDatabase.fetch_token_security(TOKEN, 56)
    finally:
        patcher.stop()
    assert _chain_counts(ledger, 56) == {"goplus_token": {**_counts(), outcome: 1}}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply, outcome",
    [
        ((200, {"code": 1, "result": {"phishing_site": 0}}), "answered"),
        ((200, {"code": 1, "result": {}}), "unknown"),
        ((502, None), "failed"),
        (aiohttp.ClientConnectionError(), "failed"),
    ],
    ids=["verdict", "no-verdict", "server-error", "network-error"],
)
async def test_goplus_phishing_lookups_are_counted_without_a_chain(ledger, reply, outcome):
    from services.phishing_service import PhishingService

    patcher = _aiohttp("services.phishing_service", reply)
    try:
        service = PhishingService()
        await service.check_url("https://example.org/a")
        await service.check_url("https://example.org/b")
    finally:
        patcher.stop()
    assert _chain_counts(ledger, None) == {"goplus_phishing": {**_counts(), outcome: 1}}


# --- DexScreener ----------------------------------------------------------------------------

PAIR = {
    "chainId": "bsc",
    "baseToken": {"address": TOKEN, "name": "T", "symbol": "T"},
    "priceUsd": "1",
    "liquidity": {"usd": 100000},
    "volume": {"h24": 5},
    "priceChange": {"h24": 1},
    "fdv": 10,
    "pairCreatedAt": 1,
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply, outcome",
    [
        ((200, [PAIR]), "answered"),
        ((200, []), "unknown"),
        ((429, None), "failed"),
        (aiohttp.ClientConnectionError(), "failed"),
    ],
    ids=["pairs", "no-pairs", "rate-limited", "network-error"],
)
async def test_dexscreener_lookups_are_counted(ledger, reply, outcome):
    from services.dex_service import DexService

    patcher = _aiohttp("services.dex_service", reply)
    try:
        await DexService().fetch_token_market_data(TOKEN, 56)
    finally:
        patcher.stop()
    assert _chain_counts(ledger, 56) == {"dexscreener": {**_counts(), outcome: 1}}


# --- eth_simulateV1 -------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "run, outcome",
    [
        (AsyncMock(return_value={"is_honeypot": False}), "answered"),
        (AsyncMock(return_value={"is_honeypot": True, "simulation_failed": True}), "unknown"),
        (AsyncMock(return_value={"is_honeypot": None}), "unknown"),
        (AsyncMock(side_effect=aiohttp.ClientConnectionError()), "failed"),
    ],
    ids=["decided", "one-pool-failed", "no-supported-pool", "rpc-error"],
)
async def test_robinhood_simulations_are_counted_once_per_token(ledger, run, outcome):
    from services.robinhood_simulation import RobinhoodSimulator

    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._run = run
    await simulator.simulate(TOKEN)
    await simulator.simulate(TOKEN)
    assert run.await_count == 1
    assert _chain_counts(ledger, 4663) == {"eth_simulateV1": {**_counts(), outcome: 1}}


@pytest.mark.asyncio
async def test_an_unavailable_simulation_rpc_is_a_failure(ledger):
    from services.robinhood_simulation import RobinhoodSimulator, SimulationUnavailable

    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._run = AsyncMock(
        side_effect=SimulationUnavailable("eth_simulateV1 unsupported by the RPC")
    )
    await simulator.simulate(TOKEN)
    assert _chain_counts(ledger, 4663) == {"eth_simulateV1": _counts(failed=1)}


# --- /api/stats -----------------------------------------------------------------------------


def test_public_stats_carry_the_ledger_summary(ledger, monkeypatch):
    import api

    ledger.record("honeypot.is", 56, "failed")
    ledger.record("goplus_phishing", None, "answered")
    monkeypatch.setattr(
        api,
        "container",
        SimpleNamespace(
            settings=SimpleNamespace(admin_secret="", trusted_proxies=[]),
            auth_manager=None,
            db=None,
            mempool_monitor=None,
            phishing_service=None,
        ),
    )
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))

    body = TestClient(api.app).get("/api/stats").json()

    assert body["unknown_ledger"] == {
        "counting_since": ledger.counting_since,
        "by_provider": {"honeypot.is": _counts(failed=1), "goplus_phishing": _counts(answered=1)},
        "by_chain": {"56": _counts(failed=1)},
    }
