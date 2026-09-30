"""A sell simulation of ShieldBot's own (Robinhood Chain, Arbitrum One) that could not run leaves sellability
unknown, even beside a complete and clean GoPlus answer: GoPlus misses the honeypots the simulation exists to
catch (it reports the real Arbitrum honeypot ARBROKER as not a honeypot)."""

import dataclasses
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from eth_utils import keccak

from adapters.arbitrum import ArbitrumAdapter
from adapters.evm_base import EvmAdapter
from adapters.robinhood import RobinhoodAdapter
from analyzers.honeypot import HoneypotAnalyzer
from core.analyzer import AnalysisContext
from core.extension_formatter import format_extension_alert
from core.risk_engine import RiskEngine
from core.telegram_formatter import format_full_report
from core.verdict_evidence import build_evidence, canonical_bytes
from scanner.token_scanner import TokenScanner
from services.honeypot_service import HoneypotService
from services.robinhood_simulation import SimulationUnavailable, aggregate_outcomes
from tests.test_arbitrum_simulation import FakeRpc as ArbitrumRpc
from tests.test_arbitrum_simulation import load as load_arbitrum
from tests.test_robinhood_simulation import SECRET, TOKEN, adapter_with, outcome, replay, rpc_for
from tests.test_robinhood_simulation import FakeRpc as RobinhoodRpc
from tests.test_robinhood_simulation import fresh_addresses as robinhood_addresses
from tests.test_robinhood_simulation import load as load_robinhood
from utils.scam_db import ScamDatabase
from utils.web3_client import Web3Client

CLEAN_GOPLUS = {
    "status": "ok",
    "reason": None,
    "observed_at": 0,
    "data": {
        "is_honeypot": "0",
        "cannot_buy": "0",
        "cannot_sell_all": "0",
        "transfer_pausable": "0",
        "buy_tax": "0",
        "sell_tax": "0",
    },
}


def arbitrum_adapter(request):
    adapter = ArbitrumAdapter(rpc_url="https://rpc.invalid")
    adapter._simulator._request = request
    return adapter


async def scan(chain_id, adapter, token=TOKEN, goplus=CLEAN_GOPLUS):
    client = Web3Client.__new__(Web3Client)
    client._adapters = {chain_id: adapter}
    service = HoneypotService(client)
    with patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock(return_value=goplus)):
        data = await service.fetch_honeypot_data(token, chain_id=chain_id)
        analyzed = await HoneypotAnalyzer(service).analyze(
            AnalysisContext(token, chain_id=chain_id)
        )
    # The engine weighs analyzers to a total of 1. The honeypot analyzer alone at full weight decides the
    # verdict, as in a scan whose other analyzers are complete and clean; at its own weight of 0.15 the
    # missing weight alone would keep the verdict from LOW.
    risk = RiskEngine().compute_from_results([dataclasses.replace(analyzed, weight=1.0)])
    return data, analyzed, risk, format_extension_alert(risk)


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [42161, 4663])
@pytest.mark.parametrize(
    "failure",
    [SimulationUnavailable("RPC HTTP 503"), aiohttp.ClientConnectionError()],
    ids=["unavailable", "transport-error"],
)
async def test_a_simulation_that_could_not_run_stays_unknown_beside_a_complete_clean_goplus_answer(
    chain_id, failure
):
    request = AsyncMock(side_effect=failure)
    adapter = arbitrum_adapter(request) if chain_id == 42161 else adapter_with(request)
    data, analyzed, risk, extension = await scan(chain_id, adapter)
    assert data["status"] == analyzed.data["status"] == risk["status"] == "unknown"
    assert risk["risk_level"] != "LOW"
    assert extension["risk_classification"] != "SAFE"
    assert data["can_sell"] is None and "can_sell" not in data["field_providers"]
    assert data["coverage"]["can_sell"] is False
    # Nothing about the token was observed: unknown, not suspicious.
    assert data["simulation_failed"] is False
    assert analyzed.score == 0
    assert not any("treat as suspicious" in flag for flag in analyzed.flags)
    assert "Honeypot simulation could not run (unresolved)" in data["reason"]
    assert data["rpc_failed"] is True
    assert data["field_providers"]["rpc_failed"] == "eth_simulateV1"


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [42161, 4663])
async def test_a_token_with_no_pool_to_simulate_is_still_decided_by_a_complete_clean_goplus_answer(
    chain_id,
):
    if chain_id == 42161:
        fixture = load_arbitrum("v3_arb")
        adapter = arbitrum_adapter(ArbitrumRpc(fixture, pools={}))
        token = fixture["token"]
    else:
        adapter = adapter_with(RobinhoodRpc(TOKEN, 10**27))
        token = TOKEN
    data, analyzed, risk, extension = await scan(chain_id, adapter, token)
    assert "No supported pool found" in data["reason"]
    assert data["can_sell"] is True and data["field_providers"]["can_sell"] == "goplus"
    assert data["status"] == analyzed.data["status"] == risk["status"] == "ok"
    assert (analyzed.score, risk["risk_level"], extension["risk_classification"]) == (
        0,
        "LOW",
        "SAFE",
    )
    assert data["rpc_failed"] is False


@pytest.mark.asyncio
async def test_a_honeypot_is_simulation_failure_still_scores_as_suspicious():
    # honeypot.is (Ethereum, BNB Chain, Base) ran its own simulation of the token and could not finish it.
    adapter = EvmAdapter.__new__(EvmAdapter)
    adapter._chain_id = 56
    adapter._honeypot_chain_id = 56
    adapter._chain_name = "BSC"
    adapter._honeypot_is_replies = {}
    response = AsyncMock(status=200)
    response.json.return_value = {"simulationSuccess": False}
    session = MagicMock()
    session.get.return_value.__aenter__.return_value = response
    with patch("adapters.evm_base.aiohttp.ClientSession") as http:
        http.return_value.__aenter__.return_value = session
        data, analyzed, risk, extension = await scan(56, adapter, "0x" + "ab" * 20)
    assert data["simulation_failed"] is True
    assert data["field_providers"]["simulation_failed"] == "honeypot.is"
    assert any("treat as suspicious" in flag for flag in analyzed.flags)
    assert analyzed.score == 40
    assert data["status"] == risk["status"] == "unknown"
    assert data["rpc_failed"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("can_sell", [True, False])
async def test_the_analyzer_itself_keeps_sellability_uncovered_after_a_simulation_that_could_not_run(
    can_sell,
):
    # The analyzer recomputes coverage from the fields, so it applies the guard itself rather than
    # trusting the service's status.
    service = MagicMock()
    service.fetch_honeypot_data = AsyncMock(
        return_value={
            "is_honeypot": False,
            "can_buy": True,
            "can_sell": can_sell,
            "buy_tax": 0.0,
            "sell_tax": 0.0,
            "rpc_failed": True,
            "status": "ok",
            "reason": None,
        }
    )
    result = await HoneypotAnalyzer(service).analyze(AnalysisContext(TOKEN, chain_id=42161))
    assert result.data["can_sell"] is (None if can_sell else False)
    assert result.data["coverage"]["can_sell"] is False
    assert result.data["status"] == "unknown"
    assert result.data["reason"] == "Honeypot simulation could not run (unresolved)"
    assert not any("treat as suspicious" in flag for flag in result.flags)


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [42161, 4663])
async def test_the_telegram_report_never_calls_a_token_not_a_honeypot_after_a_simulation_that_could_not_run(
    chain_id,
):
    request = AsyncMock(side_effect=SimulationUnavailable("RPC HTTP 503"))
    adapter = arbitrum_adapter(request) if chain_id == 42161 else adapter_with(request)
    data, analyzed, risk, extension = await scan(chain_id, adapter)
    # The bot reports the honeypot analyzer's data; GoPlus's is_honeypot False is in it.
    assert (analyzed.data["is_honeypot"], analyzed.data["rpc_failed"]) == (False, True)
    report = format_full_report(risk, {}, {}, {}, honeypot_data=analyzed.data)
    assert "Not Honeypot" not in report
    assert "\n  Unknown (" in report
    assert "Sellability: Unknown" in report


@pytest.mark.asyncio
async def test_the_telegram_report_of_a_simulated_clean_token_is_unchanged():
    fixture = load_arbitrum("v3_arb")
    adapter = arbitrum_adapter(ArbitrumRpc(fixture))
    addresses = [fixture["buyer"], fixture["receiver"]]
    with patch("services.arbitrum_simulation._fresh_address", side_effect=addresses):
        data, analyzed, risk, extension = await scan(42161, adapter, fixture["token"])
    report = format_full_report(risk, {}, {}, {}, honeypot_data=analyzed.data)
    assert "\u2705 Not Honeypot" in report and "Sellability: Yes" in report
    # Byte for byte what the data without the new key rendered.
    before = {key: value for key, value in analyzed.data.items() if key != "rpc_failed"}
    assert report == format_full_report(risk, {}, {}, {}, honeypot_data=before)


# --- a discovery lookup the node could not answer ---------------------------------------------------

# What a node under load answers, over HTTP 200, instead of a lookup's result.
NODE_ERROR = {"code": -32000, "message": "execution aborted (timeout = 5s)"}
# What the Arbitrum One and Robinhood Chain RPCs answer for a call that reverts (both checked
# 2026-09-30: totalSupply() on a contract without it).
REVERTED = {"code": 3, "message": "execution reverted", "data": "0x"}


def calldata_of(signature):
    return "0x" + keccak(text=signature)[:4].hex()


class Node:
    """The node behind a simulator's _post, below its retry: the fake RPC's answer, with `answer` (an
    error or a result) in place of every row `fails` selects, in the first `times` requests that carry
    one (all of them when None). `hits` counts the requests that carried one."""

    def __init__(self, rpc, fails, answer, times=None):
        self.rpc, self.fails, self.answer, self.times = rpc, fails, answer, times
        self.hits = 0

    async def __call__(self, session, calls):
        rows = await self.rpc(session, calls)
        failing = [self.fails(method, params) for method, params in calls]
        if not any(failing):
            return rows
        self.hits += 1
        if self.times is not None:
            if self.times == 0:
                return rows
            self.times -= 1
        return [
            {"jsonrpc": "2.0", "id": row["id"], **self.answer} if fails else row
            for fails, row in zip(failing, rows)
        ]


def adapter_posting(chain_id, post):
    """The chain's adapter, its simulator sending every JSON-RPC request through `post`."""
    if chain_id == 42161:
        adapter = ArbitrumAdapter(rpc_url="https://rpc.invalid")
    else:
        with patch("adapters.evm_base.Web3"):
            adapter = RobinhoodAdapter()
    adapter._simulator._post = post
    return adapter


@pytest.fixture
def no_backoff():
    with patch("services.robinhood_simulation.asyncio.sleep", new=AsyncMock()) as sleep:
        yield sleep


def eth_call_to(selector=None, to=None):
    def fails(method, params):
        if method != "eth_call":
            return False
        call = params[0]
        return (selector is None or call["data"].startswith(selector)) and (
            to is None or call["to"] == to
        )

    return fails


ARBITRUM_LOOKUPS = {
    "totalSupply": eth_call_to(calldata_of("totalSupply()")),
    "v3-factory": eth_call_to(calldata_of("getPool(address,address,uint24)")),
    "v2-factories": eth_call_to(calldata_of("getPair(address,address)")),
    "weth-balance": eth_call_to(to="0x82af49447d8a07e3bd95bd0d56f35241523fbab1"),
}
ROBINHOOD_LOOKUPS = {
    "totalSupply": (eth_call_to(calldata_of("totalSupply()")), {}),
    "v2-factory": (eth_call_to(calldata_of("getPair(address,address)")), {}),
    "doppler-hook": (eth_call_to(calldata_of("getState(address)")), {}),
    "pool-manager": (eth_call_to(calldata_of("extsload(bytes32)")), {}),
    "pair-reserves": (
        eth_call_to(calldata_of("getReserves()")),
        {"pair": "0x" + "3c" * 20, "reserves": (10**20, 10**27)},
    ),
    "block-number": (lambda method, params: method == "eth_blockNumber", {}),
    "initialize-logs": (lambda method, params: method == "eth_getLogs", {}),
}


def discovery_with(chain_id, answer, lookup):
    """The chain's adapter, and the node answering `answer` in place of the lookup's row."""
    if chain_id == 42161:
        node = Node(ArbitrumRpc(load_arbitrum("v3_arb")), ARBITRUM_LOOKUPS[lookup], answer)
    else:
        fails, tables = ROBINHOOD_LOOKUPS[lookup]
        node = Node(RobinhoodRpc(TOKEN, 10**27, **tables), fails, answer)
    return adapter_posting(chain_id, node), node


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_backoff")
@pytest.mark.parametrize(
    "chain_id,lookup",
    [(42161, lookup) for lookup in ARBITRUM_LOOKUPS] + [(4663, lookup) for lookup in ROBINHOOD_LOOKUPS],
)
async def test_a_discovery_lookup_the_node_could_not_answer_stays_unknown_beside_a_complete_clean_goplus_answer(
    chain_id, lookup
):
    adapter, node = discovery_with(chain_id, {"error": NODE_ERROR}, lookup)
    data, analyzed, risk, extension = await scan(chain_id, adapter)
    # Asked once more, the node failed again.
    assert node.hits == 2
    assert data["status"] == analyzed.data["status"] == risk["status"] == "unknown"
    assert risk["risk_level"] != "LOW"
    assert extension["risk_classification"] != "SAFE"
    assert data["can_sell"] is None and data["coverage"]["can_sell"] is False
    assert data["simulation_failed"] is False and analyzed.score == 0
    assert data["rpc_failed"] is True
    assert "No supported pool found" not in data["reason"]
    assert "(JSON-RPC error -32000)" in data["reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "chain_id,lookup",
    [(42161, "v3-factory"), (42161, "weth-balance"), (4663, "doppler-hook"), (4663, "pool-manager")],
)
async def test_a_getter_that_reverts_is_not_an_answer_of_no_pool(chain_id, lookup):
    # A pool getter, a mapping read or a WETH balance never reverts on a working node: no answer. A
    # revert is the call's own answer, so it is not asked again.
    adapter, node = discovery_with(chain_id, {"error": REVERTED}, lookup)
    data, analyzed, risk, extension = await scan(chain_id, adapter)
    assert node.hits == 1
    assert data["status"] == "unknown" and data["rpc_failed"] is True
    assert "No supported pool found" not in data["reason"]
    assert "(JSON-RPC error 3)" in data["reason"]
    assert risk["risk_level"] != "LOW" and extension["risk_classification"] != "SAFE"


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [42161, 4663])
@pytest.mark.parametrize(
    "reverted",
    # As both simulation RPCs answer a revert, and as other nodes word it.
    [REVERTED, {"code": -32000, "message": "execution reverted"}],
    ids=["code-3", "message"],
)
async def test_a_total_supply_that_reverts_is_still_answered_by_a_complete_clean_goplus_answer(
    chain_id, reverted
):
    # A contract without totalSupply() reverts, legitimately: nothing to simulate, and GoPlus decides.
    adapter, node = discovery_with(chain_id, {"error": reverted}, "totalSupply")
    data, analyzed, risk, extension = await scan(chain_id, adapter)
    assert node.hits == 1
    assert "totalSupply() unavailable; cannot size a buy" in data["reason"]
    assert data["can_sell"] is True and data["field_providers"]["can_sell"] == "goplus"
    assert data["status"] == analyzed.data["status"] == risk["status"] == "ok"
    assert (analyzed.score, risk["risk_level"], extension["risk_classification"]) == (0, "LOW", "SAFE")
    assert data["rpc_failed"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [42161, 4663])
@pytest.mark.parametrize("result", [None, "0xzz"], ids=["null", "not-hex"])
async def test_a_discovery_lookup_answered_without_data_stays_unknown(chain_id, result):
    lookup = "v3-factory" if chain_id == 42161 else "v2-factory"
    adapter, node = discovery_with(chain_id, {"result": result}, lookup)
    data, analyzed, risk, extension = await scan(chain_id, adapter)
    assert data["status"] == "unknown" and data["rpc_failed"] is True
    assert "lookup failed (no result)" in data["reason"]
    assert "No supported pool found" not in data["reason"]
    assert data["simulation_failed"] is False and analyzed.score == 0
    assert risk["risk_level"] != "LOW" and extension["risk_classification"] != "SAFE"


def is_simulate(method, params):
    return method == "eth_simulateV1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "chain_id,fails",
    [
        (42161, ARBITRUM_LOOKUPS["v3-factory"]),
        (42161, is_simulate),
        (4663, ROBINHOOD_LOOKUPS["v2-factory"][0]),
        (4663, is_simulate),
    ],
    ids=["42161-discovery", "42161-simulation", "4663-discovery", "4663-simulation"],
)
async def test_an_error_the_node_answers_once_is_asked_again_and_the_simulation_completes(
    no_backoff, chain_id, fails
):
    # A node under load can time out a request once; the scan must not read unknown for that.
    if chain_id == 42161:
        fixture = load_arbitrum("v3_arb")
        rpc = ArbitrumRpc(fixture)
        addresses = patch(
            "services.arbitrum_simulation._fresh_address",
            side_effect=[fixture["buyer"], fixture["receiver"]],
        )
    else:
        fixture = load_robinhood("v2_router02")
        rpc = rpc_for(fixture, simulations=[replay(fixture), replay(fixture)])
        addresses = robinhood_addresses(fixture)
    node = Node(rpc, fails, {"error": NODE_ERROR}, times=1)
    with addresses:
        data, analyzed, risk, extension = await scan(chain_id, adapter_posting(chain_id, node), fixture["token"])
    assert node.hits == 2
    no_backoff.assert_awaited_once_with(1.0)
    assert (data["is_honeypot"], data["can_sell"], data["buy_tax"], data["sell_tax"]) == (
        False,
        True,
        0.0,
        0.0,
    )
    assert data["field_providers"]["is_honeypot"] == "eth_simulateV1"
    assert data["rpc_failed"] is False and data["simulation_failed"] is False
    assert data["status"] == risk["status"] == "ok"


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id,name", [(42161, "Arbitrum"), (4663, "Robinhood")])
async def test_the_retry_warning_names_the_error_codes_and_never_the_message(
    no_backoff, caplog, chain_id, name
):
    # A node's error message can carry the RPC URL, and with it the API key in the URL.
    leak = f"https://rpc.invalid/{SECRET}"
    errors = [
        {"code": -32000, "message": f"execution aborted (timeout = 5s) {leak}"},
        {"code": -32603, "message": f"internal error {leak}"},
        {"code": -32000, "message": f"header not found {leak}"},
        # A revert is the call's own answer: it is not what the request is asked again for.
        {**REVERTED, "message": f"execution reverted {leak}"},
    ]
    rows = [{"jsonrpc": "2.0", "id": index, "error": error} for index, error in enumerate(errors)]
    answered = [{"jsonrpc": "2.0", "id": index, "result": "0x"} for index in range(len(errors))]
    adapter = adapter_posting(chain_id, AsyncMock(side_effect=[rows, answered]))
    caplog.set_level(logging.DEBUG)
    caplog.clear()
    calls = [("eth_call", [{"to": TOKEN, "data": "0x"}, "latest"])] * len(errors)
    assert await adapter._simulator._request(None, calls) == answered
    no_backoff.assert_awaited_once_with(1.0)
    assert [record.getMessage() for record in caplog.records] == [
        f"{name} simulation RPC answered an error (JSON-RPC error -32000, JSON-RPC error -32603); "
        "asking once more"
    ]
    assert SECRET not in caplog.text


# --- the legacy token scanner, which the bot and /api/firewall fall back to -------------------------

CLEAN_POOL = outcome(can_buy=True, can_sell=True, is_honeypot=False, buy_tax=0.0, sell_tax=0.0)
TRAP_POOL = outcome(pool="0xtrap", can_buy=True, can_sell=False, is_honeypot=True, buy_tax=0.0)
FAILED_POOL = outcome(pool="0xfailed", simulation_failed=True, reason="Malformed result")


def simulation_of(*outcomes, rpc_failed=False):
    """What the chain's simulator answers for these pool outcomes, with rpc_failed as it sets it."""
    simulation = aggregate_outcomes(list(outcomes), [])
    if rpc_failed:
        simulation["rpc_failed"] = True
    simulation["observed_at"] = 1000
    return simulation


# The simulator's own "not a honeypot" beside a sell it did not settle.
UNSETTLED = {
    # One pool failed, another sold cleanly.
    "pool-failed": simulation_of(CLEAN_POOL, FAILED_POOL),
    # The simulator never sends rpc_failed beside a verdict (a simulation that could not run has
    # none), but the adapter passes on whatever it is given.
    "could-not-run": simulation_of(CLEAN_POOL, rpc_failed=True),
}
PROVEN_TRAP = {
    "pool-failed": simulation_of(TRAP_POOL, FAILED_POOL),
    "could-not-run": simulation_of(TRAP_POOL, rpc_failed=True),
}


async def answering(web3, chain_id, simulation):
    """`web3`, answering the legacy scanner's honeypot and tax questions about TOKEN as the chain's
    own adapter does when its simulator answers `simulation`."""
    adapter = arbitrum_adapter(AsyncMock()) if chain_id == 42161 else adapter_with(AsyncMock())
    adapter._simulator.simulate = AsyncMock(return_value=simulation)
    web3.supports_honeypot_simulation = MagicMock(return_value=True)
    web3.check_honeypot = AsyncMock(return_value=await adapter.check_honeypot(TOKEN))
    web3.get_tax_info = AsyncMock(return_value=await adapter.get_tax_info(TOKEN))
    return web3


async def legacy_scan(web3, chain_id, simulation):
    scanner = TokenScanner(await answering(web3, chain_id, simulation))
    return await scanner.check_token(TOKEN, chain_id=chain_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [42161, 4663])
@pytest.mark.parametrize("state", UNSETTLED)
async def test_the_legacy_scanner_leaves_the_sell_unknown_beside_a_simulation_it_did_not_settle(
    mock_web3_client, chain_id, state
):
    result = await legacy_scan(mock_web3_client, chain_id, UNSETTLED[state])
    assert result["simulation_failed" if state == "pool-failed" else "rpc_failed"] is True
    assert result["checks"]["can_sell"] is None and result["coverage"]["can_sell"] is False
    assert result["status"] == result["safety_level"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [42161, 4663])
@pytest.mark.parametrize("state", PROVEN_TRAP)
async def test_the_legacy_scanner_keeps_a_proven_honeypot_beside_a_simulation_it_did_not_settle(
    mock_web3_client, chain_id, state
):
    result = await legacy_scan(mock_web3_client, chain_id, PROVEN_TRAP[state])
    assert result["is_honeypot"] is True and result["checks"]["can_sell"] is False
    assert result["safety_level"] == "danger"
    assert "HONEYPOT DETECTED - Cannot sell after buying" in result["risks"]


# The evidence document of a simulated clean token's legacy scan on Robinhood Chain, which bot.py
# publishes when the analysis pipeline fails, as recorded at 82268d7, before the scanner carried the
# simulation's flags.
CLEAN_LEGACY_EVIDENCE = (
    b'{"chain_id":4663,"coverage":{"buy_tax":true,"can_buy":true,"can_sell":true,'
    b'"contract_age_days":true,"is_honeypot":true,"is_verified":true,"liquidity_locked":true,'
    b'"ownership_renounced":true,"sell_tax":true},"coverage_reasons":{},"observed_block":0,'
    b'"rug_probability":null,"scanned_at":0,"schema_version":1,"status":"ok",'
    b'"subject":"0x7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a","verdict":"UNKNOWN"}'
)


@pytest.mark.asyncio
async def test_the_evidence_of_a_simulated_clean_tokens_legacy_scan_is_unchanged(mock_web3_client):
    result = await legacy_scan(mock_web3_client, 4663, simulation_of(CLEAN_POOL))
    assert "simulation_failed" not in result and "rpc_failed" not in result
    assert result["status"] == "ok" and result["safety_level"] == "safe"
    assert canonical_bytes(build_evidence(4663, TOKEN, result, None)) == CLEAN_LEGACY_EVIDENCE


@pytest.mark.asyncio
@pytest.mark.parametrize("state", UNSETTLED)
async def test_the_simulations_flags_never_reach_a_legacy_scans_evidence(mock_web3_client, state):
    result = await legacy_scan(mock_web3_client, 4663, UNSETTLED[state])
    flags = ("simulation_failed", "rpc_failed")
    without = {key: value for key, value in result.items() if key not in flags}
    evidence = build_evidence(4663, TOKEN, result, None)
    assert canonical_bytes(evidence) == canonical_bytes(build_evidence(4663, TOKEN, without, None))
    assert (evidence["verdict"], evidence["status"]) == ("UNKNOWN", "unknown")
