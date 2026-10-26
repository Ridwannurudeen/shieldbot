"""A Robinhood Chain swap answers inside the firewall deadline with its analysis intact.

Blockscout (the chain's only explorer) answers an addresses/{address} lookup in 2-12 s. The structural
analyzer starts that lookup first and uses it when it answers before the analyzers' deadline; one still
running leaves only its own fields unknown, named, and fills the caches for the next scan. Exact known
addresses are not looked up at all.
"""

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from adapters.robinhood import (
    KNOWN_SPENDERS,
    PANCAKESWAP_V2_FACTORY,
    PERMIT2_ADDRESS,
    POOL_MANAGER_ADDRESS,
    UNISWAP_V2_FACTORY,
    WHITELISTED_ROUTERS,
    RobinhoodAdapter,
)
from analyzers.honeypot import STILL_RUNNING as HONEYPOT_STILL_RUNNING
from analyzers.honeypot import HoneypotAnalyzer
from analyzers.structural import StructuralAnalyzer
from api import _revert_blocks
from core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from core.policy import PolicyEngine
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine
from core.verdicts import BLOCK_RECOMMENDED
from services.contract_service import ContractService
from services.explorer_service import BACKGROUND, ExplorerService
from services.robinhood_assets import RobinhoodAssets
from services.robinhood_simulation import USDG, WETH, RobinhoodSimulator
from tests.test_consumer_unknowns import consumer_api  # noqa: F401 (fixture)
from tests.test_robinhood_assets import LISTED, NVDA, OTHER
from utils.scam_db import ScamMatches

CHAIN = 4663
STILL_RUNNING = "Explorer lookup still running at the request deadline; it continues for the next scan"
KNOWN = [
    WETH, USDG, NVDA, *WHITELISTED_ROUTERS, *KNOWN_SPENDERS,
    PERMIT2_ADDRESS, POOL_MANAGER_ADDRESS, UNISWAP_V2_FACTORY, PANCAKESWAP_V2_FACTORY,
]
BACKGROUND_TOKEN = "0x" + "9a" * 20
SELLABLE = {"is_honeypot": False, "can_sell": True, "buy_tax": 0, "sell_tax": 0, "status": "ok"}


def assets():
    service = RobinhoodAssets("http://rpc.invalid")
    service.listed = AsyncMock(return_value=LISTED)
    return service


def scam_db(goplus_record=None):
    """No scam match; GoPlus's token record as given (is_open_source says whether the source is open)."""
    return MagicMock(check_address=AsyncMock(
        return_value=ScamMatches(observed_at=time.time(), goplus_record=goplus_record),
    ))


class Answered(Analyzer):
    """An analyzer that answers at once with a fixed result."""

    def __init__(self, name, weight, score, data):
        self._name, self._weight, self._score, self._data = name, weight, score, data

    @property
    def name(self):
        return self._name

    @property
    def weight(self):
        return self._weight

    async def analyze(self, ctx):
        return AnalyzerResult(self._name, self._weight, self._score, data=dict(self._data))


def hanging(gate, answer):
    async def lookup(*args, **kwargs):
        await gate.wait()
        return answer
    return lookup


@pytest.mark.asyncio
@pytest.mark.parametrize("address", KNOWN)
async def test_exact_known_addresses_skip_the_explorer(mock_web3_client, address):
    analyzer = StructuralAnalyzer(ContractService(mock_web3_client, scam_db()), robinhood_assets=assets())

    result = await analyzer.analyze(
        AnalysisContext(address, CHAIN, extra={"deadline": time.monotonic() + 5}),
    )

    mock_web3_client.is_verified_contract.assert_not_awaited()
    mock_web3_client.get_contract_creation_info.assert_not_awaited()
    # The fast checks still run.
    mock_web3_client.get_ownership_info.assert_awaited_once()
    mock_web3_client.get_bytecode.assert_awaited_once()
    assert result.data["status"] == "ok"
    assert set(result.data["coverage_exemptions"]) == {"is_verified", "contract_age_days"}
    assert "coverage_reasons" not in result.data
    assert result.data["notes"][0].startswith("Explorer verification and contract age not needed: ")
    assert result.data["notes"][0].endswith("(exact address)")
    risk = RiskEngine().compute_from_results([result])
    assert risk["coverage"]["structural"] == 1
    assert "structural" not in risk["coverage_reasons"]


@pytest.mark.asyncio
async def test_any_other_address_is_looked_up(mock_web3_client):
    data = await ContractService(mock_web3_client, scam_db()).fetch_contract_data(
        OTHER, chain_id=CHAIN, robinhood_assets=assets(), deadline=time.monotonic() + 5,
    )

    mock_web3_client.is_verified_contract.assert_awaited_once_with(OTHER, chain_id=CHAIN)
    mock_web3_client.get_contract_creation_info.assert_awaited_once_with(OTHER, chain_id=CHAIN)
    assert (data["is_verified"], data["contract_age_days"]) == (True, 90)
    assert "coverage_exemptions" not in data


@pytest.mark.asyncio
async def test_a_cold_official_list_does_not_hold_up_the_lookups(mock_web3_client):
    gate = asyncio.Event()
    official = RobinhoodAssets("http://rpc.invalid")
    official.listed = hanging(gate, LISTED)

    data = await ContractService(mock_web3_client, scam_db()).fetch_contract_data(
        OTHER, chain_id=CHAIN, robinhood_assets=official, deadline=time.monotonic() + 5,
    )

    mock_web3_client.is_verified_contract.assert_awaited_once()
    assert (data["is_verified"], data["contract_age_days"]) == (True, 90)
    assert "coverage_reasons" not in data
    gate.set()
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_a_late_exemption_keeps_the_explorer_answers_that_arrived(mock_web3_client):
    # The official list answers after the lookups started; it exempts only what they left unanswered.
    listed, creation = asyncio.Event(), asyncio.Event()
    official = RobinhoodAssets("http://rpc.invalid")
    official.listed = hanging(listed, LISTED)
    mock_web3_client.get_contract_creation_info.side_effect = hanging(creation, {"age_days": 90})
    loop = asyncio.get_running_loop()
    loop.call_later(0.1, listed.set)

    with patch("services.contract_service.BSCSCAN_DELAY", 0), patch(
        "services.contract_service.EXPLORER_RESULT_RESERVE_SECONDS", 0,
    ):
        data = await ContractService(mock_web3_client, scam_db()).fetch_contract_data(
            NVDA, chain_id=CHAIN, robinhood_assets=official, deadline=time.monotonic() + 0.3,
        )

    assert data["is_verified"] is True  # the explorer's answer, kept
    assert set(data["coverage_exemptions"]) == {"contract_age_days"}
    assert "coverage_reasons" not in data
    creation.set()
    await asyncio.sleep(0)


async def structural_and_answers(mock_web3_client, gate):
    """One unverified token scanned by the registry as a swap token is: the real structural analyzer
    and two answered analyzers. Sourcify and Blockscout say unverified and the creation is 90 days old
    once ``gate`` opens; GoPlus says the source is closed."""
    mock_web3_client.is_verified_contract.side_effect = hanging(gate, (False, None))
    mock_web3_client.get_contract_creation_info.side_effect = hanging(gate, {"age_days": 90})
    registry = AnalyzerRegistry()
    registry.register(StructuralAnalyzer(
        ContractService(mock_web3_client, scam_db({"is_open_source": "0"})), robinhood_assets=assets(),
    ))
    registry.register(Answered("market", 0.3, 32, {"status": "ok"}))
    registry.register(Answered("honeypot", 0.3, 32, SELLABLE))
    deadline = 0.4
    with patch("services.contract_service.BSCSCAN_DELAY", 0), patch(
        "services.contract_service.EXPLORER_RESULT_RESERVE_SECONDS", 0.1,
    ):
        return await registry.run_all(
            AnalysisContext(OTHER, CHAIN, extra={"deadline": time.monotonic() + deadline}),
            deadline=deadline,
        )


@pytest.mark.asyncio
async def test_a_slow_explorer_never_yields_a_harsher_verdict(mock_web3_client):
    # Swap 2 of the root-cause trace: CAUTION with a reverted simulation. A revert blocks only a
    # score of REVERT_BLOCK_MIN or more, so the score must not rise because the explorer was slow.
    answered = asyncio.Event()
    answered.set()
    full_results = await structural_and_answers(mock_web3_client, answered)
    slow = asyncio.Event()
    mock_web3_client.reset_mock()
    slow_results = await structural_and_answers(mock_web3_client, slow)

    engine = RiskEngine()
    full = engine.compute_from_results(full_results, is_token=True)
    partial = engine.compute_from_results(slow_results, is_token=True)

    structural = next(result for result in slow_results if result.name == "structural")
    assert structural.error is None
    assert structural.data["is_verified"] is False  # GoPlus's is_open_source
    assert structural.data["coverage_reasons"] == {"contract_age_days": STILL_RUNNING}
    assert partial["category_scores"]["structural"] == full["category_scores"]["structural"] == 25
    assert partial["status"] == "unknown" and full["status"] == "ok"
    assert partial["score_before_community_floor"] <= full["score_before_community_floor"]
    assert not _revert_blocks(full)
    assert not _revert_blocks(partial)
    # What this guards against: the same answers with the structural analyzer failed as a whole leave
    # it out of the mean, which renormalises over the others to a block.
    failed = engine.compute_from_results([
        AnalyzerResult("structural", structural.weight, 50, error="structural analysis unavailable (TimeoutError)"),
        *(result for result in slow_results if result.name != "structural"),
    ], is_token=True)
    assert _revert_blocks(failed)

    slow.set()
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_an_abandoned_explorer_lookup_finishes_and_fills_the_caches(monkeypatch, mock_web3_client):
    # The structural analyzer gives up on Blockscout at its deadline; the lookup runs on, and the next
    # scan of the token is answered from the caches without a request.
    monkeypatch.setenv("BLOCKSCOUT_API_KEY", "test-key")
    address = OTHER
    release = asyncio.Event()
    gets = []

    def reply(status, payload, wait=None):
        async def enter():
            if wait is not None:
                await wait.wait()
            response = MagicMock(status=status)
            response.json = AsyncMock(return_value=payload)
            return response
        context = MagicMock()
        context.__aenter__ = AsyncMock(side_effect=enter)
        context.__aexit__ = AsyncMock(return_value=False)
        return context

    def get(url, params=None, **kwargs):
        gets.append(url)
        if "sourcify" in url:
            return reply(404, {
                "match": None, "creationMatch": None, "runtimeMatch": None,
                "chainId": str(CHAIN), "address": address,
            })
        return reply(200, {
            "hash": address, "is_contract": True, "is_verified": False, "creation_status": "success",
            "creator_address_hash": "0x" + "cd" * 20, "creation_transaction_hash": "0x" + "ef" * 32,
        }, release)

    session = MagicMock()
    session.get.side_effect = get
    adapter = RobinhoodAdapter("https://rpc.invalid")
    adapter._explorer_service = ExplorerService()

    async def dated(creation):
        return {**creation, "age_days": 90}

    adapter._date_creation = dated
    adapter.get_bytecode = AsyncMock(return_value="0x6080")
    mock_web3_client.is_verified_contract = lambda address, chain_id: adapter.is_verified_contract(address)
    mock_web3_client.get_contract_creation_info = (
        lambda address, chain_id: adapter.get_contract_creation_info(address)
    )
    service = ContractService(mock_web3_client, scam_db())
    with patch("aiohttp.ClientSession") as client, patch(
        "services.contract_service.BSCSCAN_DELAY", 0,
    ), patch("services.contract_service.EXPLORER_RESULT_RESERVE_SECONDS", 0):
        client.return_value.__aenter__.return_value = session
        first = await service.fetch_contract_data(address, chain_id=CHAIN, deadline=time.monotonic() + 0.05)
        assert first["coverage_reasons"] == {"is_verified": STILL_RUNNING, "contract_age_days": STILL_RUNNING}

        release.set()
        for _ in range(100):
            if adapter._creation_infos.get((CHAIN, address)):
                break
            await asyncio.sleep(0.01)
        second = await service.fetch_contract_data(address, chain_id=CHAIN, deadline=time.monotonic() + 0.05)

    assert (second["is_verified"], second["contract_age_days"]) == (False, 90)
    assert "coverage_reasons" not in second
    # One Sourcify and one Blockscout request served both lookups of both scans.
    assert len(gets) == 2
    assert [url for url in gets if "blockscout" in url][0].endswith(f"/addresses/{address}")


@pytest.mark.asyncio
async def test_firewall_swap_answers_inside_the_deadline_with_structural_present(consumer_api, monkeypatch):  # noqa: F811
    # An end-to-end POST /api/firewall swap on 4663 through a trusted router, into an unknown token
    # and canonical WETH, while Blockscout hangs. Deadlines are scaled down from 7.5 s to 1 s.
    api, services = consumer_api
    monkeypatch.setattr(api, "FIREWALL_REQUEST_DEADLINE_SECONDS", 1.0)
    services.web3_client.supports_honeypot_simulation = lambda chain_id: chain_id in {42161, 4663}
    monkeypatch.setattr(api, "FIREWALL_RESPONSE_RESERVE_SECONDS", 0.1)
    monkeypatch.setattr("services.contract_service.EXPLORER_RESULT_RESERVE_SECONDS", 0.3)
    api.risk_engine = RiskEngine()
    sender = "0x" + "b" * 40
    decoded = {
        "selector": "38ed1739", "function_name": "swapExactTokensForTokens",
        "category": "swap", "params": {"path": [OTHER, WETH], "to": sender},
    }
    api.calldata_decoder = SimpleNamespace(
        decode=lambda _: decoded,
        is_whitelisted_target=lambda *args, **kwargs: "Robinhood Router",
    )
    web3 = services.web3_client
    web3._get_adapter = lambda chain_id: None
    blockscout = asyncio.Event()
    web3.is_verified_contract = AsyncMock(side_effect=hanging(blockscout, (True, None)))
    web3.get_contract_creation_info = AsyncMock(side_effect=hanging(blockscout, {"age_days": 400}))
    registry = AnalyzerRegistry()
    registry.register(StructuralAnalyzer(
        ContractService(web3, scam_db({"is_open_source": "1"})), robinhood_assets=assets(),
    ))
    registry.register(Answered("market", 0.3, 0, {"status": "ok"}))
    registry.register(Answered("honeypot", 0.3, 0, SELLABLE))
    services.registry = registry
    services.policy_engine = PolicyEngine("BALANCED")

    import httpx
    started = time.monotonic()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver",
    ) as client:
        http_response = await client.post("/api/firewall", json={
            "to": "0x" + "a" * 40, "from": sender, "chainId": CHAIN, "value": "0", "data": "0x38ed1739",
        })
    elapsed = time.monotonic() - started
    response = http_response.json()

    assert http_response.status_code == 200
    # The proof is the shape below; the clock gets a margin for a slow runner.
    assert elapsed < 2.0
    other, weth = (api.web3_client.to_checksum_address(token) for token in (OTHER, WETH))
    # Structural answered for both tokens: canonical WETH in full, the unknown token with its age
    # alone unknown (GoPlus gives its verification), named.
    assert response["coverage"][f"{weth}:structural"] == 1
    assert 0 < response["coverage"][f"{other}:structural"] < 1
    assert response["coverage_reasons"][f"{other}:structural"] == f"contract age: {STILL_RUNNING}"
    assert not any("unavailable" in reason for reason in response["coverage_reasons"].values())
    assert response["coverage"][f"{other}:honeypot"] == 1
    assert response["status"] == "unknown"
    assert response["classification"] != BLOCK_RECOMMENDED
    # Only the unknown token was looked up, once per lookup.
    web3.is_verified_contract.assert_awaited_once_with(other, chain_id=CHAIN)
    web3.get_contract_creation_info.assert_awaited_once_with(other, chain_id=CHAIN)

    blockscout.set()
    await asyncio.sleep(0)


def simulated(gate=None):
    """A simulator whose run for a token waits on ``gate`` (when given), then finds it sellable."""
    simulator = RobinhoodSimulator("https://rpc.invalid")
    order = []

    async def run(token):
        order.append(token)
        if gate is not None and token == BACKGROUND_TOKEN:
            await gate.wait()
        return {
            "is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0,
            "reason": "", "simulation_block": 1,
        }

    simulator._run = run
    return simulator, order


def honeypot_on(simulator):
    service = SimpleNamespace(fetch_honeypot_data=lambda address, chain_id: simulator.simulate(address))
    return HoneypotAnalyzer(service, assets())


async def background(simulator, token):
    """A simulation the hunter started: it takes background turns."""
    BACKGROUND.set(True)
    return await simulator.simulate(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("token", [OTHER, NVDA], ids=["unknown-token", "official-stock"])
async def test_a_queued_simulation_degrades_to_a_named_gap_never_an_error(token):
    # The hunter's simulation holds the lane past this scan's deadline.
    gate = asyncio.Event()
    simulator, order = simulated(gate)
    hunter = asyncio.create_task(background(simulator, BACKGROUND_TOKEN))
    await asyncio.sleep(0)
    registry = AnalyzerRegistry()
    registry.register(Answered("structural", 0.4, 25, {"is_contract": True, "is_verified": False, "contract_age_days": 90}))
    registry.register(Answered("market", 0.3, 32, {"status": "ok"}))
    registry.register(honeypot_on(simulator))

    with patch("analyzers.honeypot.SIMULATION_RESULT_RESERVE_SECONDS", 0.1):
        results = await registry.run_all(
            AnalysisContext(token, CHAIN, extra={"deadline": time.monotonic() + 0.3}), deadline=0.3,
        )

    honeypot = next(result for result in results if result.name == "honeypot")
    assert honeypot.error is None
    assert not honeypot.data.get("skipped")  # an official stock is not let off as "does not apply"
    assert honeypot.data["status"] == "unknown"
    assert honeypot.data["coverage"]["can_sell"] is False
    assert honeypot.data["reason"] == HONEYPOT_STILL_RUNNING
    assert honeypot.score == 0
    # Under the risk engine's rules an unanswered sell check counts exactly as a failed one: the
    # verdict is the one the error gave, never harsher.
    engine = RiskEngine()
    errored = [
        AnalyzerResult("honeypot", honeypot.weight, 50, error="honeypot analysis unavailable (TimeoutError)")
        if result.name == "honeypot" else result
        for result in results
    ]
    degraded, failed = engine.compute_from_results(results), engine.compute_from_results(errored)
    assert degraded["score_before_community_floor"] == failed["score_before_community_floor"]
    assert degraded["coverage_reasons"]["honeypot"] == HONEYPOT_STILL_RUNNING

    # The simulation runs on and its cached answer serves the next scan.
    gate.set()
    await hunter
    for _ in range(100):
        if token.lower() in simulator._cache:
            break
        await asyncio.sleep(0.01)
    assert simulator._cache[token.lower()]["can_sell"] is True
    assert order == [BACKGROUND_TOKEN, token.lower()]


@pytest.mark.asyncio
async def test_a_user_simulation_goes_before_waiting_background_ones():
    gate = asyncio.Event()
    simulator, order = simulated(gate)
    hunter = asyncio.create_task(background(simulator, BACKGROUND_TOKEN))
    await asyncio.sleep(0)
    later = "0x" + "12" * 20
    joined = "0x" + "34" * 20
    user = "0x" + "56" * 20
    waiting = [
        asyncio.create_task(background(simulator, later)),
        asyncio.create_task(background(simulator, joined)),
    ]
    for _ in range(5):
        waiting.append(asyncio.create_task(simulator.simulate(user)))
    for _ in range(5):
        await asyncio.sleep(0)
    # A user joins a background simulation still waiting for its turn: it takes a user's turn.
    waiting.append(asyncio.create_task(simulator.simulate(joined)))
    await asyncio.sleep(0)

    gate.set()
    await asyncio.gather(hunter, *waiting)

    assert order == [BACKGROUND_TOKEN, user, joined, later]


@pytest.mark.asyncio
async def test_a_two_unknown_token_swap_answers_with_honeypot_unknown_while_the_hunter_simulates(
    consumer_api, monkeypatch,  # noqa: F811
):
    api, services = consumer_api
    monkeypatch.setattr(api, "FIREWALL_REQUEST_DEADLINE_SECONDS", 1.0)
    services.web3_client.supports_honeypot_simulation = lambda chain_id: chain_id in {42161, 4663}
    monkeypatch.setattr(api, "FIREWALL_RESPONSE_RESERVE_SECONDS", 0.1)
    monkeypatch.setattr("analyzers.honeypot.SIMULATION_RESULT_RESERVE_SECONDS", 0.3)
    api.risk_engine = RiskEngine()
    sender = "0x" + "b" * 40
    second = "0x" + "cd" * 20
    decoded = {
        "selector": "38ed1739", "function_name": "swapExactTokensForTokens",
        "category": "swap", "params": {"path": [OTHER, second], "to": sender},
    }
    api.calldata_decoder = SimpleNamespace(
        decode=lambda _: decoded, is_whitelisted_target=lambda *args, **kwargs: "Robinhood Router",
    )
    services.web3_client._get_adapter = lambda chain_id: None
    gate = asyncio.Event()
    simulator, _ = simulated(gate)
    hunter = asyncio.create_task(background(simulator, BACKGROUND_TOKEN))
    await asyncio.sleep(0)
    registry = AnalyzerRegistry()
    registry.register(Answered("structural", 0.4, 25, {"is_contract": True, "is_verified": False, "contract_age_days": 90}))
    registry.register(Answered("market", 0.3, 0, {"status": "ok"}))
    registry.register(honeypot_on(simulator))
    services.registry = registry
    services.policy_engine = PolicyEngine("BALANCED")

    import httpx
    started = time.monotonic()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver",
    ) as client:
        http_response = await client.post("/api/firewall", json={
            "to": "0x" + "a" * 40, "from": sender, "chainId": CHAIN, "value": "0", "data": "0x38ed1739",
        })
    elapsed = time.monotonic() - started
    response = http_response.json()

    assert http_response.status_code == 200
    assert elapsed < 2.0  # a 1 s deadline; the margin is for a slow runner
    for token in (OTHER, second):
        address = api.web3_client.to_checksum_address(token)
        assert response["coverage"][f"{address}:honeypot"] == 0
        assert response["coverage_reasons"][f"{address}:honeypot"] == HONEYPOT_STILL_RUNNING
        assert response["coverage"][f"{address}:structural"] == 1
    assert not any("unavailable" in reason for reason in response["coverage_reasons"].values())
    assert response["classification"] != BLOCK_RECOMMENDED

    gate.set()
    await hunter


@pytest.mark.asyncio
async def test_other_chains_keep_no_request_deadline(consumer_api, monkeypatch):  # noqa: F811
    api, services = consumer_api
    monkeypatch.setattr(api, "FIREWALL_REQUEST_DEADLINE_SECONDS", 0.05)
    services.web3_client.supports_honeypot_simulation = lambda chain_id: chain_id in {42161, 4663}
    services.registry.get_all = lambda: [SimpleNamespace(name="structural")]

    async def slow_token_info(address, **kwargs):
        await asyncio.sleep(0.2)
        return {}

    api.web3_client.get_token_info = slow_token_info
    api.risk_engine = RiskEngine()
    api.calldata_decoder = SimpleNamespace(
        decode=lambda _: {
            "selector": "095ea7b3", "function_name": "approve", "category": "approval",
            "is_approval": True, "params": {"spender": "0x" + "e" * 40, "amount": 1},
        },
        is_whitelisted_target=lambda *args, **kwargs: None,
    )

    response = await api.firewall(
        api.FirewallRequest(to="0x" + "f" * 40, sender="0x" + "b" * 40, chainId=56, data="0x095ea7b3"),
        SimpleNamespace(headers={}),
    )

    assert "token_metadata" not in response.get("coverage_reasons", {})
    assert not response.get("pending_sources")


@pytest.mark.asyncio
async def test_a_provider_timeout_is_not_relabelled_as_the_request_deadline(consumer_api, monkeypatch):  # noqa: F811
    api, _ = consumer_api
    error = TimeoutError("provider")

    async def verdict(*args, **kwargs):
        raise error

    monkeypatch.setattr(api, "_firewall_verdict", verdict)
    with pytest.raises(TimeoutError) as raised:
        await api.firewall(
            api.FirewallRequest(to="0x" + "f" * 40, sender="0x" + "b" * 40, chainId=CHAIN),
            SimpleNamespace(headers={}),
        )
    assert raised.value is error
