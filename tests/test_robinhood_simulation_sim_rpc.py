"""Optional Robinhood simulation RPC routing and official-node fallback."""

import asyncio
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from services.robinhood_simulation import (
    RobinhoodSimulator,
    SimulationUnavailable,
    aggregate_outcomes,
)
from tests.test_robinhood_simulation import (
    FakeRpc,
    evaluate,
    fresh_addresses,
    load,
    rpc_for,
    simulation_requests,
)
from tests.test_robinhood_simulation_hookless_usdg import storage_values


class ProviderRpc:
    """Minimal provider fake that records each header and simulation request."""

    def __init__(self, head, simulation=None, header=None, failure=None):
        self.head = head
        self.simulation = simulation
        self.header = header
        self.failure = failure
        self.requests = []

    async def __call__(self, session, calls):
        self.requests.append(calls)
        assert len(calls) == 1
        method, params = calls[0]
        if self.failure is not None:
            raise self.failure
        if method == "eth_getBlockByNumber":
            assert params == ["latest", False]
            result = self.header if self.header is not None else {"result": {"number": hex(self.head)}}
        else:
            assert method == "eth_simulateV1"
            result = self.simulation
        return [{"jsonrpc": "2.0", "id": 0, **result}]


def _fixture_and_official(head=None):
    fixture = load("v4_hookless_usdg_nvda")
    block = fixture["block"] if head is None else head
    official = rpc_for(
        fixture,
        head=block,
        pool_slots=storage_values(tuple(fixture["key"]), 1),
    )
    return fixture, block, official


def _without_observed_at(result):
    return {key: value for key, value in result.items() if key != "observed_at"}


def _golden(fixture, head):
    return aggregate_outcomes([{**evaluate(fixture), "block": head}], [])


@pytest.mark.asyncio
async def test_provider_handles_pool_header_and_simulation_and_matches_official_golden():
    fixture, head, official = _fixture_and_official()
    provider = ProviderRpc(head, simulation=fixture["response"])
    simulator = RobinhoodSimulator("https://official.example", sim_rpc_url="https://sim.example")
    simulator._request = official
    simulator._sim_request = provider

    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])

    assert [calls[0][0] for calls in provider.requests] == [
        "eth_getBlockByNumber",
        "eth_simulateV1",
    ]
    assert provider.requests[0] == [("eth_getBlockByNumber", ["latest", False])]
    assert provider.requests[1] == [("eth_simulateV1", [fixture["request"][0], hex(head)])]
    assert simulation_requests(official) == []
    assert all(
        method in {"eth_call", "eth_blockNumber", "eth_getLogs"}
        for calls in official.requests
        for method, _ in calls
    )
    assert _without_observed_at(result) == _golden(fixture, head)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure,header,sim_error",
    [
        (SimulationUnavailable("RPC HTTP 429"), None, None),
        (SimulationUnavailable("RPC HTTP 403"), None, None),
        (aiohttp.ClientError(), None, None),
        (asyncio.TimeoutError(), None, None),
        (None, {"result": None}, None),
        (None, None, {"code": -32602, "message": "Archive requests require a personal token"}),
        (None, None, {"code": -32000, "message": "historical state is not available"}),
        (None, None, {"code": -32601, "message": "method does not exist"}),
        (None, None, {"code": -32603, "message": "handler crashed"}),
        (None, None, {"code": -32005, "message": "rate limit exceeded"}),
    ],
    ids=[
        "http-429",
        "http-403",
        "client-error",
        "timeout",
        "invalid-header",
        "archive-state",
        "historical-state",
        "unsupported-method",
        "handler-crash",
        "json-rpc-rate-limit",
    ],
)
async def test_provider_failures_fall_back_to_a_fresh_official_header(
    failure, header, sim_error, caplog
):
    fixture, official_head, official = _fixture_and_official()
    sim_response = {"error": sim_error} if sim_error is not None else fixture["response"]
    provider = ProviderRpc(
        fixture["block"] + 25,
        simulation=sim_response,
        header=header,
        failure=failure,
    )
    simulator = RobinhoodSimulator("https://official.example", sim_rpc_url="https://sim.example")
    simulator._request = official
    simulator._sim_request = provider

    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])

    assert official.requests[-2] == [("eth_getBlockByNumber", ["latest", False])]
    assert official.requests[-1] == [
        ("eth_simulateV1", [fixture["request"][0], hex(official_head)])
    ]
    assert simulation_requests(official) == [official.requests[-1]]
    assert _without_observed_at(result) == _golden(fixture, official_head)
    assert caplog.text.count("Robinhood simulation provider fallback:") == 1
    assert "https://sim.example" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("fallback", [False, True], ids=["provider-success", "provider-fallback"])
async def test_provider_and_official_blocks_never_cross(fallback):
    fixture = load("v4_hookless_usdg_nvda")
    provider_head = fixture["block"] + 25
    official_head = fixture["block"] - 37
    _, _, official = _fixture_and_official(official_head)
    sim_response = (
        {"error": {"code": -32602, "message": "historical state unavailable"}}
        if fallback
        else fixture["response"]
    )
    provider = ProviderRpc(provider_head, simulation=sim_response)
    simulator = RobinhoodSimulator("https://official.example", sim_rpc_url="https://sim.example")
    simulator._request = official
    simulator._sim_request = provider

    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])

    assert provider.requests[1] == [
        ("eth_simulateV1", [fixture["request"][0], hex(provider_head)])
    ]
    if fallback:
        assert official.requests[-2] == [("eth_getBlockByNumber", ["latest", False])]
        assert official.requests[-1] == [
            ("eth_simulateV1", [fixture["request"][0], hex(official_head)])
        ]
        expected_head = official_head
    else:
        assert simulation_requests(official) == []
        expected_head = provider_head
    assert _without_observed_at(result) == _golden(fixture, expected_head)


@pytest.mark.asyncio
async def test_simulation_rpc_is_off_by_default_and_keeps_the_official_request_sequence():
    fixture, head, official = _fixture_and_official()
    simulator = RobinhoodSimulator("https://official.example")
    simulator._request = official
    simulator._sim_request = AsyncMock(side_effect=AssertionError("optional provider was used"))

    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])

    assert simulator._sim_request.await_count == 0
    assert len(official.requests) == 3
    assert all(method == "eth_call" for method, _ in official.requests[0])
    assert official.requests[1] == [("eth_getBlockByNumber", ["latest", False])]
    assert official.requests[2] == [
        ("eth_simulateV1", [fixture["request"][0], hex(head)])
    ]
    assert _without_observed_at(result) == _golden(fixture, head)


@pytest.mark.asyncio
async def test_post_fail_fast_makes_one_429_attempt_without_sleep():
    from tests.test_robinhood_simulation import http_response, http_session

    simulator = RobinhoodSimulator("https://official.example")
    session = http_session(http_response(429), http_response(429), http_response(429))
    with patch("services.robinhood_simulation.asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(SimulationUnavailable, match="HTTP 429"):
            await simulator._post(
                session,
                [("eth_simulateV1", [{}, "0x1"])],
                url="https://sim.example",
                fail_fast=True,
            )
    assert session.post.call_count == 1
    assert session.post.call_args.args[0] == "https://sim.example"
    sleep.assert_not_awaited()


def test_adapter_reads_optional_sim_rpc_environment_variable(monkeypatch):
    from adapters.robinhood import RobinhoodAdapter

    monkeypatch.setenv("ROBINHOOD_SIM_RPC_URL", "https://sim-env.example")
    with patch("adapters.evm_base.Web3"):
        configured = RobinhoodAdapter()
    assert configured._simulator._sim_rpc_url == "https://sim-env.example"

    monkeypatch.delenv("ROBINHOOD_SIM_RPC_URL", raising=False)
    with patch("adapters.evm_base.Web3"):
        unset = RobinhoodAdapter()
    assert unset._simulator._sim_rpc_url is None
