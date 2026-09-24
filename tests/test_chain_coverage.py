"""GET /api/coverage/{chain_id}: what each chain's configuration lets a scan check, and how its providers are
answering, from configuration and in-memory counters alone."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import aiohttp
import pytest
import requests
from fastapi.testclient import TestClient

from adapters.arbitrum import ArbitrumAdapter
from adapters.base_chain import BaseChainAdapter
from adapters.bsc import BscAdapter
from adapters.eth import EthAdapter
from adapters.robinhood import RobinhoodAdapter
from core.unknown_ledger import UnknownLedger
from services.rescue_service import RescueService
from utils.web3_client import Web3Client

RPC = "https://rpc.invalid"


@pytest.fixture
def coverage(monkeypatch):
    import api

    registry = Web3Client.__new__(Web3Client)
    adapters = (
        BscAdapter(rpc_url=RPC),
        EthAdapter(rpc_url=RPC),
        BaseChainAdapter(rpc_url=RPC),
        ArbitrumAdapter(rpc_url=RPC),
        RobinhoodAdapter(rpc_url=RPC),
    )
    registry._adapters = {adapter.chain_id: adapter for adapter in adapters}
    mempool = SimpleNamespace(
        get_stats=MagicMock(return_value={"monitored_chains": [56, 1], "unobservable_chains": [1]})
    )
    services = SimpleNamespace(
        settings=SimpleNamespace(admin_secret="", trusted_proxies=[]),
        auth_manager=None,
        db=None,
        mempool_monitor=mempool,
        phishing_service=None,
        rescue_service=RescueService(registry, logs_rpcs={56: "https://logs.invalid"}),
    )
    ledger = UnknownLedger()
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "unknown_ledger", ledger)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))

    def refuse(*args, **kwargs):
        raise AssertionError("the coverage report must not send a provider request")

    # Providers are reached through aiohttp sessions and web3's requests-based HTTP provider.
    monkeypatch.setattr(aiohttp, "ClientSession", refuse)
    monkeypatch.setattr(requests.Session, "send", refuse)
    client = TestClient(api.app)
    yield SimpleNamespace(
        get=lambda chain_id: client.get(f"/api/coverage/{chain_id}"),
        ledger=ledger,
        services=services,
    )
    client.close()


def test_bsc_simulates_sells_reads_etherscan_and_knows_its_lockers(coverage):
    body = coverage.get(56).json()
    assert body["chain_id"] == 56
    assert body["chain_name"] == "BSC"
    assert body["capabilities"] == {
        "sell_simulation": "honeypot.is",
        "contract_age": "etherscan",
        "verification": "etherscan",
        "liquidity_lock": {"lockers": "known", "known_lockers": ["PinkLock", "Unicrypt"]},
        "router_allowlist": {"present": True, "routers": 6},
        "public_mempool": "yes",
        "approvals": {"history": "full", "window_blocks": None},
    }


def test_robinhood_simulates_with_eth_simulate_and_reads_blockscout(coverage):
    capabilities = coverage.get(4663).json()["capabilities"]
    assert capabilities["sell_simulation"] == "eth_simulateV1"
    assert capabilities["contract_age"] == "blockscout"
    assert capabilities["verification"] == "sourcify+blockscout"
    # Only burn addresses are known, so an unlocked pool cannot be told from one held by an unlisted locker.
    assert capabilities["liquidity_lock"] == {"lockers": "unknown", "known_lockers": []}
    assert capabilities["router_allowlist"] == {"present": True, "routers": 2}
    assert capabilities["public_mempool"] == "no"
    assert capabilities["approvals"] == {"history": "recent", "window_blocks": 240_000}


def test_base_ages_contracts_through_blockscout_and_reads_short_log_windows(coverage):
    capabilities = coverage.get(8453).json()["capabilities"]
    assert capabilities["sell_simulation"] == "honeypot.is"
    assert capabilities["contract_age"] == "blockscout"
    assert capabilities["verification"] == "etherscan"
    assert capabilities["approvals"] == {"history": "recent", "window_blocks": 48_000}


def test_a_chain_without_a_simulator_reports_goplus_flags(coverage):
    assert coverage.get(42161).json()["capabilities"]["sell_simulation"] == "goplus_reported"


def test_a_monitored_mempool_the_monitor_could_not_read_is_unobservable(coverage):
    assert coverage.get(1).json()["capabilities"]["public_mempool"] == "unobservable"


def test_without_a_running_monitor_a_public_mempool_is_unobservable_not_watched(coverage):
    coverage.services.mempool_monitor = None
    assert coverage.get(56).json()["capabilities"]["public_mempool"] == "unobservable"


def test_provider_health_is_the_chain_s_ledger_with_chain_independent_providers(coverage):
    coverage.ledger.record("honeypot.is", 56, "answered")
    coverage.ledger.record("honeypot.is", 56, "failed")
    coverage.ledger.record("rpc", 1, "failed")
    coverage.ledger.record("goplus_phishing", None, "unknown")

    health = coverage.get(56).json()["provider_health"]

    assert health["counting_since"] == coverage.ledger.counting_since
    assert list(health["providers"]) == ["honeypot.is"]
    honeypot = health["providers"]["honeypot.is"]
    assert (honeypot["answered"], honeypot["unknown"], honeypot["failed"]) == (1, 0, 1)
    assert honeypot["last_outcome"] == "failed"
    assert list(health["chain_independent"]) == ["goplus_phishing"]


def test_provider_health_before_any_request_is_empty_not_healthy(coverage):
    health = coverage.get(4663).json()["provider_health"]
    assert health["providers"] == {}


@pytest.mark.parametrize("chain_id", [999, 204, 0])
def test_an_unsupported_chain_is_rejected(coverage, chain_id):
    response = coverage.get(chain_id)
    assert response.status_code == 400


def test_the_report_never_names_an_rpc_url(coverage):
    text = coverage.get(56).text
    assert "logs.invalid" not in text
    assert "rpc.invalid" not in text
