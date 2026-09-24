"""GET /api/ready: 200 only while the database and at least one chain's RPC answer."""

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import api
from core.circuit_breaker import FAILURE_THRESHOLD, provider_breakers
from services.rpc_guard import BREAKER_FAILURE_THRESHOLD, RpcGuard

SECRET_URL = "https://rpc.secret.example/v1/key-123"


def database(error=None, hangs=False, queries=None):
    cursor = MagicMock()
    cursor.fetchone = AsyncMock(return_value=(1,))

    async def execute(sql):
        if queries is not None:
            queries.append(sql)
        if hangs:
            await asyncio.Event().wait()
        if error is not None:
            raise error
        return cursor

    return SimpleNamespace(_db=SimpleNamespace(execute=execute))


def chains(answers: dict, asked: list):
    """A web3 client whose chains answer eth_blockNumber when ``answers[chain_id]`` is true."""

    def web3_for(chain_id):
        def get_block_number():
            asked.append(chain_id)
            if not answers[chain_id]:
                raise ConnectionError(f"{SECRET_URL} refused the connection")
            return 1234

        return SimpleNamespace(eth=SimpleNamespace(get_block_number=get_block_number))

    client = MagicMock()
    client.get_supported_chain_ids.return_value = list(answers)
    client.get_web3.side_effect = web3_for
    return client


@pytest.fixture
def serve(monkeypatch):
    monkeypatch.setattr(api, "_ready_cache", {"body": None, "expires_at": 0.0})

    def configure(db, web3_client, guard=None):
        monkeypatch.setattr(
            api,
            "container",
            SimpleNamespace(
                db=db,
                web3_client=web3_client,
                robinhood_rpc_guard=guard or RpcGuard("Robinhood Chain"),
            ),
        )
        return TestClient(api.app)

    return configure


def test_ready_when_the_database_and_one_chain_answer(serve):
    asked, queries = [], []
    client = serve(database(queries=queries), chains({56: False, 1: True, 8453: True}, asked))
    response = client.get("/api/ready")
    assert response.status_code == 200
    assert response.json() == {
        "ready": True,
        "checks": {"database": "ok", "rpc": "ok", "robinhood_rpc": "ok"},
    }
    assert queries == ["SELECT 1"]
    # Chains are asked one at a time, and the first answer ends the check.
    assert asked == [56, 1]


def test_not_ready_when_the_database_fails(serve):
    client = serve(database(error=RuntimeError("disk I/O error")), chains({56: True}, []))
    response = client.get("/api/ready")
    assert response.status_code == 503
    assert response.json()["ready"] is False
    assert response.json()["checks"]["database"] == "failed"
    assert response.json()["checks"]["rpc"] == "ok"


def test_not_ready_when_no_chain_answers(serve):
    asked = []
    client = serve(database(), chains({56: False, 1: False, 4663: False}, asked))
    response = client.get("/api/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {"database": "ok", "rpc": "failed", "robinhood_rpc": "ok"}
    assert asked == [56, 1, 4663]


def test_a_hanging_check_is_cut_at_the_timeout(serve, monkeypatch):
    monkeypatch.setattr(api, "READY_TIMEOUT_SECONDS", 0.05)
    client = serve(database(hangs=True), chains({56: True}, []))
    started = time.monotonic()
    response = client.get("/api/ready")
    assert time.monotonic() - started < 2
    assert response.status_code == 503
    assert response.json()["checks"]["database"] == "failed"


def test_the_body_names_the_checks_and_nothing_else(serve):
    client = serve(database(error=RuntimeError(SECRET_URL)), chains({56: False}, []))
    body = client.get("/api/ready").json()
    assert set(body) == {"ready", "checks"}
    assert set(body["checks"].values()) <= {"ok", "failed", "open"}
    text = json.dumps(body)
    for leak in ("secret", "http", "key-123", "Error"):
        assert leak not in text


def test_the_answer_is_reused_for_the_cache_period(serve, monkeypatch):
    asked = []
    client = serve(database(), chains({56: True}, asked))
    assert client.get("/api/ready").status_code == 200
    assert client.get("/api/ready").status_code == 200
    assert asked == [56]

    monkeypatch.setattr(api, "READY_CACHE_SECONDS", 0)
    monkeypatch.setattr(api, "_ready_cache", {"body": None, "expires_at": 0.0})
    client.get("/api/ready")
    client.get("/api/ready")
    assert asked == [56, 56, 56]


@pytest.mark.asyncio
async def test_concurrent_requests_share_one_check(serve, monkeypatch):
    asked = []
    serve(database(), chains({56: True}, asked))
    monkeypatch.setattr(api, "_ready_lock", asyncio.Lock())
    responses = await asyncio.gather(*(api.ready() for _ in range(20)))
    assert {response.status_code for response in responses} == {200}
    assert asked == [56]


def test_open_breakers_are_reported_but_the_process_stays_ready(serve):
    for _ in range(FAILURE_THRESHOLD):
        provider_breakers.record_status("dexscreener", None, 503)
    provider_breakers.record_status("goplus_token", 56, 200)
    guard = RpcGuard("Robinhood Chain")
    for _ in range(BREAKER_FAILURE_THRESHOLD):
        guard.record_failure("HTTP 429")

    response = serve(database(), chains({56: True}, []), guard).get("/api/ready")
    assert response.status_code == 200
    assert response.json()["checks"] == {
        "database": "ok",
        "rpc": "ok",
        "robinhood_rpc": "open",
        "dexscreener": "open",
        "goplus_token:56": "ok",
    }


def test_without_a_container_it_is_not_ready(monkeypatch):
    monkeypatch.setattr(api, "_ready_cache", {"body": None, "expires_at": 0.0})
    monkeypatch.setattr(api, "container", None)
    response = TestClient(api.app).get("/api/ready")
    assert response.status_code == 503
    assert response.json() == {"ready": False, "checks": {"database": "failed", "rpc": "failed"}}


def test_polling_it_is_never_rate_limited(serve):
    client = serve(database(), chains({56: True}, []))
    statuses = {client.get("/api/ready").status_code for _ in range(40)}
    assert statuses == {200}
