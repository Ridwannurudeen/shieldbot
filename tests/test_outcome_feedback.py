"""POST /api/outcome stays open, but every row says who sent it and no score reads the rows."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import aiosqlite
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from core.database import Database
from utils.web3_client import Web3Client


ADDRESS = "0x" + "a" * 40
TX_HASH = "0x" + "b" * 64


@pytest.fixture
def outcome_api(monkeypatch):
    import api

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {chain_id: MagicMock(chain_id=chain_id) for chain_id in (56, 1)}
    services = MagicMock()
    services.web3_client = registry
    services.settings = SimpleNamespace(trusted_proxies=[])
    services.auth_manager.validate_key = AsyncMock(return_value={"key_id": "sb_partner"})
    services.auth_manager.check_rate_limit = AsyncMock(return_value=True)
    services.auth_manager.record_usage = AsyncMock()
    services.db.record_outcome = AsyncMock()
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    monkeypatch.setattr(api, "_outcome_limiter", api.RateLimiter(1000, 1000))
    client = TestClient(api.app, raise_server_exceptions=False)
    yield api, client, services
    client.close()


def test_unauthenticated_outcome_is_recorded_as_client(outcome_api):
    _, client, services = outcome_api
    response = client.post(
        "/api/outcome",
        json={
            "address": ADDRESS,
            "user_decision": "block",
            "outcome": "scam",
            "tx_hash": TX_HASH,
        },
    )
    assert response.status_code == 200
    kwargs = services.db.record_outcome.await_args.kwargs
    assert kwargs["source"] == "client"
    assert (kwargs["user_decision"], kwargs["outcome"], kwargs["tx_hash"]) == (
        "block",
        "scam",
        TX_HASH,
    )


def test_outcome_with_a_valid_api_key_is_recorded_under_the_key(outcome_api):
    _, client, services = outcome_api
    response = client.post(
        "/api/outcome",
        json={"address": ADDRESS, "user_decision": "proceed", "outcome": "safe"},
        headers={"x-api-key": "sb_secret"},
    )
    assert response.status_code == 200
    assert services.db.record_outcome.await_args.kwargs["source"] == "key:sb_partner"


def test_outcome_with_an_invalid_api_key_is_refused(outcome_api):
    _, client, services = outcome_api
    services.auth_manager.validate_key = AsyncMock(return_value=None)
    response = client.post(
        "/api/outcome",
        json={"address": ADDRESS, "user_decision": "block"},
        headers={"x-api-key": "forged"},
    )
    assert response.status_code == 401
    services.db.record_outcome.assert_not_awaited()


@pytest.mark.parametrize(
    "field,value",
    [
        ("address", "0x1234"),
        ("address", "not-an-address"),
        ("user_decision", "approve"),
        ("user_decision", "BLOCK"),
        ("outcome", "rugged"),
        ("tx_hash", "0xtxhash123"),
        ("tx_hash", "0x" + "g" * 64),
        ("risk_score_at_scan", 101),
        ("risk_score_at_scan", -1),
    ],
)
def test_malformed_outcome_fields_are_refused(outcome_api, field, value):
    _, client, services = outcome_api
    body = {"address": ADDRESS, "user_decision": "block", field: value}
    response = client.post("/api/outcome", json=body)
    assert response.status_code in (400, 422)
    services.db.record_outcome.assert_not_awaited()


def test_non_finite_score_is_refused(outcome_api):
    _, client, services = outcome_api
    response = client.post(
        "/api/outcome",
        content='{"address": "%s", "user_decision": "block", "risk_score_at_scan": NaN}' % ADDRESS,
        headers={"content-type": "application/json"},
    )
    # Refused by the model's range check. The 422 body would echo the NaN, which the JSON response
    # cannot encode, so the client sees a 500 (true of every float field in this API).
    assert response.status_code != 200
    services.db.record_outcome.assert_not_awaited()


def test_unauthenticated_outcomes_are_rate_limited_per_ip(outcome_api, monkeypatch):
    api, client, services = outcome_api
    monkeypatch.setattr(api, "_outcome_limiter", api.RateLimiter(requests_per_minute=2, burst=2))
    statuses = [
        client.post("/api/outcome", json={"address": ADDRESS, "user_decision": "block"}).status_code
        for _ in range(3)
    ]
    assert statuses == [200, 200, 429]
    assert services.db.record_outcome.await_count == 2


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


@pytest.mark.asyncio
async def test_outcome_source_is_stored(db):
    await db.record_outcome(
        address=ADDRESS, user_decision="block", outcome="scam", source="key:sb_partner"
    )
    await db.record_outcome(address=ADDRESS, user_decision="block", outcome="scam")
    sources = sorted(row["source"] for row in await db.get_outcomes(ADDRESS))
    assert sources == ["client", "key:sb_partner"]


@pytest.mark.asyncio
async def test_outcomes_stored_before_the_source_column_count_as_client(tmp_path):
    path = (tmp_path / "legacy.sqlite").as_posix()
    async with aiosqlite.connect(path) as legacy:
        await legacy.executescript("""
            CREATE TABLE outcome_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                chain_id INTEGER NOT NULL DEFAULT 56,
                risk_score_at_scan REAL,
                user_decision TEXT,
                outcome TEXT,
                tx_hash TEXT,
                created_at REAL NOT NULL
            );
            INSERT INTO outcome_events (address, user_decision, outcome, created_at)
            VALUES ('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'block', 'scam', 1);
        """)
        await legacy.commit()
    database = Database(path)
    await database.initialize()
    await database.close()
    database = Database(path)
    await database.initialize()
    try:
        assert [row["source"] for row in await database.get_outcomes(ADDRESS)] == ["client"]
    finally:
        await database.close()


def test_no_scoring_code_reads_outcome_events():
    # The rows come from anyone, so nothing that computes a score may read them; scripts/calibrate.py
    # reads the API key rows into a proposal the owner applies by hand.
    root = Path(__file__).resolve().parent.parent
    readers = sorted(
        path.relative_to(root).as_posix()
        for folder in ("core", "analyzers", "services", "scanner", "utils", "agent", "adapters", "mcp_server", "rpc")
        for path in (root / folder).rglob("*.py")
        if "outcome_events" in path.read_text(encoding="utf-8")
    )
    assert readers == ["core/database.py"]

