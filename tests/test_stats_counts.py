"""/api/stats reports the Robinhood Chain goals from the database alone: stored evidence documents
per chain, confirmed registry records and the last day's launch scan share."""

import time
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio

from core.database import Database
from utils.web3_client import Web3Client

TOKENS = ["0x" + f"{index:040x}" for index in range(1, 5)]


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


async def _evidence(db, chain_id, subject, onchain_status):
    evidence_id = await db.insert_verdict_evidence(
        chain_id=chain_id,
        subject=subject,
        verdict="UNKNOWN",
        evidence_hash="0x" + "11" * 32,
        canonical='{"verdict":"UNKNOWN"}',
        observed_block=1,
        onchain_status="pending" if chain_id == 4663 else "off",
        registry="0x" + "33" * 20 if chain_id == 4663 else None,
    )
    if onchain_status not in ("pending", "off"):
        await db.update_verdict_onchain(evidence_id, onchain_status)


def _launch(token, block, block_timestamp):
    return {
        "token_address": token,
        "source": "long",
        "launchpad": "LONG",
        "source_rank": 5,
        "pool_id": None,
        "block_number": block,
        "tx_hash": "0x" + f"{block:064x}",
        "block_timestamp": block_timestamp,
    }


@pytest.mark.asyncio
async def test_no_evidence_counts_nothing(db):
    assert await db.get_verdict_evidence_counts() == {}


@pytest.mark.asyncio
async def test_evidence_is_counted_per_chain_with_its_confirmed_records(db):
    await _evidence(db, 4663, TOKENS[0], "confirmed")
    await _evidence(db, 4663, TOKENS[0], "pending")
    await _evidence(db, 4663, TOKENS[1], "failed")
    await _evidence(db, 56, TOKENS[2], "off")

    assert await db.get_verdict_evidence_counts() == {
        4663: {"documents": 3, "confirmed": 1},
        56: {"documents": 1, "confirmed": 0},
    }


@pytest_asyncio.fixture
async def stats_api(monkeypatch, db):
    import api

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {chain_id: SimpleNamespace(chain_id=chain_id) for chain_id in (56, 4663)}
    services = SimpleNamespace(
        settings=SimpleNamespace(trusted_proxies=[], admin_secret=""),
        auth_manager=None,
        db=db,
        mempool_monitor=None,
        phishing_service=None,
    )
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_stats_report_evidence_and_registry_records(stats_api, db):
    await _evidence(db, 4663, TOKENS[0], "confirmed")
    await _evidence(db, 4663, TOKENS[1], "submitted")
    await _evidence(db, 56, TOKENS[2], "off")

    body = (await stats_api.get("/api/stats")).json()

    assert body["evidence_documents"] == {"4663": 2, "56": 1}
    assert body["registry_records_confirmed"] == 1


@pytest.mark.asyncio
async def test_only_confirmed_robinhood_chain_records_count_as_registry_records(stats_api, db):
    await _evidence(db, 4663, TOKENS[0], "confirmed")
    await _evidence(db, 56, TOKENS[1], "confirmed")

    body = (await stats_api.get("/api/stats")).json()

    assert body["registry_records_confirmed"] == 1


@pytest.mark.asyncio
async def test_stats_with_no_evidence_report_zero_records_not_null(stats_api):
    body = (await stats_api.get("/api/stats")).json()

    assert body["evidence_documents"] == {}
    assert body["registry_records_confirmed"] == 0


@pytest.mark.asyncio
async def test_stats_report_the_last_day_of_launches_and_how_many_were_scanned(stats_api, db):
    now = time.time()
    await db.upsert_discovered_launches(
        4663,
        [
            _launch(TOKENS[0], 100, now - 25 * 3600),
            _launch(TOKENS[1], 200, now - 3600),
            _launch(TOKENS[2], 201, now - 60),
        ],
    )
    await db.record_launch_scan(4663, TOKENS[2], "unknown", None)

    body = (await stats_api.get("/api/stats")).json()

    assert body["launch_discovery"]["scanned_share"] == {
        "window_hours": 24,
        "launches": 2,
        "scanned": 1,
    }
    assert body["launch_discovery"]["last_discovered_block"] == 201


@pytest.mark.asyncio
async def test_stats_without_a_database_report_the_goal_fields_as_unavailable(
    stats_api, monkeypatch
):
    import api

    monkeypatch.setattr(api.container, "db", None)
    body = (await stats_api.get("/api/stats")).json()

    assert body["evidence_documents"] is None
    assert body["registry_records_confirmed"] is None
    assert body["launch_discovery"] is None
    for key in ("contracts_scanned_24h", "threats_detected_24h", "transactions_blocked_24h"):
        assert body[key] is None, key


@pytest.mark.asyncio
async def test_stats_count_the_last_day_beside_all_time_from_the_same_tables(stats_api, db):
    await db.upsert_contract_score(TOKENS[0], 56, 90, "HIGH")
    await db.upsert_contract_score(TOKENS[1], 56, 20, "LOW")
    await db.upsert_contract_score(TOKENS[2], 56, 95, "HIGH")
    await db._db.execute(
        "UPDATE contract_scores SET last_scanned_at = ? WHERE address = ?", (time.time() - 2 * 86400, TOKENS[2])
    )
    await db._db.commit()
    await db.record_outcome(TOKENS[0], 56, 90, "block")

    body = (await stats_api.get("/api/stats")).json()

    assert (body["contracts_scanned"], body["threats_detected"], body["transactions_blocked"]) == (3, 2, 1)
    assert (body["contracts_scanned_24h"], body["threats_detected_24h"], body["transactions_blocked_24h"]) == (
        2,
        1,
        1,
    )
