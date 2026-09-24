"""A stored risk level always matches its stored score, and the threat counts count what the threat
feed lists."""

import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from core.database import Database
from core.verdicts import stored_level
from utils.scam_db import ScamDatabase

TOKENS = ["0x" + f"{index:040x}" for index in range(1, 7)]


@pytest.mark.parametrize(
    "score, level, expected",
    [
        (85, "MEDIUM", "HIGH"),
        (85, "LOW", "HIGH"),
        (85, "UNKNOWN", "HIGH"),
        (40, "LOW", "MEDIUM"),
        # A level is never lowered: an incomplete scan's MEDIUM keeps it whatever the score.
        (10, "MEDIUM", "MEDIUM"),
        (60, "HIGH", "HIGH"),
        (40, "UNKNOWN", "UNKNOWN"),
        (10, "LOW", "LOW"),
    ],
)
def test_stored_level_raises_to_the_band_of_the_score_and_never_lowers(score, level, expected):
    assert stored_level(score, level) == expected


@pytest.fixture
def firewall_api(monkeypatch, mock_web3_client):
    import api

    mock_web3_client.is_token_contract = AsyncMock(return_value=True)
    db = SimpleNamespace(
        get_contract_score=AsyncMock(return_value=None),
        get_deployer_risk_summary=AsyncMock(return_value=None),
        upsert_contract_score=AsyncMock(),
    )
    services = SimpleNamespace(
        web3_client=mock_web3_client,
        db=db,
        registry=SimpleNamespace(run_all=AsyncMock(return_value=[])),
        policy_engine=None,
        indexer=None,
        counterparty_service=None,
    )
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", mock_web3_client)
    monkeypatch.setattr(api, "scam_db", ScamDatabase())
    monkeypatch.setattr(
        api,
        "calldata_decoder",
        SimpleNamespace(
            decode=lambda _: {"selector": None},
            is_whitelisted_target=lambda *args, **kwargs: None,
        ),
    )
    monkeypatch.setattr(api, "risk_engine", MagicMock())
    monkeypatch.setattr(api, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    monkeypatch.setattr(api, "greenfield_service", None)
    monkeypatch.setattr(api, "ai_analyzer", SimpleNamespace(is_available=lambda: False))
    return api, services


@pytest.mark.asyncio
async def test_campaign_boost_stores_the_level_of_the_boosted_score(firewall_api, monkeypatch):
    api, services = firewall_api
    api.risk_engine.compute_from_results.return_value = {
        "rug_probability": 60,
        "risk_level": "MEDIUM",
        "status": "ok",
        "coverage": {"honeypot": 1},
        "coverage_reasons": {},
    }
    monkeypatch.setattr(
        api,
        "_get_deployer_campaign_context",
        AsyncMock(
            return_value={
                "risk_boost": 25,
                "danger_signal": "Deployer has 4 HIGH RISK contracts on record (serial scammer pattern)",
            }
        ),
    )
    services.threat_graph = SimpleNamespace(enrich_from_scan=AsyncMock())

    response = await api.firewall(
        api.FirewallRequest(to="0x" + "a" * 40, sender="0x" + "b" * 40),
        SimpleNamespace(headers={}),
    )

    assert (response["risk_score"], response["classification"]) == (85, "BLOCK_RECOMMENDED")
    stored = services.db.upsert_contract_score.await_args.kwargs
    assert (stored["risk_score"], stored["risk_level"]) == (85, "HIGH")
    assert response["shield_score"]["risk_level"] == "HIGH"
    enriched = services.threat_graph.enrich_from_scan.call_args.args[2]
    assert (enriched["rug_probability"], enriched["risk_level"]) == (85, "HIGH")


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


@pytest.mark.asyncio
async def test_threat_counts_count_what_the_threat_feed_lists(db, monkeypatch):
    import api

    # The last row is one written before the level followed the score: a boosted score with the
    # engine's unboosted level.
    for token, score, level in zip(
        TOKENS, (90, 72, 60, 40, 10, 75), ("HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW", "MEDIUM")
    ):
        await db.upsert_contract_score(
            address=token, chain_id=56, risk_score=score, risk_level=level
        )
    monkeypatch.setattr(api, "container", SimpleNamespace(db=db, mempool_monitor=None))

    stats = await db.get_platform_stats()
    feed = await api.threat_feed(source="contracts")

    listed = sorted(threat["address"] for threat in feed["threats"])
    assert stats["all_time"]["threats_detected"] == len(listed)
    assert stats["last_24h"]["threats_detected"] == len(listed)
    assert listed == sorted(TOKENS[:2])


@pytest.mark.asyncio
async def test_startup_raises_old_rows_to_the_level_of_their_score(tmp_path):
    path = tmp_path / "scores.db"
    rows = [
        (85, "MEDIUM"),
        (75, "UNKNOWN"),
        (40, "LOW"),
        (10, "MEDIUM"),
        (40, "UNKNOWN"),
        (95, "HIGH"),
    ]
    db = Database(str(path))
    await db.initialize()
    for token, (score, level) in zip(TOKENS, rows):
        await db.upsert_contract_score(
            address=token, chain_id=56, risk_score=score, risk_level=level
        )
    await db.close()

    for _ in range(2):
        db = Database(str(path))
        await db.initialize()
        await db.close()
        connection = sqlite3.connect(path)
        try:
            levels = [
                row[0]
                for row in connection.execute(
                    "SELECT risk_level FROM contract_scores ORDER BY address"
                )
            ]
        finally:
            connection.close()
        assert levels == ["HIGH", "HIGH", "MEDIUM", "MEDIUM", "UNKNOWN", "HIGH"]
