"""Public Robinhood Chain launch feed: the shared query and GET /api/launches/{chain_id}."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import pytest_asyncio

from core.database import Database
from core.extension_formatter import is_scan_incomplete
from utils.web3_client import Web3Client


CHAIN = 4663
TOKENS = ["0x" + f"{index:040x}" for index in range(1, 7)]
REASON = "v2 pool 0x1c99: sell reverted; Unknown fields: sell_tax"
HONEYPOT_EVIDENCE = {
    "rug_probability": 80,
    "risk_level": "HIGH",
    "risk_archetype": "honeypot",
    "critical_flags": [
        "Honeypot detected",
        "Cannot sell token",
        f"Honeypot coverage unknown: {REASON}",
    ],
    "coverage": {"structural": 1.0, "honeypot": 0.8},
    "coverage_reasons": {"honeypot": REASON},
    "status": "unknown",
}


def _launch(token, block, source="long", launchpad="LONG", pool_id=None):
    return {
        "token_address": token,
        "source": source,
        "launchpad": launchpad,
        "source_rank": 5,
        "pool_id": pool_id,
        "block_number": block,
        "tx_hash": "0x" + f"{block:064x}",
        "block_timestamp": 1_758_000_000 + block,
    }


async def _scan(db, token, status, score, at, chain_id=CHAIN):
    await db.record_launch_scan(chain_id, token, status, score)
    await db._db.execute(
        "UPDATE discovered_launches SET scanned_at = ? WHERE chain_id = ? AND token_address = ?",
        (at, chain_id, token),
    )
    await db._db.commit()


async def _recheck(db, token, status, at):
    await db.upsert_tracked_pair(token, token_address=token, chain_id=CHAIN)
    await db._db.execute(
        "UPDATE tracked_pairs SET status = ?, last_checked = ? WHERE pair_address = ?",
        (status, at, token),
    )
    await db._db.commit()


async def _finding(db, token, score, evidence, at):
    await db.insert_agent_finding(
        finding_type="hunter_sweep",
        address=token,
        chain_id=CHAIN,
        risk_score=score,
        evidence=evidence,
        action_taken="blocked",
    )
    await db._db.execute(
        "UPDATE agent_findings SET created_at = ? WHERE id = (SELECT MAX(id) FROM agent_findings)",
        (at,),
    )
    await db._db.commit()


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "feed.db"))
    await database.initialize()
    yield database
    await database.close()


async def _by_token(db, **kwargs):
    items, _ = await db.get_launch_feed(CHAIN, 50, **kwargs)
    return {item["token_address"]: item for item in items}


# --- shared query ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_feed_is_newest_first_and_pages_with_a_cursor(db):
    await db.upsert_discovered_launches(
        CHAIN, [_launch(token, 100 + index) for index, token in enumerate(TOKENS[:5])]
    )

    first, cursor = await db.get_launch_feed(CHAIN, 2)
    second, cursor2 = await db.get_launch_feed(CHAIN, 2, cursor=cursor)
    third, cursor3 = await db.get_launch_feed(CHAIN, 2, cursor=cursor2)

    assert [item["block_number"] for item in first] == [104, 103]
    assert cursor == f"103:{TOKENS[3]}"
    assert [item["block_number"] for item in second] == [102, 101]
    assert [item["block_number"] for item in third] == [100]
    assert cursor3 is None


@pytest.mark.asyncio
async def test_cursor_breaks_ties_within_a_block_by_token(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(token, 100) for token in TOKENS[:3]])

    first, cursor = await db.get_launch_feed(CHAIN, 2)
    rest, _ = await db.get_launch_feed(CHAIN, 2, cursor=cursor)

    assert [item["token_address"] for item in first + rest] == TOKENS[2::-1]


@pytest.mark.asyncio
async def test_feed_excludes_other_chains(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])
    await db.upsert_discovered_launches(56, [_launch(TOKENS[1], 200)])

    items, _ = await db.get_launch_feed(CHAIN, 50)

    assert [item["token_address"] for item in items] == [TOKENS[0]]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cursor", ["", "abc", "100", "x:" + TOKENS[0], "100:0xabc", f"100:{TOKENS[0]}:1"]
)
async def test_malformed_cursor_is_rejected(db, cursor):
    with pytest.raises(ValueError, match="Invalid cursor"):
        await db.get_launch_feed(CHAIN, 10, cursor=cursor)


@pytest.mark.asyncio
async def test_unscanned_item_has_the_full_shape_and_is_never_safe(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100, pool_id="0x" + "ab" * 32)])
    await db._db.execute("UPDATE discovered_launches SET discovered_at = 1758000500.5")
    await db._db.commit()

    items, _ = await db.get_launch_feed(CHAIN, 50)

    assert items == [
        {
            "chain_id": CHAIN,
            "token_address": TOKENS[0],
            "launchpad": "LONG",
            "source": "long",
            "pool_id": "0x" + "ab" * 32,
            "tx_hash": "0x" + f"{100:064x}",
            "block_number": 100,
            "block_timestamp": 1_758_000_100,
            "discovered_at": 1758000500.5,
            "scan": {
                "outcome": "not_scanned",
                "status": "unknown",
                "risk_level": None,
                "risk_score": None,
                "coverage": None,
                "coverage_reasons": {"scan": "Not scanned yet"},
                "flags": [],
                "scanned_at": None,
            },
            "impostor_check": None,
            "verdict_url": f"/api/verdict/{CHAIN}/{TOKENS[0]}",
        }
    ]
    assert is_scan_incomplete(items[0]["scan"])


@pytest.mark.asyncio
async def test_blocked_item_takes_detail_from_the_hunter_evidence(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])
    await _scan(db, TOKENS[0], "blocked", 80, at=1000.0)
    await _finding(db, TOKENS[0], 80, HONEYPOT_EVIDENCE, at=1000.0)

    scan = (await _by_token(db))[TOKENS[0]]["scan"]

    assert scan == {
        "outcome": "blocked",
        "status": "unknown",
        "risk_level": "HIGH",
        "risk_score": 80,
        "coverage": {"structural": 1.0, "honeypot": 0.8},
        "coverage_reasons": {"honeypot": REASON},
        "flags": HONEYPOT_EVIDENCE["critical_flags"],
        "scanned_at": 1000.0,
    }


@pytest.mark.asyncio
async def test_complete_blocked_evidence_is_ok(db):
    evidence = {
        **HONEYPOT_EVIDENCE,
        "status": "ok",
        "coverage": {"structural": 1, "honeypot": 1},
        "coverage_reasons": {},
    }
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])
    await _scan(db, TOKENS[0], "blocked", 85, at=1000.0)
    await _finding(db, TOKENS[0], 85, evidence, at=1000.0)

    scan = (await _by_token(db))[TOKENS[0]]["scan"]

    assert (scan["outcome"], scan["status"], scan["coverage_reasons"]) == ("blocked", "ok", {})
    assert scan["coverage"] == {"structural": 1, "honeypot": 1}
    assert not is_scan_incomplete(scan)


@pytest.mark.asyncio
async def test_blocked_without_evidence_is_not_presented_as_complete(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])
    await _scan(db, TOKENS[0], "blocked", 90, at=1000.0)

    scan = (await _by_token(db))[TOKENS[0]]["scan"]

    assert scan["outcome"] == "blocked"
    assert scan["risk_score"] == 90
    assert scan["status"] == "unknown"
    assert scan["risk_level"] is None
    assert scan["coverage_reasons"] == {"scan": "Coverage details were not recorded for this scan"}


@pytest.mark.asyncio
async def test_evidence_from_another_chain_is_ignored(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])
    await _scan(db, TOKENS[0], "blocked", 90, at=1000.0)
    await db.insert_agent_finding(
        finding_type="hunter_sweep",
        address=TOKENS[0],
        chain_id=56,
        risk_score=95,
        evidence={**HONEYPOT_EVIDENCE, "status": "ok"},
        action_taken="blocked",
    )

    scan = (await _by_token(db))[TOKENS[0]]["scan"]

    assert scan["status"] == "unknown" and scan["risk_level"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stored,reason",
    [
        ("unknown", "Scan incomplete; coverage details were not recorded"),
        ("error", "Scan failed before completing"),
        ("something_new", "Scan incomplete; coverage details were not recorded"),
    ],
)
async def test_incomplete_outcomes_are_unknown_without_a_score(db, stored, reason):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])
    await _scan(db, TOKENS[0], stored, 12, at=1000.0)

    scan = (await _by_token(db))[TOKENS[0]]["scan"]

    assert scan == {
        "outcome": "unknown",
        "status": "unknown",
        "risk_level": None,
        "risk_score": None,
        "coverage": None,
        "coverage_reasons": {"scan": reason},
        "flags": [],
        "scanned_at": 1000.0,
    }
    assert is_scan_incomplete(scan)


@pytest.mark.asyncio
@pytest.mark.parametrize("stored,score", [("cleared", 12), ("watching", 45)])
async def test_complete_outcomes_keep_their_score(db, stored, score):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])
    await _scan(db, TOKENS[0], stored, score, at=1000.0)

    scan = (await _by_token(db))[TOKENS[0]]["scan"]

    assert scan == {
        "outcome": stored,
        "status": "ok",
        "risk_level": None,
        "risk_score": score,
        "coverage": None,
        "coverage_reasons": {},
        "flags": [],
        "scanned_at": 1000.0,
    }


@pytest.mark.asyncio
async def test_a_cleared_launch_as_a_consumer_sees_it(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])
    await _scan(db, TOKENS[0], "cleared", 12, at=1000.0)

    scan = (await _by_token(db))[TOKENS[0]]["scan"]

    # scan.status is the authoritative field: "ok" only for a complete scan.
    assert (scan["outcome"], scan["status"], scan["coverage_reasons"]) == ("cleared", "ok", {})
    # The hunter records per-field coverage only with a blocked launch's evidence, so a
    # field-level check of this item cannot confirm it and stays on the safe side.
    assert scan["coverage"] is None
    assert is_scan_incomplete(scan)


@pytest.mark.asyncio
async def test_recheck_upgrade_to_blocked_is_the_latest_outcome(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])
    await _scan(db, TOKENS[0], "unknown", 20, at=1000.0)
    await _recheck(db, TOKENS[0], "blocked", at=2000.0)
    await _finding(db, TOKENS[0], 82, HONEYPOT_EVIDENCE, at=2000.0)

    scan = (await _by_token(db))[TOKENS[0]]["scan"]

    assert (scan["outcome"], scan["risk_score"], scan["risk_level"], scan["scanned_at"]) == (
        "blocked",
        82,
        "HIGH",
        2000.0,
    )
    assert scan["coverage_reasons"] == {"honeypot": REASON}


@pytest.mark.asyncio
async def test_recheck_clear_is_the_latest_outcome(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])
    await _scan(db, TOKENS[0], "watching", 40, at=1000.0)
    await _recheck(db, TOKENS[0], "cleared", at=2000.0)

    scan = (await _by_token(db))[TOKENS[0]]["scan"]

    assert (scan["outcome"], scan["status"], scan["risk_score"], scan["scanned_at"]) == (
        "cleared",
        "ok",
        None,
        2000.0,
    )


@pytest.mark.asyncio
async def test_watching_or_stale_tracked_pairs_do_not_override_the_scan(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100), _launch(TOKENS[1], 101)])
    await _scan(db, TOKENS[0], "unknown", None, at=1000.0)
    await _recheck(db, TOKENS[0], "watching", at=2000.0)
    await _scan(db, TOKENS[1], "unknown", None, at=3000.0)
    await _recheck(db, TOKENS[1], "cleared", at=2000.0)

    items = await _by_token(db)

    assert items[TOKENS[0]]["scan"]["outcome"] == "unknown"
    assert items[TOKENS[1]]["scan"]["outcome"] == "unknown"
    assert items[TOKENS[1]]["scan"]["scanned_at"] == 3000.0


@pytest.mark.asyncio
async def test_discovery_status_is_empty_before_discovery_has_run(db):
    assert await db.get_launch_discovery_status(CHAIN) == {
        "cursor": None,
        "last_sweep_at": None,
        "last_discovered_block": None,
    }


@pytest.mark.asyncio
async def test_discovery_status_reports_the_lowest_cursor_last_sweep_and_newest_launch(db):
    await db.set_launch_cursor(CHAIN, "long", 900)
    await db.set_launch_cursor(CHAIN, "uniswap_v4", 700)
    await db.set_launch_cursor(56, "long", 5_000)
    await db._db.execute(
        "UPDATE launch_discovery_cursors SET updated_at = CASE source WHEN 'long' THEN 2000.0 "
        "ELSE 1000.0 END WHERE chain_id = ?",
        (CHAIN,),
    )
    await db._db.commit()
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 650), _launch(TOKENS[1], 880)])
    await db.upsert_discovered_launches(56, [_launch(TOKENS[2], 4_900)])

    assert await db.get_launch_discovery_status(CHAIN) == {
        "cursor": 700,
        "last_sweep_at": 2000.0,
        "last_discovered_block": 880,
    }


@pytest.mark.asyncio
async def test_scan_share_counts_launches_since_a_block_time_and_those_scanned(db):
    since = 1_758_000_000 + 200
    await db.upsert_discovered_launches(
        CHAIN, [_launch(token, 190 + 10 * index) for index, token in enumerate(TOKENS[:5])]
    )
    await db.upsert_discovered_launches(56, [_launch(TOKENS[5], 300)])
    await _scan(db, TOKENS[0], "cleared", 10, at=1000.0)
    await _scan(db, TOKENS[2], "unknown", None, at=1001.0)
    await _scan(db, TOKENS[3], "error", None, at=1002.0)

    # Blocks 200 to 230 are in the window; block 190 is older and chain 56 is another chain.
    assert await db.get_launch_scan_share(CHAIN, since) == {"launches": 4, "scanned": 2}


# --- HTTP endpoint --------------------------------------------------------------------------


@pytest_asyncio.fixture
async def feed_api(monkeypatch, db):
    import api

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {chain_id: MagicMock(chain_id=chain_id) for chain_id in (56, 4663)}
    services = MagicMock()
    services.web3_client = registry
    services.settings = SimpleNamespace(trusted_proxies=[], admin_secret="")
    services.db = db
    services.mempool_monitor.get_alerts.return_value = []
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as client:
        yield SimpleNamespace(api=api, client=client, db=db, services=services)


@pytest.mark.asyncio
async def test_endpoint_shape_and_pagination(feed_api):
    db = feed_api.db
    await db.upsert_discovered_launches(
        CHAIN, [_launch(token, 100 + index) for index, token in enumerate(TOKENS[:3])]
    )
    await _scan(db, TOKENS[2], "blocked", 80, at=1000.0)
    await _finding(db, TOKENS[2], 80, HONEYPOT_EVIDENCE, at=1000.0)
    await _scan(db, TOKENS[1], "unknown", 30, at=1001.0)

    first = await feed_api.client.get(f"/api/launches/{CHAIN}", params={"limit": 2})
    body = first.json()
    second = await feed_api.client.get(
        f"/api/launches/{CHAIN}", params={"limit": 2, "cursor": body["next_cursor"]}
    )

    assert first.status_code == second.status_code == 200
    assert set(body) == {"launches", "count", "chain_id", "next_cursor", "scanned_share"}
    assert body["chain_id"] == CHAIN and body["count"] == 2
    assert [item["scan"]["outcome"] for item in body["launches"]] == ["blocked", "unknown"]
    assert body["launches"][0]["verdict_url"] == f"/api/verdict/{CHAIN}/{TOKENS[2]}"
    assert second.json() == {
        "launches": [(await db.get_launch_feed(CHAIN, 50))[0][2]],
        "count": 1,
        "chain_id": CHAIN,
        "next_cursor": None,
        "scanned_share": body["scanned_share"],
    }
    assert second.json()["launches"][0]["scan"]["outcome"] == "not_scanned"


@pytest.mark.asyncio
async def test_endpoint_says_how_many_launches_of_the_last_day_were_scanned(feed_api):
    db = feed_api.db
    now = int(time.time())
    recent = [
        dict(_launch(token, 100 + index), block_timestamp=now - 60)
        for index, token in enumerate(TOKENS[:3])
    ]
    old = dict(_launch(TOKENS[3], 90), block_timestamp=now - 2 * 86400)
    await db.upsert_discovered_launches(CHAIN, recent + [old])
    await _scan(db, TOKENS[0], "unknown", None, at=1000.0)
    await _scan(db, TOKENS[3], "cleared", 5, at=1001.0)

    response = await feed_api.client.get(f"/api/launches/{CHAIN}", params={"limit": 1})

    assert response.json()["scanned_share"] == {"window_hours": 24, "launches": 3, "scanned": 1}


@pytest.mark.asyncio
async def test_endpoint_never_renders_incomplete_items_as_complete(feed_api):
    db = feed_api.db
    await db.upsert_discovered_launches(
        CHAIN, [_launch(token, 100 + index) for index, token in enumerate(TOKENS[:5])]
    )
    await _scan(db, TOKENS[0], "blocked", 80, at=1000.0)
    await _finding(db, TOKENS[0], 80, HONEYPOT_EVIDENCE, at=1000.0)
    await _scan(db, TOKENS[1], "unknown", 5, at=1000.0)
    await _scan(db, TOKENS[2], "error", None, at=1000.0)
    await _scan(db, TOKENS[3], "cleared", 5, at=1000.0)

    items = {
        item["token_address"]: item["scan"]
        for item in (await feed_api.client.get(f"/api/launches/{CHAIN}")).json()["launches"]
    }

    for token in (TOKENS[0], TOKENS[1], TOKENS[2], TOKENS[4]):
        assert items[token]["status"] == "unknown"
        assert is_scan_incomplete(items[token])
    assert [items[token]["outcome"] for token in TOKENS[:5]] == [
        "blocked",
        "unknown",
        "unknown",
        "cleared",
        "not_scanned",
    ]
    assert items[TOKENS[3]]["status"] == "ok"


@pytest.mark.asyncio
@pytest.mark.parametrize("requested,expected", [(1000, 200), (0, 1), (-5, 1), (7, 7)])
async def test_endpoint_bounds_the_page_size(feed_api, requested, expected):
    feed_api.services.db = MagicMock(
        get_launch_feed=AsyncMock(return_value=([], None)),
        get_launch_scan_share=AsyncMock(return_value={"launches": 0, "scanned": 0}),
    )

    response = await feed_api.client.get(f"/api/launches/{CHAIN}", params={"limit": requested})

    assert response.status_code == 200
    feed_api.services.db.get_launch_feed.assert_awaited_once_with(CHAIN, expected, None)


@pytest.mark.asyncio
async def test_endpoint_rejects_an_unsupported_chain_before_the_database(feed_api):
    feed_api.services.db = MagicMock(get_launch_feed=AsyncMock())

    response = await feed_api.client.get("/api/launches/999999")

    assert response.status_code == 400
    assert "Supported chain IDs" in response.json()["detail"]
    feed_api.services.db.get_launch_feed.assert_not_awaited()


@pytest.mark.asyncio
async def test_endpoint_rejects_a_non_integer_chain(feed_api):
    response = await feed_api.client.get("/api/launches/robinhood")

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_supported_chain_without_discovery_says_so(feed_api):
    feed_api.services.db = MagicMock(get_launch_feed=AsyncMock())

    response = await feed_api.client.get("/api/launches/56")

    assert response.status_code == 200
    assert response.json() == {
        "launches": [],
        "count": 0,
        "chain_id": 56,
        "next_cursor": None,
        "discovery_unavailable": "Launch discovery is not available on this chain",
    }
    feed_api.services.db.get_launch_feed.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("cursor", ["nope", "9" * 19 + ":" + TOKENS[0], "1" + "0" * 40 + ":" + TOKENS[0]])
async def test_endpoint_rejects_a_malformed_cursor(feed_api, cursor):
    response = await feed_api.client.get(f"/api/launches/{CHAIN}", params={"cursor": cursor})

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid cursor"}


@pytest.mark.asyncio
async def test_the_largest_accepted_cursor_block_is_a_valid_query(db):
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[0], 100)])

    items, _ = await db.get_launch_feed(CHAIN, 10, cursor="9" * 18 + ":" + TOKENS[1])

    assert [item["token_address"] for item in items] == [TOKENS[0]]


@pytest.mark.asyncio
async def test_endpoint_is_unavailable_without_services(feed_api, monkeypatch):
    monkeypatch.setattr(feed_api.api, "container", None)

    response = await feed_api.client.get(f"/api/launches/{CHAIN}")

    assert response.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [f"/api/launches/{CHAIN}", f"/api/threats/feed?chain_id={CHAIN}"])
async def test_endpoint_is_rate_limited_like_the_threat_feed(feed_api, monkeypatch, path):
    monkeypatch.setattr(
        feed_api.api, "rate_limiter", feed_api.api.RateLimiter(requests_per_minute=2, burst=10)
    )
    feed_api.services.db = MagicMock(
        get_launch_feed=AsyncMock(return_value=([], None)),
        get_launch_scan_share=AsyncMock(return_value={"launches": 0, "scanned": 0}),
    )
    feed_api.services.db._db.execute = AsyncMock(
        return_value=SimpleNamespace(fetchall=AsyncMock(return_value=[]))
    )

    statuses = [(await feed_api.client.get(path)).status_code for _ in range(3)]
    limited = await feed_api.client.get(path)

    assert statuses == [200, 200, 429]
    assert limited.json() == {"detail": "Too many requests. Please wait before trying again."}
