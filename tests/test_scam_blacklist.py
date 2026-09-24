"""The local scam blacklist persists with its provenance: community entries expire after 30 days
unless an admin confirms them, admins can remove any entry, and a protected address never lists."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

import utils.scam_db as scam_module
from agent.hunter import Hunter
from core.database import Database
from utils.scam_db import COMMUNITY_BLACKLIST_TTL, ScamDatabase
from utils.web3_client import Web3Client


ADDRESS = "0x1111111111111111111111111111111111111111"
PROTECTED = next(iter(scam_module._PROTECTED_ADDRESSES))
GOPLUS_OK = {"status": "ok", "reason": None, "data": {"is_honeypot": "0", "is_open_source": "1"}}
COMMUNITY_MATCH = {
    "type": "community_reports",
    "reason": "Reported by 3 users",
    "source": "ShieldBot",
    "severity": "medium",
    "reports": 3,
}
ADMIN_MATCH = {
    "type": "Local Blacklist",
    "reason": "Confirmed scam address",
    "source": "ShieldBot",
    "severity": "block",
}


@pytest_asyncio.fixture
async def db_path(tmp_path):
    return (tmp_path / "blacklist.sqlite").as_posix()


async def _open(path):
    db = Database(path)
    await db.initialize()
    scam_db = ScamDatabase()
    scam_db.db = db
    await scam_db.load_blacklist()
    return db, scam_db


async def _lookup(scam_db, address=ADDRESS, chain_id=56):
    with patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock(return_value=GOPLUS_OK)):
        return await scam_db.check_address(address, chain_id=chain_id)


async def _report_three_times(scam_db, address=ADDRESS, chain_id=56):
    results = [
        await scam_db.report_address(address, f"user-{index}", chain_id) for index in range(3)
    ]
    return results[-1]


@pytest.mark.asyncio
async def test_community_entry_survives_a_restart(db_path):
    db, scam_db = await _open(db_path)
    result = await _report_three_times(scam_db)
    assert (result["accepted"], result["blacklisted"], result["reports"]) == (True, True, 3)
    assert result["already_listed"] is False
    assert await _lookup(scam_db) == [COMMUNITY_MATCH]
    await db.close()

    db, restarted = await _open(db_path)
    try:
        assert await _lookup(restarted) == [COMMUNITY_MATCH]
        [row] = await db.get_active_blacklist(time.time())
        assert (row["source"], row["chain_id"], row["reports"]) == ("community", 56, 3)
        assert row["expires_at"] == pytest.approx(row["created_at"] + COMMUNITY_BLACKLIST_TTL)
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_a_bsc_report_does_not_list_the_address_on_ethereum(db_path):
    db, scam_db = await _open(db_path)
    try:
        await _report_three_times(scam_db, chain_id=56)
        assert await _lookup(scam_db, chain_id=56) == [COMMUNITY_MATCH]
        assert await _lookup(scam_db, chain_id=1) == []
        # The BSC entry does not count as a listing on Ethereum: a report there starts its own count.
        other_chain = await scam_db.report_address(ADDRESS, "user-9", 1)
        assert (other_chain["blacklisted"], other_chain["reports"]) == (False, 1)
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_reporting_a_listed_address_leaves_its_expiry_and_count(db_path):
    db, scam_db = await _open(db_path)
    try:
        await _report_three_times(scam_db)
        [before] = await db.get_active_blacklist(time.time())
        with patch("utils.scam_db.time.time", return_value=time.time() + 86400):
            for index in range(3, 6):
                result = await scam_db.report_address(ADDRESS, f"user-{index}", 56)
                assert (result["blacklisted"], result["reports"]) == (True, 3)
        [after] = await db.get_active_blacklist(time.time())
        assert after == before
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_pending_reports_age_out_after_thirty_days(db_path):
    db, scam_db = await _open(db_path)
    try:
        start = time.time()
        with patch("utils.scam_db.time.time", return_value=start):
            await scam_db.report_address(ADDRESS, "user-0", 56)
            await scam_db.report_address(ADDRESS, "user-1", 56)
        with patch("utils.scam_db.time.time", return_value=start + COMMUNITY_BLACKLIST_TTL + 1):
            result = await scam_db.report_address(ADDRESS, "user-2", 56)
        assert (result["blacklisted"], result["reports"]) == (False, 1)
        assert await db.get_active_blacklist(0) == []
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_community_entry_expires_after_thirty_days_and_the_sweep_prunes_it(db_path):
    db, scam_db = await _open(db_path)
    try:
        await _report_three_times(scam_db)
        later = time.time() + COMMUNITY_BLACKLIST_TTL + 1
        with patch("utils.scam_db.time.time", return_value=later):
            assert await _lookup(scam_db) == []
            await scam_db.prune_blacklist()
        assert await db.get_active_blacklist(0) == []
        assert scam_db.known_scams == {}
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_prune_keeps_unexpired_and_admin_entries(db_path):
    db, scam_db = await _open(db_path)
    try:
        await _report_three_times(scam_db)
        assert await scam_db.confirm_scam("0x" + "22" * 20, 56, "drainer")
        await scam_db.prune_blacklist()
        assert len(await db.get_active_blacklist(time.time())) == 2
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_protected_address_is_never_blacklisted(db_path):
    db, scam_db = await _open(db_path)
    try:
        refused = [
            await scam_db.report_address(PROTECTED, f"user-{index}", 56) for index in range(3)
        ]
        assert not any(result["accepted"] for result in refused)
        await scam_db.add_to_blacklist(PROTECTED, 3, 56)
        assert await scam_db.confirm_scam(PROTECTED, None, "claimed scam") is False
        assert await db.get_active_blacklist(0) == []

        # An entry written straight into the table is still ignored.
        await db.confirm_blacklist(PROTECTED, None, "written by hand")
        await scam_db.load_blacklist()
        assert await _lookup(scam_db, PROTECTED) == []
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_admin_confirmation_makes_a_community_entry_a_permanent_full_match(db_path):
    db, scam_db = await _open(db_path)
    await _report_three_times(scam_db)
    assert await scam_db.confirm_scam(ADDRESS, 56, "reviewed")
    assert await _lookup(scam_db) == [ADMIN_MATCH]
    await db.close()

    db, restarted = await _open(db_path)
    try:
        with patch(
            "utils.scam_db.time.time", return_value=time.time() + 10 * COMMUNITY_BLACKLIST_TTL
        ):
            assert await _lookup(restarted) == [ADMIN_MATCH]
        [row] = await db.get_active_blacklist(time.time())
        assert (row["source"], row["expires_at"], row["reports"], row["reason"]) == (
            "admin",
            None,
            3,
            "reviewed",
        )
        # A later community threshold never downgrades a confirmed entry.
        await restarted.add_to_blacklist(ADDRESS, 3, 56)
        assert await _lookup(restarted) == [ADMIN_MATCH]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_admin_can_remove_an_entry(db_path):
    db, scam_db = await _open(db_path)
    try:
        await _report_three_times(scam_db)
        assert await scam_db.remove_from_blacklist(ADDRESS, 1) is False
        assert await scam_db.remove_from_blacklist(ADDRESS, 56) is True
        assert await _lookup(scam_db) == []
        assert await db.get_active_blacklist(0) == []
        assert await scam_db.remove_from_blacklist(ADDRESS, 56) is False
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_a_chain_scoped_entry_matches_only_its_chain(db_path):
    db, scam_db = await _open(db_path)
    try:
        assert await scam_db.confirm_scam(ADDRESS, 56, "drainer on BNB Chain")
        assert await _lookup(scam_db, chain_id=56) == [ADMIN_MATCH]
        assert await _lookup(scam_db, chain_id=1) == []
        # An every-chain admin entry covers chains that have no entry of their own, and outranks a
        # community entry on the same chain.
        await scam_db.add_to_blacklist(ADDRESS, 3, 1)
        assert await _lookup(scam_db, chain_id=1) == [COMMUNITY_MATCH]
        assert await scam_db.confirm_scam(ADDRESS, None, "drainer everywhere")
        assert await _lookup(scam_db, chain_id=1) == [ADMIN_MATCH]
        assert await _lookup(scam_db, chain_id=137) == [ADMIN_MATCH]
        assert await scam_db.remove_from_blacklist(ADDRESS, None) is True
        assert await _lookup(scam_db, chain_id=1) == [COMMUNITY_MATCH]
        assert await _lookup(scam_db, chain_id=137) == []
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_hunter_sweep_prunes_the_blacklist():
    scam_db = SimpleNamespace(prune_blacklist=AsyncMock())
    db = MagicMock(prune_old_chats=AsyncMock(), prune_retention=AsyncMock())
    hunter = Hunter(
        tools=MagicMock(), db=db, ai_analyzer=MagicMock(), sentinel=MagicMock(), scam_db=scam_db
    )
    hunter._check_watched_deployers = AsyncMock(return_value=[])
    hunter._recheck_warn_contracts = AsyncMock(return_value=[])
    hunter._scan_new_pairs = AsyncMock(return_value=[])
    await hunter.sweep()
    scam_db.prune_blacklist.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_startup_loads_the_blacklist_after_the_database_opens():
    from core.container import ServiceContainer

    order = []
    container = MagicMock()
    container.db.initialize = AsyncMock(side_effect=lambda: order.append("db"))
    container.scam_db.load_blacklist = AsyncMock(side_effect=lambda: order.append("blacklist"))
    container.indexer.start = AsyncMock()
    container.greenfield_service.async_init = AsyncMock()
    container.cache.connect = AsyncMock()
    await ServiceContainer.startup(container)
    assert order == ["db", "blacklist"]


ADMIN_HEADERS = {"x-admin-secret": "test-admin"}


@pytest.fixture
def admin_api(monkeypatch):
    import api

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {chain_id: MagicMock(chain_id=chain_id) for chain_id in (56, 1)}
    services = SimpleNamespace(
        settings=SimpleNamespace(admin_secret="test-admin", trusted_proxies=[]),
        auth_manager=None,
        db=SimpleNamespace(),
        scam_db=SimpleNamespace(
            confirm_scam=AsyncMock(return_value=True),
            remove_from_blacklist=AsyncMock(return_value=True),
        ),
        onchain_recorder=MagicMock(record_scan_fire_and_forget=AsyncMock()),
        base_attestor=MagicMock(attest_fire_and_forget=AsyncMock()),
    )
    services.onchain_recorder.is_available.return_value = True
    services.base_attestor.is_available.return_value = True
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    client = TestClient(api.app)
    yield api, client, services
    client.close()


def test_blacklist_admin_routes_are_hidden_from_the_schema(admin_api):
    api, _, _ = admin_api
    assert not [path for path in api.app.openapi()["paths"] if "blacklist" in path]


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/admin/blacklist"),
        ("DELETE", f"/api/admin/blacklist/{ADDRESS}"),
    ],
)
@pytest.mark.parametrize("headers", [{}, {"x-admin-secret": "wrong"}])
def test_blacklist_admin_routes_need_the_secret(admin_api, method, path, headers):
    _, client, services = admin_api
    response = client.request(
        method, path, headers=headers, json={"address": ADDRESS} if method == "POST" else None
    )
    assert response.status_code == 403
    services.scam_db.confirm_scam.assert_not_awaited()
    services.scam_db.remove_from_blacklist.assert_not_awaited()


def test_admin_confirms_an_entry(admin_api):
    _, client, services = admin_api
    response = client.post(
        "/api/admin/blacklist",
        headers=ADMIN_HEADERS,
        json={"address": ADDRESS, "chainId": 56, "reason": "drainer"},
    )
    assert response.status_code == 200
    services.scam_db.confirm_scam.assert_awaited_once_with(ADDRESS, 56, "drainer")


@pytest.mark.parametrize("confirmed", [True, False])
def test_an_admin_confirmation_writes_nothing_on_chain(admin_api, confirmed):
    # Only the bot sends from the recorder and attestor wallets, so the API never does.
    _, client, services = admin_api
    services.scam_db.confirm_scam.return_value = confirmed
    for chain_id in (56, 1):
        client.post(
            "/api/admin/blacklist", headers=ADMIN_HEADERS, json={"address": ADDRESS, "chainId": chain_id}
        )
    services.onchain_recorder.record_scan_fire_and_forget.assert_not_awaited()
    services.base_attestor.attest_fire_and_forget.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_report_of_a_listed_address_gives_its_count_and_whether_an_admin_confirmed_it(
    db_path,
):
    db, scam_db = await _open(db_path)
    try:
        await _report_three_times(scam_db)
        repeat = await scam_db.report_address(ADDRESS, "user-9", 56)
        assert (repeat["blacklisted"], repeat["reports"], repeat["confirmed"]) == (True, 3, False)
        assert repeat["already_listed"] is True
        other = "0x" + "22" * 20
        assert await scam_db.confirm_scam(other, None, "drainer")
        confirmed = await scam_db.report_address(other, "user-9", 56)
        assert (confirmed["blacklisted"], confirmed["reports"], confirmed["confirmed"]) == (
            True,
            0,
            True,
        )
    finally:
        await db.close()


def test_admin_confirmation_without_a_chain_covers_every_chain(admin_api):
    _, client, services = admin_api
    response = client.post("/api/admin/blacklist", headers=ADMIN_HEADERS, json={"address": ADDRESS})
    assert response.status_code == 200
    services.scam_db.confirm_scam.assert_awaited_once_with(ADDRESS, None, None)


def test_admin_confirmation_of_a_protected_address_is_refused(admin_api):
    _, client, services = admin_api
    services.scam_db.confirm_scam.return_value = False
    response = client.post(
        "/api/admin/blacklist", headers=ADMIN_HEADERS, json={"address": PROTECTED}
    )
    assert response.status_code == 409


def test_admin_confirmation_needs_a_valid_address(admin_api):
    _, client, services = admin_api
    response = client.post(
        "/api/admin/blacklist", headers=ADMIN_HEADERS, json={"address": "0x1234"}
    )
    assert response.status_code == 400
    services.scam_db.confirm_scam.assert_not_awaited()


def test_admin_removes_an_entry(admin_api):
    _, client, services = admin_api
    response = client.delete(
        f"/api/admin/blacklist/{ADDRESS}", headers=ADMIN_HEADERS, params={"chain_id": 56}
    )
    assert response.status_code == 200
    services.scam_db.remove_from_blacklist.assert_awaited_once_with(ADDRESS, 56)


@pytest.mark.asyncio
@pytest.mark.parametrize("headers, status", [({}, 403), ({"x-admin-secret": "test-admin"}, 400)])
async def test_the_remove_route_checks_the_secret_then_the_chain(admin_api, headers, status):
    api, _, services = admin_api
    with pytest.raises(api.HTTPException) as refused:
        await api.blacklist_remove(ADDRESS, SimpleNamespace(headers=headers), chain_id=999999)
    assert refused.value.status_code == status
    services.scam_db.remove_from_blacklist.assert_not_awaited()


@pytest.mark.asyncio
async def test_removal_is_logged_only_when_an_entry_was_removed(db_path, caplog):
    db, scam_db = await _open(db_path)
    try:
        with caplog.at_level("INFO", logger="utils.scam_db"):
            assert await scam_db.remove_from_blacklist(ADDRESS, 56) is False
        assert "Removed" not in caplog.text
        await _report_three_times(scam_db)
        with caplog.at_level("INFO", logger="utils.scam_db"):
            assert await scam_db.remove_from_blacklist(ADDRESS, 56) is True
        assert "Removed" in caplog.text
    finally:
        await db.close()


def test_removing_a_missing_entry_is_not_found(admin_api):
    _, client, services = admin_api
    services.scam_db.remove_from_blacklist.return_value = False
    response = client.delete(f"/api/admin/blacklist/{ADDRESS}", headers=ADMIN_HEADERS)
    assert response.status_code == 404
    services.scam_db.remove_from_blacklist.assert_awaited_once_with(ADDRESS, None)
