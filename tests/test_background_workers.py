"""BACKGROUND_WORKERS: background work in the API process (the default) or in workers.py.

With "external" the API starts none of it, and anything the API would have served from that work's memory
reads null with a note, never zero, empty or protected.
"""

import asyncio
import logging
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call

import httpx
import pydantic
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from core.config import Settings
from core.database import Database
from utils.scam_db import BLACKLIST_RELOAD_SECONDS, ScamDatabase
from utils.web3_client import Web3Client
from tests.test_lifespan import mock_container  # noqa: F401  (pytest fixture)

# What an idle mempool monitor and an idle launch watch report: zeros, empty lists and a full budget.
IDLE_MEMPOOL = {
    "total_pending_seen": 0,
    "sandwiches_detected": 0,
    "frontruns_detected": 0,
    "suspicious_approvals": 0,
    "counting_since": 1_790_000_000.0,
    "monitored_chains": [],
    "unobservable_chains": [],
    "pending_count": {},
    "active_alerts": 0,
}
IDLE_GUARD_WATCH = {
    "max_subjects": 25,
    "subjects": [],
    "due_count": 0,
    "running": False,
    "rpc_budget": {"state": "closed", "tokens": 4.0},
}


def test_api_is_the_default_and_an_unknown_value_stops_startup():
    assert Settings(_env_file=None).background_workers == "api"
    assert Settings(_env_file=None, background_workers="external").background_workers == "external"
    with pytest.raises(pydantic.ValidationError):
        Settings(_env_file=None, background_workers="both")


# ---------------------------------------------------------------------------
# The API lifespan
# ---------------------------------------------------------------------------


def test_external_starts_no_background_work_in_the_api(mock_container, monkeypatch):  # noqa: F811
    import api

    monkeypatch.setattr(api, "_background_workers", "api")
    mock_container.settings.background_workers = "external"
    with TestClient(api.app) as client:
        assert api._background_workers == "external"
        mock_container.startup.assert_awaited_once_with()
        mock_container.start_mempool_monitor.assert_not_awaited()
        mock_container.verdict_publisher.start.assert_not_called()
        mock_container.hunter.start.assert_not_awaited()
        mock_container.launch_watch.start.assert_not_awaited()
        # The routers still mount and the API still serves.
        assert client.get("/mcp/health").status_code == 200
    mock_container.shutdown.assert_awaited_once_with()


def test_api_setting_starts_the_background_work_as_before(mock_container, monkeypatch):  # noqa: F811
    import api

    monkeypatch.setattr(api, "_background_workers", "external")
    monkeypatch.setattr(api, "_blacklist_reload_task", None)
    with TestClient(api.app):
        assert api._background_workers == "api"
        mock_container.start_mempool_monitor.assert_awaited_once_with()
        mock_container.verdict_publisher.start.assert_called_once_with()
        mock_container.hunter.start.assert_awaited_once_with()
        mock_container.launch_watch.start.assert_awaited_once_with()
        # The hunter's sweep reloads the scam blacklist here, so the API runs no reload of its own.
        assert api._blacklist_reload_task is None


def test_external_api_reloads_the_blacklist_itself_and_stops_on_shutdown(
    mock_container, monkeypatch, tmp_path  # noqa: F811
):
    import api

    # The API reloads as often as the bot does, and as the hunter's sweep would.
    assert api.BLACKLIST_RELOAD_SECONDS == BLACKLIST_RELOAD_SECONDS == 1800
    path = (tmp_path / "shieldbot.db").as_posix()
    database = Database(path)
    scam_db = ScamDatabase()
    scam_db.db = database

    async def startup():
        await database.initialize()
        await scam_db.load_blacklist()

    mock_container.startup = AsyncMock(side_effect=startup)
    mock_container.shutdown = AsyncMock(side_effect=database.close)
    mock_container.scam_db = scam_db
    mock_container.settings.background_workers = "external"
    monkeypatch.setattr(api, "BLACKLIST_RELOAD_SECONDS", 0.05)
    monkeypatch.setattr(api, "_blacklist_reload_task", None)
    address = "0x" + "12" * 20

    with TestClient(api.app):
        task = api._blacklist_reload_task
        assert task is not None and not task.done()
        assert scam_db.known_scams == {}
        # Another process (the bot, or workers.py) writes an entry straight into the table.
        writer = sqlite3.connect(path)
        writer.execute(
            "INSERT INTO scam_blacklist (chain_id, address, source, reports, created_at, expires_at) "
            "VALUES (56, ?, 'community', 3, ?, ?)",
            (address, time.time(), time.time() + 3600),
        )
        writer.commit()
        writer.close()
        deadline = time.monotonic() + 5
        while (56, address) not in scam_db.known_scams and time.monotonic() < deadline:
            time.sleep(0.02)
        assert scam_db.known_scams[(56, address)]["source"] == "community"

    assert task.cancelled()


# ---------------------------------------------------------------------------
# Fields the API served from the background work's memory
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


@pytest_asyncio.fixture
async def external_api(monkeypatch, db):
    import api

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {
        chain_id: SimpleNamespace(
            chain_id=chain_id, chain_name=f"chain {chain_id}", capabilities=lambda: {}
        )
        for chain_id in (56, 4663)
    }
    monitor = MagicMock()
    monitor.get_stats.return_value = dict(IDLE_MEMPOOL)
    monitor.get_alerts.return_value = []
    services = SimpleNamespace(
        settings=SimpleNamespace(trusted_proxies=[], admin_secret="test-admin"),
        auth_manager=None,
        db=db,
        mempool_monitor=monitor,
        phishing_service=None,
        hunter=SimpleNamespace(guard_watch_stats=AsyncMock(return_value=dict(IDLE_GUARD_WATCH))),
        rescue_service=SimpleNamespace(approval_history=lambda chain_id: {"history": "full"}),
    )
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    monkeypatch.setattr(api, "_background_workers", "external")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as client:
        yield SimpleNamespace(client=client, monitor=monitor, api=api)


MEMPOOL_STATS_FIELDS = (
    "transactions_monitored",
    "sandwiches_caught",
    "suspicious_approvals",
    "chains_protected",
    "mempool_chains_observable",
    "mempool_chains_unobservable",
    "mempool_counting_since",
)


@pytest.mark.asyncio
async def test_public_stats_report_mempool_fields_as_null_with_a_note(external_api):
    body = (await external_api.client.get("/api/stats")).json()
    for field in MEMPOOL_STATS_FIELDS:
        assert body[field] is None, field
    assert "workers" in body["background_workers_note"]
    # Database-backed fields still come from the database.
    assert body["contracts_scanned"] == 0
    assert body["launch_discovery"]["chain_id"] == 4663
    external_api.monitor.get_stats.assert_not_called()


@pytest.mark.asyncio
async def test_default_stats_carry_no_note(external_api, monkeypatch):
    monkeypatch.setattr(external_api.api, "_background_workers", "api")
    body = (await external_api.client.get("/api/stats")).json()
    assert "background_workers_note" not in body
    assert body["transactions_monitored"] == 0
    assert body["chains_protected"] == 0


@pytest.mark.asyncio
async def test_admin_stats_null_the_mempool_and_the_watch_run_state(external_api):
    body = (
        await external_api.client.get("/api/admin/stats", headers={"X-Admin-Secret": "test-admin"})
    ).json()
    assert body["mempool"] is None
    assert body["guard_watch"]["running"] is None
    assert body["guard_watch"]["rpc_budget"] is None
    # The guard subjects come from the database and stay.
    assert body["guard_watch"]["subjects"] == []
    assert "workers" in body["background_workers_note"]
    external_api.monitor.get_stats.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/mempool/alerts", "/api/mempool/stats"])
async def test_mempool_routes_answer_unavailable_not_empty(external_api, path):
    response = await external_api.client.get(path)
    assert response.status_code == 503
    assert "workers" in response.json()["detail"]
    external_api.monitor.get_alerts.assert_not_called()
    external_api.monitor.get_stats.assert_not_called()


@pytest.mark.asyncio
async def test_threat_feed_says_mempool_alerts_are_not_here(external_api):
    body = (await external_api.client.get("/api/threats/feed")).json()
    assert "workers" in body["mempool_unavailable"]
    external_api.monitor.get_alerts.assert_not_called()
    contracts_only = (
        await external_api.client.get("/api/threats/feed", params={"source": "contracts"})
    ).json()
    assert "mempool_unavailable" not in contracts_only


@pytest.mark.asyncio
async def test_coverage_never_reads_the_idle_monitor_as_watching(external_api):
    body = (await external_api.client.get("/api/coverage/56")).json()
    assert body["capabilities"]["public_mempool"] == "unobservable"
    assert "workers" in body["background_workers_note"]
    external_api.monitor.get_stats.assert_not_called()


# ---------------------------------------------------------------------------
# workers.py
# ---------------------------------------------------------------------------


ROOT = Path(__file__).resolve().parent.parent


def _worker_container():
    container = MagicMock()
    for name in ("startup", "start_mempool_monitor", "shutdown"):
        setattr(container, name, AsyncMock())
    for name in ("hunter", "launch_watch"):
        getattr(container, name).start = AsyncMock()
        getattr(container, name).stop = AsyncMock()
    container.verdict_publisher.stop = AsyncMock()
    # The services' own task handles: none running unless a test starts one.
    for name in ("indexer", "mempool_monitor", "hunter", "launch_watch"):
        getattr(container, name)._task = None
    container.verdict_publisher._drain_task = None
    return container


LIFESPAN_ORDER = [
    call.startup(),
    call.start_mempool_monitor(),
    call.verdict_publisher.start(),
    call.hunter.start(),
    call.launch_watch.start(),
    call.launch_watch.stop(),
    call.hunter.stop(),
    call.verdict_publisher.stop(),
    call.shutdown(),
]


@pytest.mark.asyncio
async def test_workers_run_the_api_lifespans_background_work_in_its_order():
    import workers

    container = _worker_container()
    stop = asyncio.Event()
    running = asyncio.create_task(workers.run(container, stop))
    await asyncio.sleep(0)
    assert container.mock_calls == LIFESPAN_ORDER[:5]
    stop.set()
    assert await running == 0
    assert container.mock_calls == LIFESPAN_ORDER


@pytest.mark.asyncio
@pytest.mark.parametrize("service", ["indexer", "mempool_monitor", "verdict_publisher", "hunter", "launch_watch"])
async def test_workers_stop_and_exit_non_zero_when_background_work_ends_on_its_own(service, caplog):
    import workers

    container = _worker_container()
    running_forever = asyncio.Event()

    async def fails():
        raise RuntimeError("loop crashed")

    for name in ("indexer", "mempool_monitor", "hunter", "launch_watch"):
        getattr(container, name)._task = asyncio.create_task(running_forever.wait())
    container.verdict_publisher._drain_task = asyncio.create_task(running_forever.wait())
    ended = asyncio.create_task(fails())
    if service == "verdict_publisher":
        container.verdict_publisher._drain_task = ended
    else:
        getattr(container, service)._task = ended
    with caplog.at_level(logging.ERROR, logger="workers"):
        # The stop event is never set: the task that ended is what stops the workers.
        status = await asyncio.wait_for(workers.run(container, asyncio.Event()), 5)
    assert status == 1
    assert container.mock_calls == LIFESPAN_ORDER
    assert "RuntimeError" in caplog.text
    running_forever.set()


@pytest.mark.asyncio
async def test_a_service_whose_stop_fails_does_not_keep_the_others_running(caplog):
    import workers
    from agent.hunter import Hunter

    container = _worker_container()
    # A real hunter whose loop died with an error: its stop() raises that error again.
    hunter = Hunter(tools=MagicMock(), db=MagicMock(), ai_analyzer=MagicMock(), sentinel=MagicMock())

    async def sweep_crashes():
        raise RuntimeError("sweep crashed")

    hunter._task = asyncio.create_task(sweep_crashes())
    hunter.start = AsyncMock()
    container.hunter = hunter
    with caplog.at_level(logging.ERROR, logger="workers"):
        status = await asyncio.wait_for(workers.run(container, asyncio.Event()), 5)
    assert status == 1
    container.launch_watch.stop.assert_awaited_once_with()
    container.verdict_publisher.stop.assert_awaited_once_with()
    container.shutdown.assert_awaited_once_with()
    assert "stopping the hunter failed (RuntimeError)" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("setting", ["api", "both"])
async def test_workers_refuse_to_run_unless_the_setting_is_external(monkeypatch, caplog, setting):
    import workers

    built = MagicMock()
    monkeypatch.setattr(workers, "Settings", lambda: Settings(_env_file=None, background_workers=setting))
    monkeypatch.setattr(workers, "ServiceContainer", built)
    with caplog.at_level(logging.ERROR, logger="workers"):
        assert await workers.main() == workers.MISCONFIGURED == 3
    assert "background_workers" in caplog.text.lower()
    built.assert_not_called()


def test_the_entrypoint_exits_with_the_misconfiguration_status_systemd_does_not_restart(tmp_path):
    # Run from an empty directory with the setting unset, so no .env is read and nothing starts.
    environment = {
        name: value for name, value in os.environ.items() if name.upper() != "BACKGROUND_WORKERS"
    }
    environment["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [sys.executable, str(ROOT / "workers.py")],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert result.returncode == 3, result.stderr
    unit = (ROOT / "deploy" / "shieldbot-workers.service.example").read_text(encoding="utf-8")
    assert "RestartPreventExitStatus=3" in unit.splitlines()


@pytest.mark.asyncio
@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
async def test_workers_build_the_real_container_and_stop_cleanly_on_a_signal(
    monkeypatch, tmp_path, signum
):
    import workers
    from core.container import ServiceContainer

    settings = Settings(
        _env_file=None,
        background_workers="external",
        database_path=str(tmp_path / "workers.db"),
    )
    monkeypatch.setattr(workers, "Settings", lambda: settings)
    handlers = {}
    monkeypatch.setattr(
        workers.signal, "signal", lambda sig, handler: handlers.__setitem__(sig, handler)
    )
    ran = {}

    async def run(container, stop):
        ran["container"] = container
        await stop.wait()
        return 0

    monkeypatch.setattr(workers, "run", run)
    main = asyncio.create_task(workers.main())
    while "container" not in ran:
        await asyncio.sleep(0)
    assert isinstance(ran["container"], ServiceContainer)
    assert ran["container"].settings is settings
    assert set(handlers) == {signal.SIGTERM, signal.SIGINT}
    handlers[signum](signum, None)
    assert await asyncio.wait_for(main, timeout=5) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("service", ["hunter", "launch_watch"])
async def test_a_loop_that_never_started_does_not_log_that_it_stopped(service, caplog):
    from agent.hunter import Hunter
    from agent.launch_watch import LaunchWatch

    hunter = Hunter(tools=MagicMock(), db=MagicMock(), ai_analyzer=MagicMock(), sentinel=MagicMock())
    loop = hunter if service == "hunter" else LaunchWatch(hunter)
    with caplog.at_level(logging.INFO):
        await loop.stop()
    assert "stopped" not in caplog.text
