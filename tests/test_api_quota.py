"""Durable daily API-key quotas, exactly-once metering and rate-limit headers."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from core.auth import AuthManager
from core.database import Database
from utils.web3_client import Web3Client

MIDNIGHT = 1789689600  # 2026-09-18 00:00:00 UTC
NOON = MIDNIGHT - 12 * 3600
RPC_BODY = {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
RATE_HEADERS = ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after")


@pytest.fixture
def clock(monkeypatch):
    clock = SimpleNamespace(now=NOON + 0.25)
    monkeypatch.setattr("core.auth.time", SimpleNamespace(time=lambda: clock.now))
    return clock


async def _create_key(db, auth, daily_limit=1000, rpm_limit=1000):
    created = await auth.create_key(owner="quota-test", tier="free")
    await db._db.execute(
        "UPDATE api_keys SET daily_limit = ?, rpm_limit = ? WHERE key_id = ?",
        (daily_limit, rpm_limit, created["key_id"]),
    )
    await db._db.commit()
    return created


async def _counted(db, key_id):
    cursor = await db._db.execute(
        "SELECT COALESCE(SUM(used), 0) FROM api_daily_usage WHERE key_id = ?", (key_id,)
    )
    return (await cursor.fetchone())[0]


async def _usage_rows(db, key_id):
    cursor = await db._db.execute("SELECT COUNT(*) FROM api_usage WHERE key_id = ?", (key_id,))
    return (await cursor.fetchone())[0]


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


class TestDurableDailyQuota:
    @pytest.mark.asyncio
    async def test_daily_count_survives_restart(self, tmp_path, clock):
        path = str(tmp_path / "quota.db")
        first = Database(path)
        await first.initialize()
        auth = AuthManager(first)
        created = await _create_key(first, auth, daily_limit=2)
        info = await auth.validate_key(created["key"])
        assert await auth.check_rate_limit(info) is True
        assert await auth.check_rate_limit(info) is True
        await first.close()

        restarted = Database(path)
        await restarted.initialize()
        try:
            auth = AuthManager(restarted)
            info = await auth.validate_key(created["key"])
            assert await auth.check_rate_limit(info) is False
            assert info["quota"]["used_today"] == 2
            assert info["quota"]["remaining"] == 0
            assert await _counted(restarted, created["key_id"]) == 2
        finally:
            await restarted.close()

    @pytest.mark.asyncio
    async def test_quota_resets_at_next_utc_midnight(self, db, clock):
        auth = AuthManager(db)
        created = await _create_key(db, auth, daily_limit=1)
        info = await auth.validate_key(created["key"])

        clock.now = MIDNIGHT - 0.5
        assert await auth.check_rate_limit(info) is True
        assert info["quota"]["resets_at"] == MIDNIGHT
        assert await auth.check_rate_limit(info) is False
        assert info["quota"]["retry_after"] == 1

        clock.now = MIDNIGHT
        assert await auth.check_rate_limit(info) is True
        assert info["quota"] == {
            "daily_limit": 1,
            "used_today": 1,
            "remaining": 0,
            "resets_at": MIDNIGHT + 86400,
            "retry_after": None,
        }

    @pytest.mark.asyncio
    async def test_allowed_requests_counted_once_and_refusals_not_counted(self, db, clock):
        auth = AuthManager(db)
        created = await _create_key(db, auth, daily_limit=2)
        info = await auth.validate_key(created["key"])
        assert [await auth.check_rate_limit(info) for _ in range(3)] == [True, True, False]
        assert await _counted(db, created["key_id"]) == 2
        assert info["quota"]["retry_after"] == MIDNIGHT - NOON

    @pytest.mark.asyncio
    async def test_minute_limit_refusal_is_not_counted_and_has_retry_after(self, db, clock):
        auth = AuthManager(db)
        created = await _create_key(db, auth, daily_limit=10, rpm_limit=1)
        info = await auth.validate_key(created["key"])
        assert await auth.check_rate_limit(info) is True
        clock.now += 20
        assert await auth.check_rate_limit(info) is False
        assert info["quota"]["used_today"] == 1
        assert info["quota"]["remaining"] == 9
        assert info["quota"]["retry_after"] == 40
        assert await _counted(db, created["key_id"]) == 1

    @pytest.mark.asyncio
    async def test_unavailable_quota_store_refuses_without_logging_error_text(
        self, db, clock, caplog
    ):
        auth = AuthManager(db)
        created = await _create_key(db, auth)
        info = await auth.validate_key(created["key"])
        await db._db.execute("DROP TABLE api_daily_usage")
        with caplog.at_level(logging.DEBUG):
            assert await auth.check_rate_limit(info) is False
        assert info["quota"]["used_today"] is None
        assert info["quota"]["remaining"] is None
        assert info["quota"]["retry_after"] == 60
        assert [r.getMessage() for r in caplog.records if r.name == "core.auth"] == [
            "API quota store unavailable: OperationalError"
        ]

    @pytest.mark.asyncio
    async def test_request_scope_counts_repeated_checks_of_a_key_once(self, db, clock):
        from core.auth import request_quota_scope

        auth = AuthManager(db)
        created = await _create_key(db, auth)
        with request_quota_scope():
            first = await auth.validate_key(created["key"])
            again = await auth.validate_key(created["key"])
            assert await auth.check_rate_limit(first) is True
            assert await auth.check_rate_limit(again) is True
            assert again["quota"] == first["quota"]
        assert await _counted(db, created["key_id"]) == 1
        assert await auth.check_rate_limit(await auth.validate_key(created["key"])) is True
        assert await _counted(db, created["key_id"]) == 2

    @pytest.mark.asyncio
    async def test_key_creation_survives_an_open_quota_count(self, db, clock):
        auth = AuthManager(db)
        created = await _create_key(db, auth)
        info = await auth.validate_key(created["key"])
        counting, resume = asyncio.Event(), asyncio.Event()
        used_on_day = auth._used_on_day

        async def paused(key_id, day):
            counting.set()
            await resume.wait()
            return await used_on_day(key_id, day)

        auth._used_on_day = paused
        check = asyncio.create_task(auth.check_rate_limit(info))
        await counting.wait()
        assert db._db.in_transaction

        admin_key = await auth.create_key(owner="admin", tier="pro")
        resume.set()
        assert await check is True
        assert (await auth.validate_key(admin_key["key"]))["tier"] == "pro"
        assert await _counted(db, created["key_id"]) == 1

    @pytest.mark.asyncio
    async def test_get_quota_reports_the_utc_day(self, db, clock):
        auth = AuthManager(db)
        created = await _create_key(db, auth, daily_limit=5)
        info = await auth.validate_key(created["key"])
        await auth.check_rate_limit(info)
        assert await auth.get_quota(info) == {
            "daily_limit": 5,
            "used_today": 1,
            "remaining": 4,
            "resets_at": MIDNIGHT,
        }
        clock.now = MIDNIGHT + 1
        assert (await auth.get_quota(info))["used_today"] == 0


@pytest_asyncio.fixture
async def metered_api(monkeypatch, db, clock):
    import api
    from agent.firewall import create_agent_firewall_router

    auth = AuthManager(db)
    created = await _create_key(db, auth)
    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {56: MagicMock(chain_id=56)}
    services = MagicMock()
    services.web3_client = registry
    services.settings = SimpleNamespace(trusted_proxies=[], admin_secret="")
    services.auth_manager = auth
    services.db = db
    services.mempool_monitor.get_alerts.return_value = []
    proxy = MagicMock(_container=services)
    proxy.handle_request = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0x38"})
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    monkeypatch.setattr(api.app.state, "rpc_proxy", proxy, raising=False)
    monkeypatch.setattr(api.app.router, "routes", list(api.app.router.routes))
    api.app.include_router(create_agent_firewall_router(services), prefix="/api/agent")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as client:
        yield SimpleNamespace(
            client=client,
            db=db,
            services=services,
            proxy=proxy,
            key=created["key"],
            key_id=created["key_id"],
        )


class TestApiMiddlewareMetering:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "method,path,kwargs,status",
        [
            ("GET", "/api/mempool/alerts", {}, 200),
            ("POST", "/rpc/56", {"json": RPC_BODY}, 200),
            ("GET", "/api/agent/policy", {"params": {"agent_id": "agent-1"}}, 404),
        ],
    )
    async def test_key_request_counted_exactly_once_with_headers(
        self, metered_api, method, path, kwargs, status
    ):
        response = await metered_api.client.request(
            method,
            path,
            headers={"x-api-key": metered_api.key},
            **kwargs,
        )
        assert response.status_code == status
        assert response.headers["x-ratelimit-limit"] == "1000"
        assert response.headers["x-ratelimit-remaining"] == "999"
        assert response.headers["x-ratelimit-reset"] == str(MIDNIGHT)
        assert "retry-after" not in response.headers
        assert await _counted(metered_api.db, metered_api.key_id) == 1
        assert await _usage_rows(metered_api.db, metered_api.key_id) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "method,path,kwargs",
        [
            ("GET", "/api/mempool/alerts", {}),
            ("POST", "/rpc/56", {"json": RPC_BODY}),
        ],
    )
    async def test_keyless_requests_have_no_rate_limit_headers(
        self, metered_api, method, path, kwargs
    ):
        response = await metered_api.client.request(method, path, **kwargs)
        assert response.status_code == 200
        assert not any(header in response.headers for header in RATE_HEADERS)
        assert await _counted(metered_api.db, metered_api.key_id) == 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", ["/api/mempool/alerts", "/rpc/56"])
    async def test_invalid_key_body_unchanged(self, metered_api, path):
        response = (
            await metered_api.client.post(
                path,
                json=RPC_BODY,
                headers={"x-api-key": "sb_" + "0" * 32},
            )
            if path == "/rpc/56"
            else await metered_api.client.get(path, headers={"x-api-key": "sb_" + "0" * 32})
        )
        assert response.status_code == 401
        assert response.content == b'{"detail":"Invalid API key"}'
        assert not any(header in response.headers for header in RATE_HEADERS)

    @pytest.mark.asyncio
    async def test_quota_429_body_unchanged_with_retry_after(self, metered_api):
        await metered_api.db._db.execute(
            "UPDATE api_keys SET daily_limit = 1 WHERE key_id = ?", (metered_api.key_id,)
        )
        await metered_api.db._db.commit()
        headers = {"x-api-key": metered_api.key}
        assert (
            await metered_api.client.get("/api/mempool/alerts", headers=headers)
        ).status_code == 200
        response = await metered_api.client.post("/rpc/56", json=RPC_BODY, headers=headers)
        assert response.status_code == 429
        assert response.content == b'{"detail":"API key rate limit exceeded"}'
        assert response.headers["retry-after"] == str(MIDNIGHT - NOON)
        assert response.headers["x-ratelimit-limit"] == "1"
        assert response.headers["x-ratelimit-remaining"] == "0"
        assert response.headers["x-ratelimit-reset"] == str(MIDNIGHT)
        metered_api.proxy.handle_request.assert_not_awaited()
        assert await _counted(metered_api.db, metered_api.key_id) == 1

    @pytest.mark.asyncio
    async def test_usage_reports_quota_and_keeps_existing_fields(self, metered_api):
        headers = {"x-api-key": metered_api.key}
        await metered_api.client.get("/api/mempool/alerts", headers=headers)
        response = await metered_api.client.get("/api/usage", headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert list(body) == ["key_id", "tier", "usage", "quota"]
        assert body["key_id"] == metered_api.key_id
        assert body["tier"] == "free"
        assert body["usage"] == {
            "total": 2,
            "by_endpoint": {"/api/mempool/alerts": 1, "/api/usage": 1},
            "days": 30,
        }
        assert body["quota"] == {
            "daily_limit": 1000,
            "used_today": 2,
            "remaining": 998,
            "resets_at": MIDNIGHT,
        }

    @pytest.mark.asyncio
    async def test_usage_write_failure_serves_request_and_quota_holds_after_restart(
        self, metered_api, caplog
    ):
        await metered_api.db._db.execute(
            "UPDATE api_keys SET daily_limit = 1 WHERE key_id = ?", (metered_api.key_id,)
        )
        await metered_api.db._db.commit()
        failing = metered_api.services.auth_manager
        failing.record_usage = AsyncMock(side_effect=RuntimeError("https://rpc.invalid/SECRET_KEY"))
        headers = {"x-api-key": metered_api.key}
        with caplog.at_level(logging.DEBUG):
            response = await metered_api.client.get("/api/mempool/alerts", headers=headers)
        assert response.status_code == 200
        assert "API usage record failed: RuntimeError" in caplog.text
        assert "SECRET_KEY" not in caplog.text

        metered_api.services.auth_manager = AuthManager(metered_api.db)
        response = await metered_api.client.get("/api/mempool/alerts", headers=headers)
        assert response.status_code == 429
        assert response.content == b'{"detail":"API key rate limit exceeded"}'

    @pytest.mark.asyncio
    async def test_unavailable_quota_store_fails_closed(self, metered_api, caplog):
        await metered_api.db._db.execute("DROP TABLE api_daily_usage")
        with caplog.at_level(logging.DEBUG):
            response = await metered_api.client.get(
                "/api/mempool/alerts",
                headers={"x-api-key": metered_api.key},
            )
        assert response.status_code == 429
        assert response.content == b'{"detail":"API key rate limit exceeded"}'
        assert response.headers["retry-after"] == "60"
        assert response.headers["x-ratelimit-limit"] == "1000"
        assert "x-ratelimit-remaining" not in response.headers
        assert "API quota store unavailable: OperationalError" in caplog.text
        assert await _usage_rows(metered_api.db, metered_api.key_id) == 0


@pytest_asyncio.fixture
async def standalone_rpc(db, clock):
    from rpc.router import rpc_router

    auth = AuthManager(db)
    created = await _create_key(db, auth, daily_limit=1)
    services = MagicMock()
    services.auth_manager = auth
    proxy = MagicMock(_container=services)
    proxy.handle_request = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0x38"})
    app = FastAPI()
    app.state.rpc_proxy = proxy
    app.include_router(rpc_router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        yield SimpleNamespace(
            client=client, db=db, auth=auth, key=created["key"], key_id=created["key_id"]
        )


class TestStandaloneRpcRouterMetering:
    @pytest.mark.asyncio
    async def test_invalid_key_json_rpc_body_unchanged(self, standalone_rpc):
        response = await standalone_rpc.client.post(
            "/rpc/56",
            json=RPC_BODY,
            headers={"x-api-key": "sb_" + "0" * 32},
        )
        assert response.status_code == 401
        assert response.content == (
            b'{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Invalid API key"}}'
        )

    @pytest.mark.asyncio
    async def test_quota_429_json_rpc_body_unchanged_with_retry_after(self, standalone_rpc):
        headers = {"x-api-key": standalone_rpc.key}
        assert (
            await standalone_rpc.client.post("/rpc/56", json=RPC_BODY, headers=headers)
        ).status_code == 200
        response = await standalone_rpc.client.post("/rpc/56", json=RPC_BODY, headers=headers)
        assert response.status_code == 429
        assert response.content == (
            b'{"jsonrpc":"2.0","id":null,"error":{"code":-32005,"message":"API key rate limit exceeded"}}'
        )
        assert response.headers["retry-after"] == str(MIDNIGHT - NOON)
        assert response.headers["x-ratelimit-remaining"] == "0"
        assert await _counted(standalone_rpc.db, standalone_rpc.key_id) == 1
        assert await _usage_rows(standalone_rpc.db, standalone_rpc.key_id) == 1

    @pytest.mark.asyncio
    async def test_usage_write_failure_serves_request_and_logs_class_only(
        self, standalone_rpc, caplog
    ):
        standalone_rpc.auth.record_usage = AsyncMock(
            side_effect=RuntimeError("https://rpc.invalid/SECRET_KEY")
        )
        with caplog.at_level(logging.DEBUG):
            response = await standalone_rpc.client.post(
                "/rpc/56",
                json=RPC_BODY,
                headers={"x-api-key": standalone_rpc.key},
            )
        assert response.status_code == 200
        assert "API usage record failed: RuntimeError" in caplog.text
        assert "SECRET_KEY" not in caplog.text
        assert await _counted(standalone_rpc.db, standalone_rpc.key_id) == 1
