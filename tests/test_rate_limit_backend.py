"""RATE_LIMIT_BACKEND: rate limits in process memory (the default) or shared by every process through Redis."""

import asyncio
import logging
import math
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pydantic
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from core.auth import AuthManager
from core.config import Settings
from core.database import Database
from core.rate_limit import KEY_PREFIX, TIMEOUT_SECONDS, RateLimiter, connect
from tests.test_lifespan import mock_container  # noqa: F401  (pytest fixture)


def _bound(score: str):
    """A ZRANGEBYSCORE-style bound: -inf, +inf, a number, or "(" and a number for an exclusive one."""
    if score in ("-inf", "+inf"):
        return float(score), False
    if score.startswith("("):
        return float(score[1:]), True
    return float(score), False


def _within(value, low, high) -> bool:
    (low, low_open), (high, high_open) = _bound(str(low)), _bound(str(high))
    above = value > low if low_open else value >= low
    below = value < high if high_open else value <= high
    return above and below


class FakeRedis:
    """The commands the limiters send, with Redis's semantics, in one process.

    Every call yields to the event loop first, as a network round trip does, so concurrent checks interleave.
    A transaction's commands then apply together. With `down` set every call raises the ConnectionError a real
    client raises when Redis cannot be reached.
    """

    def __init__(self):
        self.zsets = {}
        self.ttls = {}
        self.down = False
        self.closed = False

    def pipeline(self, transaction=True):
        assert transaction, "a limiter check must be one MULTI/EXEC transaction"
        return FakePipeline(self)

    async def _round_trip(self):
        await asyncio.sleep(0)
        if self.down:
            raise RedisConnectionError("Error connecting to localhost:6379")

    async def zrem(self, key, *members):
        await self._round_trip()
        zset = self.zsets.get(key, {})
        return sum(zset.pop(member, None) is not None for member in members)

    async def zcard(self, key):
        await self._round_trip()
        return len(self.zsets.get(key, {}))

    async def ttl(self, key):
        await self._round_trip()
        return self.ttls[key] if key in self.zsets else -2

    async def keys(self, pattern="*"):
        await self._round_trip()
        assert pattern == "*"
        return [key for key, zset in self.zsets.items() if zset]

    async def ping(self):
        await self._round_trip()
        return True

    async def aclose(self):
        self.closed = True


class FakePipeline:
    def __init__(self, redis):
        self._redis = redis
        self._queued = []

    def __getattr__(self, command):
        def queue(*args, **kwargs):
            self._queued.append((command, args, kwargs))
            return self

        return queue

    async def execute(self):
        await self._redis._round_trip()
        results = [
            getattr(self, f"_{command}")(*args, **kwargs) for command, args, kwargs in self._queued
        ]
        self._queued = []
        return results

    def _zset(self, key):
        return self._redis.zsets.setdefault(key, {})

    def _zremrangebyscore(self, key, low, high):
        zset = self._zset(key)
        gone = [member for member, score in zset.items() if _within(score, low, high)]
        for member in gone:
            del zset[member]
        return len(gone)

    def _zadd(self, key, mapping):
        zset = self._zset(key)
        added = sum(member not in zset for member in mapping)
        zset.update(mapping)
        return added

    def _zcard(self, key):
        return len(self._zset(key))

    def _zcount(self, key, low, high):
        return sum(_within(score, low, high) for score in self._zset(key).values())

    def _zrange(self, key, start, end, withscores=False):
        assert (start, end, withscores) == (0, 0, True)
        ranked = sorted(self._zset(key).items(), key=lambda item: (item[1], item[0]))
        return [(member.encode(), score) for member, score in ranked[:1]]

    def _expire(self, key, seconds):
        self._redis.ttls[key] = seconds
        return True


@pytest_asyncio.fixture(params=["in-test fake", "fakeredis"])
async def redis(request):
    """The in-test fake, and, where fakeredis is installed (it is not a test dependency), a real ZSET implementation."""
    if request.param == "in-test fake":
        yield FakeRedis()
        return
    fakeredis = pytest.importorskip("fakeredis")
    client = fakeredis.FakeAsyncRedis()
    yield client
    await client.aclose()


@pytest.fixture
def clock(monkeypatch):
    """One clock for both backends: memory reads time.monotonic(), Redis reads time.time()."""
    clock = SimpleNamespace(now=1_000_000.0)
    monkeypatch.setattr(
        "core.rate_limit.time", SimpleNamespace(time=lambda: clock.now, monotonic=lambda: clock.now)
    )
    return clock


def _text(value) -> str:
    return value.decode() if isinstance(value, bytes) else value


# Offsets in seconds and what a 3 per minute, 2 per 5 seconds limiter answers at each.
SCRIPT = [
    (0.0, True),
    (1.0, True),
    (2.0, False),  # burst: two hits in the last 5 seconds
    (5.5, True),
    (6.0, False),  # three hits in the last minute
    (60.5, True),  # the hit at 0 has left the window
    (61.0, False),  # the hit at 1 is exactly 60 seconds old and still counts
    (61.5, True),
    (61.6, False),  # three hits in the last minute again
]


def test_memory_is_the_default_backend_and_an_unknown_one_stops_startup():
    assert Settings(_env_file=None).rate_limit_backend == "memory"
    assert Settings(_env_file=None, rate_limit_backend="redis").rate_limit_backend == "redis"
    with pytest.raises(pydantic.ValidationError):
        Settings(_env_file=None, rate_limit_backend="memcached")


@pytest.mark.asyncio
async def test_memory_limiter_answers_as_before(clock):
    limiter = RateLimiter(requests_per_minute=3, burst=2)
    start = clock.now
    answers = []
    for offset, _ in SCRIPT:
        clock.now = start + offset
        answers.append(await limiter.is_allowed("203.0.113.7"))
    assert answers == [allowed for _, allowed in SCRIPT]
    # Only allowed requests are kept, per caller.
    assert limiter._hits["203.0.113.7"] == [start + 5.5, start + 60.5, start + 61.5]
    assert await limiter.is_allowed("198.51.100.1") is True


@pytest.mark.asyncio
async def test_redis_limiter_answers_like_memory(redis, clock):
    limiter = RateLimiter(requests_per_minute=3, burst=2)
    limiter.use_redis(redis, "report", fail_open=False)
    start = clock.now
    answers = []
    for offset, _ in SCRIPT:
        clock.now = start + offset
        answers.append(await limiter.is_allowed("203.0.113.7"))
    assert answers == [allowed for _, allowed in SCRIPT]
    # Nothing is kept in process memory; Redis holds only the allowed hits still in the window.
    assert limiter._hits == {}
    key = f"{KEY_PREFIX}report:203.0.113.7"
    assert await redis.zcard(key) == 3


@pytest.mark.asyncio
async def test_every_process_shares_one_count_per_caller(redis, clock):
    # Two API processes: separate limiter objects, one Redis.
    first, second = (
        RateLimiter(requests_per_minute=3, burst=10),
        RateLimiter(requests_per_minute=3, burst=10),
    )
    first.use_redis(redis, "chat", fail_open=False)
    second.use_redis(redis, "chat", fail_open=False)
    assert [
        await first.is_allowed("ip"),
        await second.is_allowed("ip"),
        await first.is_allowed("ip"),
    ] == [True] * 3
    assert await second.is_allowed("ip") is False
    assert await first.is_allowed("another ip") is True


@pytest.mark.asyncio
async def test_keys_are_namespaced_per_limiter_and_all_expire(redis, clock):
    chat, signup = (
        RateLimiter(requests_per_minute=1, burst=1),
        RateLimiter(requests_per_minute=1, burst=1),
    )
    chat.use_redis(redis, "chat", fail_open=False)
    signup.use_redis(redis, "signup", fail_open=False)
    assert await chat.is_allowed("198.51.100.1") is True
    # The same caller has a separate count in another limiter.
    assert await signup.is_allowed("198.51.100.1") is True
    assert await chat.is_allowed("198.51.100.1") is False
    keys = sorted(_text(key) for key in await redis.keys("*"))
    assert keys == [f"{KEY_PREFIX}chat:198.51.100.1", f"{KEY_PREFIX}signup:198.51.100.1"]
    for key in keys:
        assert 0 < await redis.ttl(key) <= 60


@pytest.mark.asyncio
async def test_concurrent_checks_never_admit_more_than_the_limit(redis, clock):
    limiter = RateLimiter(requests_per_minute=3, burst=10)
    limiter.use_redis(redis, "requests", fail_open=True)
    answers = await asyncio.gather(*(limiter.is_allowed("ip") for _ in range(10)))
    assert sum(answers) == 3
    # The refused hits were taken back out, so they do not hold the caller back.
    assert await redis.zcard(f"{KEY_PREFIX}requests:ip") == 3


@pytest.mark.asyncio
async def test_redis_down_counts_a_fail_open_limiter_in_process_memory(clock, caplog):
    redis = FakeRedis()
    limiter = RateLimiter(requests_per_minute=2, burst=10)
    limiter.use_redis(redis, "requests", fail_open=True)
    assert await limiter.is_allowed("203.0.113.7") is True
    redis.down = True
    with caplog.at_level(logging.ERROR, logger="core.rate_limit"):
        answers = [await limiter.is_allowed("203.0.113.7") for _ in range(3)]
    # The memory window starts empty: the hit Redis holds is not in it.
    assert answers == [True, True, False]
    assert len(caplog.records) == 3
    for record in caplog.records:
        assert record.levelno == logging.ERROR
        assert "ConnectionError" in record.getMessage() and "memory" in record.getMessage()
    # Once Redis answers again it counts there, and memory is left alone.
    redis.down = False
    assert await limiter.is_allowed("203.0.113.7") is True
    assert await limiter.is_allowed("203.0.113.7") is False
    assert limiter._hits["203.0.113.7"] == [clock.now, clock.now]


@pytest.mark.asyncio
async def test_redis_down_refuses_every_request_of_a_fail_closed_limiter(clock, caplog):
    redis = FakeRedis()
    redis.down = True
    limiter = RateLimiter(requests_per_minute=30, burst=10)
    limiter.use_redis(redis, "report", fail_open=False)
    with caplog.at_level(logging.ERROR, logger="core.rate_limit"):
        assert [await limiter.is_allowed("203.0.113.7") for _ in range(3)] == [False] * 3
    assert limiter._hits == {}
    assert "ConnectionError" in caplog.records[0].getMessage()
    assert "refused" in caplog.records[0].getMessage()


@pytest.mark.asyncio
async def test_a_refused_hit_that_cannot_be_taken_back_is_logged_and_still_refused(clock, caplog):
    redis = FakeRedis()
    limiter = RateLimiter(requests_per_minute=1, burst=1)
    limiter.use_redis(redis, "requests", fail_open=True)
    assert await limiter.is_allowed("ip") is True
    real_zrem = redis.zrem

    async def zrem_fails(*args):
        redis.down = True
        return await real_zrem(*args)

    redis.zrem = zrem_fails
    with caplog.at_level(logging.ERROR, logger="core.rate_limit"):
        assert await limiter.is_allowed("ip") is False
    assert "could not take back" in caplog.text


def test_the_client_gives_up_on_a_hung_redis():
    client = connect("redis://localhost:6379/0")
    kwargs = client.connection_pool.connection_kwargs
    assert kwargs["socket_timeout"] == TIMEOUT_SECONDS
    assert kwargs["socket_connect_timeout"] == TIMEOUT_SECONDS


# ---------------------------------------------------------------------------
# API keys: the per-minute window moves to Redis; the daily quota stays in SQLite
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture
def auth_clock(monkeypatch):
    clock = SimpleNamespace(now=1_789_646_400.25)  # noon UTC
    monkeypatch.setattr("core.auth.time", SimpleNamespace(time=lambda: clock.now))
    return clock


async def _key(db, auth, rpm_limit, daily_limit=1000):
    created = await auth.create_key(owner="redis-test", tier="free")
    await db._db.execute(
        "UPDATE api_keys SET daily_limit = ?, rpm_limit = ? WHERE key_id = ?",
        (daily_limit, rpm_limit, created["key_id"]),
    )
    await db._db.commit()
    return await auth.validate_key(created["key"])


@pytest.mark.asyncio
async def test_api_key_minute_window_is_shared_through_redis(db, redis, auth_clock):
    first, second = AuthManager(db), AuthManager(db)
    first.use_redis(redis)
    second.use_redis(redis)
    info = await _key(db, first, rpm_limit=2)
    assert await first.check_rate_limit(dict(info)) is True
    auth_clock.now += 10
    assert await second.check_rate_limit(dict(info)) is True
    auth_clock.now += 5
    refused = dict(info)
    assert await second.check_rate_limit(refused) is False
    # The oldest hit in the window, 15 seconds ago, leaves it in 45 seconds.
    assert refused["quota"]["retry_after"] == 45
    assert refused["quota"]["used_today"] == 2
    assert first._minute_hits == second._minute_hits == {}
    key = f"{KEY_PREFIX}api-key:{info['key_id']}"
    assert await redis.zcard(key) == 2
    assert 0 < await redis.ttl(key) <= 60


@pytest.mark.asyncio
async def test_a_request_the_daily_quota_refuses_leaves_no_minute_hit(db, redis, auth_clock):
    auth = AuthManager(db)
    auth.use_redis(redis)
    info = await _key(db, auth, rpm_limit=5, daily_limit=1)
    assert await auth.check_rate_limit(dict(info)) is True
    refused = dict(info)
    assert await auth.check_rate_limit(refused) is False
    assert refused["quota"]["retry_after"] == math.ceil(1_789_689_600 - auth_clock.now)
    assert await redis.zcard(f"{KEY_PREFIX}api-key:{info['key_id']}") == 1


@pytest.mark.asyncio
async def test_redis_down_counts_the_api_key_minute_window_in_process_memory(db, auth_clock, caplog):
    redis = FakeRedis()
    redis.down = True
    auth = AuthManager(db)
    auth.use_redis(redis)
    info = await _key(db, auth, rpm_limit=1, daily_limit=10)
    with caplog.at_level(logging.ERROR, logger="core.auth"):
        assert await auth.check_rate_limit(dict(info)) is True
        auth_clock.now += 20
        refused = dict(info)
        assert await auth.check_rate_limit(refused) is False
    assert refused["quota"]["retry_after"] == 40
    assert refused["quota"]["used_today"] == 1
    assert "ConnectionError" in caplog.text and "memory" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", ["memory", "redis"])
async def test_a_hit_exactly_a_minute_old_leaves_the_api_key_window_in_both_backends(
    db, redis, auth_clock, backend
):
    auth = AuthManager(db)
    if backend == "redis":
        auth.use_redis(redis)
    info = await _key(db, auth, rpm_limit=1)
    assert await auth.check_rate_limit(dict(info)) is True
    auth_clock.now += 59.75
    assert await auth.check_rate_limit(dict(info)) is False
    auth_clock.now += 0.25
    assert await auth.check_rate_limit(dict(info)) is True


# ---------------------------------------------------------------------------
# The lifespan binds every limiter, with its policy for a Redis that cannot answer
# ---------------------------------------------------------------------------


LIMITERS = (
    "rate_limiter",
    "chat_limiter",
    "_report_limiter",
    "_signup_limiter",
    "_free_key_limiter",
    "_watch_alerts_limiter",
)


def _fresh_limiters(monkeypatch, api, rpc_limiter):
    import rpc.router

    for name in LIMITERS:
        monkeypatch.setattr(api, name, RateLimiter(requests_per_minute=1000, burst=1000))
    # The lifespan binds api's name for the RPC proxy's limiter; the route reads rpc.router's.
    monkeypatch.setattr(api, "rpc_limiter", rpc_limiter)
    monkeypatch.setattr(rpc.router, "rpc_limiter", rpc_limiter)


RPC_CALL = {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}


def test_redis_backend_binds_every_limiter_with_its_failure_policy(mock_container, monkeypatch, caplog):  # noqa: F811
    import api

    redis = FakeRedis()
    redis.down = True
    connect_calls = []
    monkeypatch.setattr(
        api, "connect_rate_limit_redis", lambda url: connect_calls.append(url) or redis
    )
    _fresh_limiters(monkeypatch, api, RateLimiter(requests_per_minute=1, burst=1))
    mock_container.settings.rate_limit_backend = "redis"
    mock_container.settings.redis_url = "redis://user:secret@cache.internal:6379/2"
    proxy = MagicMock()
    proxy.handle_request = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": "0x38"})
    proxy.close = AsyncMock()

    with caplog.at_level(logging.INFO), TestClient(api.app) as client:
        assert connect_calls == ["redis://user:secret@cache.internal:6379/2"]
        mock_container.auth_manager.use_redis.assert_called_once_with(redis)
        # PING failed at startup: the log says so and never claims the limits are kept in Redis.
        assert "did not answer PING" in caplog.text and "ConnectionError" in caplog.text
        assert "kept in Redis" not in caplog.text and "secret" not in caplog.text
        # The general request limiter counts in memory while Redis is down.
        assert client.get("/mcp/health").status_code == 200
        # So does the RPC proxy's, on its own route: its memory window here allows one call a minute.
        api.app.state.rpc_proxy = proxy
        assert client.post("/rpc/56", json=RPC_CALL).status_code == 200
        assert client.post("/rpc/56", json=RPC_CALL).status_code == 429
        proxy.handle_request.assert_awaited_once()
        # The abuse-sensitive limiters refuse.
        assert (
            client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"}).status_code
            == 429
        )
        assert (
            client.post("/api/agent/explain", json={"scan_result": {"risk_score": 10}}).status_code
            == 429
        )
        assert (
            client.post(
                "/api/report",
                json={"address": "0x" + "1" * 40, "report_type": "scam"},
            ).status_code
            == 429
        )
        assert client.post("/api/beta-signup", json={"email": "a@example.com"}).status_code == 429
        assert client.post("/api/keys/free", json={"email": "a@example.com"}).status_code == 429
        assert client.get("/api/watch/alerts").status_code == 429
    assert redis.closed


def test_redis_keys_name_each_limiter_and_caller_once(mock_container, monkeypatch, caplog):  # noqa: F811
    import api

    redis = FakeRedis()
    monkeypatch.setattr(api, "connect_rate_limit_redis", lambda url: redis)
    _fresh_limiters(monkeypatch, api, RateLimiter(requests_per_minute=1000, burst=1000))
    mock_container.settings.rate_limit_backend = "redis"
    mock_container.settings.redis_url = "redis://localhost:6379/0"

    with caplog.at_level(logging.INFO), TestClient(api.app, raise_server_exceptions=False) as client:
        assert "Rate limits kept in Redis" in caplog.text
        client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"})
        client.post("/api/report", json={"address": "0x" + "1" * 40, "report_type": "scam"})
        client.post("/api/beta-signup", json={"email": "a@example.com"})
        client.post("/api/keys/free", json={"email": "a@example.com"})
        client.get("/api/watch/alerts")
        keys = sorted(_text(key) for key in asyncio.run(redis.keys("*")))
    assert keys == sorted(
        f"{KEY_PREFIX}{name}:testclient"
        for name in ("requests", "chat", "report", "signup", "free-key", "watch-alerts")
    )


def test_memory_backend_creates_no_redis_client(mock_container, monkeypatch):  # noqa: F811
    import api

    monkeypatch.setattr(
        api, "connect_rate_limit_redis", MagicMock(side_effect=AssertionError("no Redis"))
    )
    with TestClient(api.app) as client:
        assert client.get("/mcp/health").status_code == 200
    mock_container.auth_manager.use_redis.assert_not_called()
