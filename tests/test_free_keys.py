"""Self-serve free API keys: an emailed single-use link creates one free-tier key per address."""

import logging
import sys
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import pytest_asyncio

from core.auth import AuthManager, hash_key
from core.database import Database

EMAIL = "dev@example.com"


@pytest_asyncio.fixture
async def env(monkeypatch):
    import api

    db = Database(":memory:")
    await db.initialize()
    auth = AuthManager(db)
    send = AsyncMock(return_value={"id": "re_1"})
    notice = AsyncMock(return_value={"id": "re_n"})
    services = SimpleNamespace(
        db=db,
        auth_manager=auth,
        email_service=SimpleNamespace(
            is_enabled=lambda: True, send_free_key_verification=send, send_free_key_exists_notice=notice
        ),
        settings=SimpleNamespace(trusted_proxies=[], public_api_url="https://api.example"),
    )
    try:
        monkeypatch.setattr(api, "container", services)
        monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
        monkeypatch.setattr(api, "_free_key_limiter", api.RateLimiter(requests_per_minute=3, burst=2))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
        ) as client:
            yield SimpleNamespace(
                client=client, db=db, auth=auth, send=send, notice=notice, services=services
            )
    finally:
        await db.close()


async def _request(env, email=EMAIL):
    return await env.client.post("/api/keys/free", json={"email": email})


async def _verify(env, token):
    return await env.client.post("/api/keys/free/verify", json={"token": token})


def _sent_token(env):
    url = env.send.await_args.args[1]
    prefix = "https://api.example/api/keys/free/verify#token="
    assert url.startswith(prefix)
    return url[len(prefix) :]


@pytest.mark.asyncio
async def test_without_an_email_service_no_key_is_issued(env):
    env.services.email_service = SimpleNamespace(
        is_enabled=lambda: False, send_free_key_verification=env.send
    )
    response = await _request(env)
    assert response.status_code == 503
    assert response.json()["detail"] == "Self-serve keys are not enabled"
    env.send.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("email", ["not-an-email", "a@b", "two@@example.com"])
async def test_invalid_email_is_refused(env, email):
    response = await _request(env, email)
    assert response.status_code == 400
    env.send.assert_not_called()


@pytest.mark.asyncio
async def test_request_emails_a_link_and_stores_only_its_hash(env):
    response = await _request(env, " Dev@Example.com ")
    assert response.status_code == 200
    assert env.send.await_args.args[0] == EMAIL
    token = _sent_token(env)
    cursor = await env.db._db.execute("SELECT token_hash, email, expires_at FROM free_key_requests")
    rows = await cursor.fetchall()
    assert rows == [(hash_key(token), EMAIL, pytest.approx(time.time() + 1800, abs=5))]
    assert token not in str(rows)


@pytest.mark.asyncio
async def test_link_creates_one_free_key_shown_once(env):
    await _request(env)
    token = _sent_token(env)
    response = await _verify(env, token)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["key"].startswith("sb_")
    assert body["tier"] == "free"
    info = await env.auth.validate_key(body["key"])
    assert info["owner"] == EMAIL and info["tier"] == "free"
    cursor = await env.db._db.execute("SELECT key_hash FROM api_keys")
    assert await cursor.fetchall() == [(hash_key(body["key"]),)]

    again = await _verify(env, token)
    assert again.status_code == 400


@pytest.mark.asyncio
async def test_verify_page_carries_no_token(env):
    response = await env.client.get("/api/keys/free/verify")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "location.hash" in response.text
    assert "/api/keys/free/verify" in response.text


@pytest.mark.asyncio
async def test_expired_link_is_refused(env):
    token = "t" * 43
    assert await env.db.add_free_key_request(EMAIL, hash_key(token), time.time() - 1) is True
    response = await _verify(env, token)
    assert response.status_code == 400
    cursor = await env.db._db.execute("SELECT COUNT(*) FROM api_keys")
    assert (await cursor.fetchone())[0] == 0


@pytest.mark.asyncio
async def test_unknown_token_is_refused(env):
    assert (await _verify(env, "x" * 43)).status_code == 400
    assert (await _verify(env, "short")).status_code == 422


@pytest.mark.asyncio
async def test_link_host_ignores_a_trailing_slash(env):
    env.services.settings.public_api_url = "https://api.example/"
    await _request(env)
    assert env.send.await_args.args[1].startswith("https://api.example/api/keys/free/verify#token=")


@pytest.mark.asyncio
async def test_one_pending_link_per_address(env):
    first = await _request(env)
    second = await _request(env)
    assert second.status_code == 200
    assert second.json() == first.json()
    assert env.send.await_count == 1
    env.notice.assert_not_called()


@pytest.mark.asyncio
async def test_request_answers_the_same_whatever_the_address_state(env, monkeypatch):
    """New address, address with a pending link, address with a key: one answer, so no enumeration."""
    import api

    monkeypatch.setattr(api, "_free_key_limiter", api.RateLimiter(1000, 1000))
    await env.auth.create_key("keyed@example.com", "free")
    answers = [await _request(env, "new@example.com"), await _request(env, "new@example.com")]
    answers.append(await _request(env, "keyed@example.com"))
    assert {response.status_code for response in answers} == {200}
    assert len({response.text for response in answers}) == 1


@pytest.mark.asyncio
async def test_requests_are_limited_per_ip(env):
    assert (await _request(env, "a@example.com")).status_code == 200
    assert (await _request(env, "b@example.com")).status_code == 200
    assert (await _request(env, "c@example.com")).status_code == 429
    assert env.send.await_count == 2


@pytest.mark.asyncio
async def test_an_address_with_an_active_free_key_gets_no_second_one(env, monkeypatch):
    await _request(env)
    token = _sent_token(env)
    import api

    monkeypatch.setattr(api, "_free_key_limiter", api.RateLimiter(1000, 1000))
    await env.auth.create_key(EMAIL, "free")
    assert (await _verify(env, token)).status_code == 409
    assert (await _request(env)).status_code == 200
    env.notice.assert_awaited_once_with(EMAIL)
    assert env.send.await_count == 1
    cursor = await env.db._db.execute("SELECT COUNT(*) FROM api_keys WHERE owner = ?", (EMAIL,))
    assert (await cursor.fetchone())[0] == 1
    assert (await _request(env)).status_code == 200
    assert env.notice.await_count == 1


@pytest.mark.asyncio
async def test_a_deactivated_key_does_not_block_a_new_one(env):
    created = await env.auth.create_key(EMAIL, "free")
    await env.auth.deactivate_key(created["key_id"])
    await _request(env)
    assert (await _verify(env, _sent_token(env))).status_code == 200


@pytest.mark.asyncio
async def test_failed_send_is_reported_and_frees_the_address(env):
    env.send.return_value = None
    failed = await _request(env)
    assert failed.status_code == 503
    cursor = await env.db._db.execute("SELECT COUNT(*) FROM free_key_requests")
    assert (await cursor.fetchone())[0] == 0
    env.send.return_value = {"id": "re_2"}
    assert (await _request(env)).status_code == 200


@pytest.mark.asyncio
async def test_neither_token_nor_key_is_logged(env, caplog):
    caplog.set_level(logging.DEBUG)
    await _request(env)
    token = _sent_token(env)
    key = (await _verify(env, token)).json()["key"]
    assert token not in caplog.text
    assert key not in caplog.text


@pytest.mark.asyncio
async def test_email_service_sends_the_link_without_logging_it(monkeypatch, caplog):
    from services.email_service import EmailService

    resend = SimpleNamespace(
        api_key=None, Emails=SimpleNamespace(send=MagicMock(return_value={"id": "re_1"}))
    )
    monkeypatch.setitem(sys.modules, "resend", resend)
    caplog.set_level(logging.DEBUG)
    url = "https://api.example/api/keys/free/verify#token=abc<def"
    response = await EmailService(api_key="re_key").send_free_key_verification(EMAIL, url)
    assert response == {"id": "re_1"}
    params = resend.Emails.send.call_args.args[0]
    assert params["to"] == [EMAIL]
    assert "https://api.example/api/keys/free/verify#token=abc&lt;def" in params["html"]
    assert "abc<def" not in params["html"]
    assert "token=" not in caplog.text


@pytest.mark.asyncio
async def test_email_service_sends_the_key_exists_notice(monkeypatch):
    from services.email_service import EmailService

    resend = SimpleNamespace(
        api_key=None, Emails=SimpleNamespace(send=MagicMock(return_value={"id": "re_n"}))
    )
    monkeypatch.setitem(sys.modules, "resend", resend)
    assert await EmailService(api_key="re_key").send_free_key_exists_notice(EMAIL) == {"id": "re_n"}
    params = resend.Emails.send.call_args.args[0]
    assert params["to"] == [EMAIL]
    assert "already has an active free" in params["html"]
    assert "deactivate" in params["html"]


@pytest.mark.asyncio
async def test_email_service_failure_returns_none(monkeypatch):
    from services.email_service import EmailService

    resend = SimpleNamespace(
        api_key=None, Emails=SimpleNamespace(send=MagicMock(side_effect=RuntimeError("down")))
    )
    monkeypatch.setitem(sys.modules, "resend", resend)
    assert (
        await EmailService(api_key="re_key").send_free_key_verification(EMAIL, "https://x/#token=a")
        is None
    )
    assert (
        await EmailService(api_key="").send_free_key_verification(EMAIL, "https://x/#token=a")
        is None
    )
