"""The operator alert: one Telegram Markdown message to TELEGRAM_ALERT_CHAT_ID, never raising."""

import logging
from types import SimpleNamespace

import aiohttp
import pytest

from core.telegram_alert import send_alert

TOKEN = "123456:synthetic-bot-token"
URL = f"https://api.telegram.org/bot{TOKEN}/sendMessage"


class Session:
    """aiohttp.ClientSession stand-in that records posts and answers with ``status``."""

    def __init__(self, status=200, error=None):
        self.status = status
        self.error = error
        self.posts = []
        self.timeouts = []

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def post(self, url, json, timeout):
        if self.error is not None:
            raise self.error
        self.posts.append((url, json))
        self.timeouts.append(timeout.total)
        return Response(self.status)


class Response:
    def __init__(self, status):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def settings(token=TOKEN, chat="42"):
    return SimpleNamespace(telegram_bot_token=token, telegram_alert_chat_id=chat)


@pytest.mark.asyncio
async def test_the_alert_is_posted_as_markdown_to_the_alert_chat(monkeypatch):
    session = Session()
    monkeypatch.setattr(aiohttp, "ClientSession", session)

    assert await send_alert(settings(), "*Discovery is behind*") is True
    assert session.posts == [
        (URL, {"chat_id": "42", "text": "*Discovery is behind*", "parse_mode": "Markdown"})
    ]
    # The timeout bounds how long the launch watch, which alerts under its lock, can wait.
    assert session.timeouts == [5]


@pytest.mark.asyncio
async def test_an_alert_telegram_refuses_is_not_reported_as_sent_and_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(aiohttp, "ClientSession", Session(status=400))

    with caplog.at_level(logging.WARNING, logger="core.telegram_alert"):
        assert await send_alert(settings(), "text") is False

    assert "Telegram alert refused: HTTP 400" in caplog.text
    assert TOKEN not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("token, chat", [("", "42"), (TOKEN, "")])
async def test_nothing_is_sent_without_a_bot_token_and_an_alert_chat(
    monkeypatch, caplog, token, chat
):
    session = Session()
    monkeypatch.setattr(aiohttp, "ClientSession", session)

    with caplog.at_level(logging.WARNING, logger="core.telegram_alert"):
        assert await send_alert(settings(token, chat), "text") is False

    assert session.posts == []
    assert "TELEGRAM_ALERT_CHAT_ID" in caplog.text


@pytest.mark.asyncio
async def test_a_failed_post_is_logged_by_class_only_so_the_token_stays_out_of_the_log(
    monkeypatch, caplog
):
    monkeypatch.setattr(aiohttp, "ClientSession", Session(error=aiohttp.ClientError(URL)))

    with caplog.at_level(logging.DEBUG, logger="core.telegram_alert"):
        assert await send_alert(settings(), "text") is False

    assert "ClientError" in caplog.text
    assert TOKEN not in caplog.text
