"""Community reports never store a client IP: a keyed hash of it, or nothing."""

import hashlib
import hmac
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import api
from core.database import Database, reporter_hash

TOKEN = "0x" + "ab" * 20
HASHED = "0123456789abcdef0123456789abcdef"


def test_the_reporter_is_an_hmac_of_the_ip_under_the_secret():
    expected = hmac.new(b"secret", b"203.0.113.7", hashlib.sha256).hexdigest()[:32]
    assert reporter_hash("secret", "203.0.113.7") == expected
    assert len(expected) == 32
    assert reporter_hash("secret", "203.0.113.8") != expected
    assert reporter_hash("other", "203.0.113.7") != expected


def test_without_a_secret_no_reporter_is_stored():
    assert reporter_hash("", "203.0.113.7") is None


def stored_reporters(path):
    connection = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in connection.execute("SELECT reporter_id FROM community_reports ORDER BY id")
        ]
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_startup_clears_every_stored_ip_and_keeps_the_rest(tmp_path):
    path = tmp_path / "reports.db"
    db = Database(str(path))
    await db.initialize()
    for reporter in ("203.0.113.7", "2001:db8::1", "::ffff:192.0.2.1", "user_0", HASHED, None, ""):
        await db.record_community_report(address=TOKEN, report_type="scam", reporter_id=reporter)
    await db.close()

    for _ in range(2):
        db = Database(str(path))
        await db.initialize()
        await db.close()
        assert stored_reporters(path) == [None, None, None, "user_0", HASHED, None, ""]


@pytest.fixture
def client(monkeypatch):
    web3_client = MagicMock()
    web3_client.is_valid_address.return_value = True
    monkeypatch.setattr(api, "web3_client", web3_client)

    def serve(secret):
        db = SimpleNamespace(record_community_report=AsyncMock())
        monkeypatch.setattr(
            api,
            "container",
            SimpleNamespace(
                db=db,
                auth_manager=None,
                settings=SimpleNamespace(reporter_hash_secret=secret, trusted_proxies=[]),
            ),
        )
        return TestClient(api.app), db

    return serve


def report(client):
    return client.post(
        "/api/report",
        json={
            "address": TOKEN,
            "chainId": 56,
            "report_type": "false_positive",
            "reason": "a known token",
        },
    )


def test_a_report_stores_the_keyed_hash_of_the_client_ip(client):
    http, db = client("secret")
    assert report(http).status_code == 200
    # TestClient reports its client host as "testclient".
    stored = db.record_community_report.await_args.kwargs["reporter_id"]
    assert stored == reporter_hash("secret", "testclient")
    assert stored != "testclient"


def test_a_report_without_a_secret_stores_no_reporter(client):
    http, db = client("")
    assert report(http).status_code == 200
    assert db.record_community_report.await_args.kwargs["reporter_id"] is None
