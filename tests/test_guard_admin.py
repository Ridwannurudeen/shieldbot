"""Authenticated guard watch management and scheduler observability."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from utils.web3_client import Web3Client


# Lowercase: web3 6.15.1 (the pinned version) rejects mixed-case addresses that fail the
# EIP-55 checksum, while web3 7.x accepts them. Lowercase is valid under both.
ADDRESS = "0x" + "ab" * 20
SUBJECT_PATH = f"/api/admin/guard-subjects/4663/{ADDRESS}"
ADMIN_HEADERS = {"x-admin-secret": "test-admin"}


@pytest.fixture
def guard_admin(monkeypatch):
    import api

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {4663: SimpleNamespace(chain_id=4663)}
    services = SimpleNamespace(
        settings=SimpleNamespace(admin_secret="test-admin", trusted_proxies=[]),
        auth_manager=None,
        db=SimpleNamespace(
            get_platform_stats=AsyncMock(return_value={"all_time": {}}),
            register_guard_subject=AsyncMock(return_value=True),
            unregister_guard_subject=AsyncMock(),
        ),
        hunter=SimpleNamespace(guard_watch_stats=AsyncMock(return_value={
            "max_subjects": 3,
            "refresh_interval_seconds": 300,
            "subjects": [{"subject": ADDRESS.lower(), "measurement_age_seconds": None}],
            "rpc_budget": {"saturated": True},
        })),
        mempool_monitor=None,
        phishing_service=None,
    )
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    client = TestClient(api.app)
    yield client, services
    client.close()


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/admin/stats"), ("POST", SUBJECT_PATH), ("DELETE", SUBJECT_PATH),
])
@pytest.mark.parametrize("headers", [{}, {"x-admin-secret": "wrong"}])
def test_guard_watch_requires_admin_before_access(guard_admin, method, path, headers):
    client, services = guard_admin
    response = client.request(method, path, headers=headers)
    assert response.status_code == 403
    services.db.get_platform_stats.assert_not_awaited()
    services.hunter.guard_watch_stats.assert_not_awaited()
    services.db.register_guard_subject.assert_not_awaited()
    services.db.unregister_guard_subject.assert_not_awaited()


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/admin/stats"), ("POST", SUBJECT_PATH), ("DELETE", SUBJECT_PATH),
])
def test_guard_watch_without_admin_configuration_is_unavailable(guard_admin, method, path):
    client, services = guard_admin
    services.settings.admin_secret = ""
    response = client.request(method, path, headers=ADMIN_HEADERS)
    assert response.status_code == 503
    services.db.register_guard_subject.assert_not_awaited()
    services.db.unregister_guard_subject.assert_not_awaited()


def test_admin_stats_exposes_watch_ages_and_budget_without_inventing_measurements(guard_admin):
    client, services = guard_admin
    response = client.get("/api/admin/stats", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    assert response.json()["guard_watch"] == services.hunter.guard_watch_stats.return_value
    services.hunter.guard_watch_stats.assert_awaited_once_with()


def test_admin_stats_without_hunter_reports_watch_unavailable(guard_admin):
    client, services = guard_admin
    services.hunter = None
    response = client.get("/api/admin/stats", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    assert response.json()["guard_watch"] is None


def test_admin_can_add_and_remove_guard_subject(guard_admin):
    client, services = guard_admin
    for method in ("POST", "DELETE"):
        response = client.request(method, SUBJECT_PATH, headers=ADMIN_HEADERS)
        assert response.status_code == 200
        assert response.json() == {"ok": True, "address": ADDRESS.lower(), "chain_id": 4663}
    services.db.register_guard_subject.assert_awaited_once_with(4663, ADDRESS.lower())
    services.db.unregister_guard_subject.assert_awaited_once_with(4663, ADDRESS.lower())


def test_admin_registration_rejected_by_cap_or_missing_record_is_conflict(guard_admin):
    client, services = guard_admin
    services.db.register_guard_subject.return_value = False
    response = client.post(SUBJECT_PATH, headers=ADMIN_HEADERS)
    assert response.status_code == 409
    assert "cap" in response.json()["detail"].lower()
    assert "confirmed" in response.json()["detail"].lower()


@pytest.mark.parametrize("method", ["POST", "DELETE"])
@pytest.mark.parametrize("chain_id,address", [
    (56, ADDRESS), (0, ADDRESS), (999999, ADDRESS),
    (4663, "not-an-address"), (4663, "0x" + "g" * 40), (4663, "0x" + "a" * 39),
])
def test_guard_watch_rejects_invalid_subject_before_mutating(guard_admin, method, chain_id, address):
    client, services = guard_admin
    response = client.request(
        method, f"/api/admin/guard-subjects/{chain_id}/{address}", headers=ADMIN_HEADERS,
    )
    assert response.status_code == 400
    services.db.register_guard_subject.assert_not_awaited()
    services.db.unregister_guard_subject.assert_not_awaited()


def test_public_stats_does_not_expose_guard_watch(guard_admin):
    client, services = guard_admin
    response = client.get("/api/stats")
    assert response.status_code == 200
    assert "guard_watch" not in response.json()
    services.hunter.guard_watch_stats.assert_not_awaited()
