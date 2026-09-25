"""Admin and webhook routes are left out of the public API schema and still answer; the old test pages are gone."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

HIDDEN_PATHS = {
    "/webhook/uptime": {"post"},
    "/api/keys": {"post"},
    "/api/admin/stats": {"get"},
    "/api/admin/signups": {"get"},
    "/api/admin/watch/deployer": {"post"},
    "/api/admin/watch/deployer/{address}": {"delete"},
    "/api/admin/watch/deployers": {"get"},
    "/api/admin/watch/alerts": {"get"},
    "/api/admin/guard-subjects/{chain_id}/{address}": {"post", "delete"},
}
PUBLIC_PATHS = (
    "/api/stats",
    "/api/threats/feed",
    "/api/verdict/{chain_id}/{address}",
    "/api/coverage/{chain_id}",
    "/api/verdicts",
    "/api/health",
    "/api/ready",
)


def _admin_container():
    return SimpleNamespace(
        settings=SimpleNamespace(admin_secret="s", trusted_proxies=[]),
        auth_manager=None,
        db=None,
        mempool_monitor=None,
        phishing_service=None,
    )


@pytest.fixture
def schema_paths():
    import api

    api.app.openapi_schema = None
    yield api.app.openapi()["paths"]
    api.app.openapi_schema = None


def test_admin_routes_are_not_in_the_public_schema(schema_paths):
    for path in HIDDEN_PATHS:
        assert path not in schema_paths, path


def test_public_routes_stay_in_the_schema(schema_paths):
    for path in PUBLIC_PATHS:
        assert path in schema_paths, path


def test_hidden_routes_are_still_served():
    import api

    served = {}
    for route in api.app.routes:
        if getattr(route, "path", None) in HIDDEN_PATHS:
            served.setdefault(route.path, set()).update(method.lower() for method in route.methods)
    assert served == HIDDEN_PATHS


@pytest.mark.parametrize("path", ["/test", "/test-phishing"])
def test_removed_test_pages_are_not_served(path):
    import api

    assert path not in {getattr(route, "path", None) for route in api.app.routes}


@pytest.mark.parametrize("headers", [{}, {"x-admin-secret": "wrong"}], ids=["no-secret", "wrong-secret"])
def test_hidden_admin_route_refuses_a_missing_or_wrong_secret(monkeypatch, headers):
    import api

    monkeypatch.setattr(api, "container", _admin_container())
    response = TestClient(api.app).get("/api/admin/stats", headers=headers)
    assert response.status_code == 403


def test_hidden_admin_route_accepts_the_secret_and_then_needs_its_database(monkeypatch):
    import api

    monkeypatch.setattr(api, "container", _admin_container())
    response = TestClient(api.app).get("/api/admin/stats", headers={"x-admin-secret": "s"})
    assert response.status_code == 503
    assert response.json()["detail"] == "Database not available"


def test_graph_seed_is_not_in_the_schema_and_still_answers():
    from services.threat_graph_router import create_threat_graph_router

    container = MagicMock()
    container.settings.admin_secret = "secret"
    app = FastAPI()
    app.include_router(create_threat_graph_router(container), prefix="/api/graph")
    paths = app.openapi()["paths"]
    assert "/api/graph/seed" not in paths
    assert "/api/graph/stats" in paths
    assert TestClient(app).post("/api/graph/seed").status_code == 401
