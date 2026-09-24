"""Admin and test routes are left out of the public API schema and still answer."""

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

HIDDEN_PATHS = {
    "/webhook/uptime": {"post"},
    "/test-phishing": {"get"},
    "/test": {"get"},
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
    "/api/health",
)


@pytest.fixture
def schema_paths():
    import api

    api.app.openapi_schema = None
    yield api.app.openapi()["paths"]
    api.app.openapi_schema = None


def test_admin_and_test_routes_are_not_in_the_public_schema(schema_paths):
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


def test_hidden_admin_route_still_checks_the_admin_secret(monkeypatch):
    import api

    monkeypatch.setattr(api, "container", None)
    response = TestClient(api.app).get("/api/admin/stats")
    assert response.status_code == 503


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
