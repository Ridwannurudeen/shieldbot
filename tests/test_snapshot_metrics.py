"""The weekly metrics snapshot reads the admin stats from the configured local API."""

from types import SimpleNamespace

import httpx
import pytest

from scripts import snapshot_metrics


@pytest.mark.parametrize("api_url", ["http://127.0.0.1:8000", "http://127.0.0.1:8000/"])
def test_fetch_stats_requests_the_admin_route_with_or_without_a_trailing_slash(
    monkeypatch, api_url
):
    requested = []

    def handler(request):
        requested.append((request.url.path, request.headers.get("x-admin-secret")))
        return httpx.Response(200, json={"all_time": {}})

    def client(**kwargs):
        return httpx.Client(transport=httpx.MockTransport(handler), **kwargs)

    # Only this module's reference to httpx is replaced.
    monkeypatch.setattr(snapshot_metrics, "httpx", SimpleNamespace(Client=client))
    monkeypatch.setattr(snapshot_metrics, "API_URL", api_url)
    monkeypatch.setattr(snapshot_metrics, "ADMIN_SECRET", "test-secret")

    assert snapshot_metrics.fetch_stats() == {"all_time": {}}
    assert requested == [("/api/admin/stats", "test-secret")]
