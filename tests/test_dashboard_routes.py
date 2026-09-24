"""Public dashboard routes report unavailable data as unavailable and keep both threat sources visible."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from utils.web3_client import Web3Client


ADDRESS = "0x" + "ab" * 20
CONTRACT_ROW = (ADDRESS, 56, 90, "HIGH", "honeypot", '["High sell tax"]', 1000)
MEMPOOL_ALERT = {
    "alert_type": "suspicious_approval",
    "chain_id": 1,
    "severity": "HIGH",
    "target_token": ADDRESS,
    "created_at": 2000,
}
MEMPOOL_STATS = {
    "total_pending_seen": 1200,
    "sandwiches_detected": 3,
    "frontruns_detected": 0,
    "suspicious_approvals": 40,
    "monitored_chains": [1, 56],
    "counting_since": 1500.0,
}
DISCOVERY = {
    "cursor": 70_706_607,
    "last_sweep_at": 1_790_217_346.4,
    "last_discovered_block": 70_756_543,
}


def _container(db=None, mempool=None):
    return SimpleNamespace(
        settings=SimpleNamespace(admin_secret="test-admin", trusted_proxies=[]),
        auth_manager=None,
        db=db,
        mempool_monitor=mempool,
        phishing_service=None,
    )


def _db(rows=(CONTRACT_ROW,), all_time=None):
    cursor = SimpleNamespace(fetchall=AsyncMock(return_value=list(rows)))
    return SimpleNamespace(
        _db=SimpleNamespace(execute=AsyncMock(return_value=cursor)),
        get_platform_stats=AsyncMock(
            return_value={
                "all_time": all_time
                or {
                    "unique_contracts_scanned": 10,
                    "threats_detected": 2,
                    "transactions_blocked": 1,
                }
            }
        ),
        get_launch_discovery_status=AsyncMock(return_value=dict(DISCOVERY)),
    )


def _mempool(alerts=(MEMPOOL_ALERT,)):
    return SimpleNamespace(
        get_alerts=MagicMock(return_value=list(alerts)),
        get_stats=MagicMock(return_value=dict(MEMPOOL_STATS)),
    )


@pytest.fixture
def dashboard_api(monkeypatch):
    import api

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {
        chain_id: SimpleNamespace(chain_id=chain_id) for chain_id in (56, 1, 4663)
    }
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))

    def client_for(container):
        monkeypatch.setattr(api, "container", container)
        return TestClient(api.app)

    return client_for


def test_stats_without_database_or_mempool_are_unavailable_not_zero(dashboard_api):
    body = dashboard_api(_container()).get("/api/stats").json()
    for key in (
        "transactions_monitored",
        "contracts_scanned",
        "threats_detected",
        "transactions_blocked",
        "sandwiches_caught",
        "suspicious_approvals",
        "chains_protected",
        "mempool_counting_since",
        "launch_discovery",
    ):
        assert body[key] is None, key


def test_stats_with_both_sources_report_values_and_counting_window(dashboard_api):
    body = dashboard_api(_container(db=_db(), mempool=_mempool())).get("/api/stats").json()
    assert body["transactions_monitored"] == 1200
    assert body["contracts_scanned"] == 10
    assert body["threats_detected"] == 2
    assert body["transactions_blocked"] == 1
    assert body["sandwiches_caught"] == 3
    assert body["suspicious_approvals"] == 40
    assert body["chains_protected"] == 2
    assert body["mempool_counting_since"] == 1500.0


def test_stats_report_how_far_launch_discovery_has_read(dashboard_api):
    db = _db()
    body = dashboard_api(_container(db=db)).get("/api/stats").json()
    assert body["launch_discovery"] == {"chain_id": 4663, **DISCOVERY}
    db.get_launch_discovery_status.assert_awaited_once_with(4663)


def test_feed_default_merges_both_sources(dashboard_api):
    body = dashboard_api(_container(db=_db(), mempool=_mempool())).get("/api/threats/feed").json()
    assert [t["type"] for t in body["threats"]] == [
        "mempool_suspicious_approval",
        "high_risk_contract",
    ]


def test_feed_contract_source_is_not_crowded_out_by_mempool_alerts(dashboard_api):
    alerts = [dict(MEMPOOL_ALERT, created_at=3000 + i) for i in range(5)]
    mempool = _mempool(alerts)
    body = (
        dashboard_api(_container(db=_db(), mempool=mempool))
        .get(
            "/api/threats/feed",
            params={"source": "contracts", "limit": 2},
        )
        .json()
    )
    assert [t["type"] for t in body["threats"]] == ["high_risk_contract"]
    mempool.get_alerts.assert_not_called()


def test_feed_mempool_source_skips_contract_rows(dashboard_api):
    db = _db()
    body = (
        dashboard_api(_container(db=db, mempool=_mempool()))
        .get(
            "/api/threats/feed",
            params={"source": "mempool"},
        )
        .json()
    )
    assert [t["type"] for t in body["threats"]] == ["mempool_suspicious_approval"]
    db._db.execute.assert_not_awaited()


def test_feed_rejects_unknown_source(dashboard_api):
    response = dashboard_api(_container(db=_db(), mempool=_mempool())).get(
        "/api/threats/feed",
        params={"source": "everything"},
    )
    assert response.status_code == 400


def test_dashboard_is_revalidated_and_locked_down(dashboard_api):
    response = dashboard_api(_container()).get("/dashboard")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_legacy_xss_filter_is_disabled(dashboard_api):
    response = dashboard_api(_container()).get("/api/stats")
    assert response.headers["x-xss-protection"] == "0"


def test_mempool_counters_report_when_counting_started():
    import time

    from services.mempool_service import MempoolMonitor

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {}
    before = time.time()
    stats = MempoolMonitor(registry).get_stats()
    assert before <= stats["counting_since"] <= time.time()
    assert stats["total_pending_seen"] == 0
