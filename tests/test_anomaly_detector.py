"""Tests for Agent Behavior Anomaly Detection."""

import json
import time
import pytest
from unittest.mock import AsyncMock, MagicMock

from services.anomaly_detector import AnomalyDetector


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.get_anomaly_baseline = AsyncMock(return_value=None)
    db.upsert_anomaly_baseline = AsyncMock()
    db.get_all_ready_baselines = AsyncMock(return_value=[])
    return db


@pytest.fixture
def detector(mock_db):
    return AnomalyDetector(db=mock_db)


def _make_event(**overrides):
    base = {
        "timestamp": time.time(),
        "tx_value_usd": 100,
        "target_address": "0xPancakeRouter",
        "method_selector": "0x38ed1739",
        "gas_used": 250000,
        "chain_id": 56,
        "verdict": "ALLOW",
    }
    base.update(overrides)
    return base


def _make_ready_baseline(values=None, hourly=None, contracts=None, methods=None):
    """Create a ready baseline for testing anomaly detection."""
    return {
        "agent_id": "test-agent",
        "baseline_data": json.dumps({
            "agent_id": "test-agent",
            "started_at": time.time() - 86400 * 4,  # 4 days ago
            "ready": True,
            "tx_count": 100,
            "hourly_counts": hourly or {str(int(time.time() / 3600) - i): 3 for i in range(72)},
            "values": values or [100, 120, 90, 110, 105, 95, 115, 100, 108, 92],
            "contracts": contracts or {"0xpancakerouter": 50, "0xtoken1": 30, "0xtoken2": 20},
            "methods": methods or {"0x38ed1739": 80, "0xa9059cbb": 20},
            "gas_values": [250000, 260000, 245000, 255000, 250000],
            "chains": {"56": 100},
        }),
        "baseline_ready": True,
    }


@pytest.mark.asyncio
async def test_update_baseline_creates_new(detector, mock_db):
    event = _make_event()
    await detector.update_baseline("agent-1", event)
    mock_db.upsert_anomaly_baseline.assert_awaited_once()
    args = mock_db.upsert_anomaly_baseline.call_args[0]
    assert args[0] == "agent-1"
    data = json.loads(args[1])
    assert data["tx_count"] == 1


@pytest.mark.asyncio
async def test_update_baseline_increments(detector, mock_db):
    existing = {
        "agent_id": "agent-1",
        "started_at": time.time() - 3600,
        "ready": False,
        "tx_count": 5,
        "hourly_counts": {},
        "values": [100, 200],
        "contracts": {},
        "methods": {},
        "gas_values": [],
        "chains": {},
    }
    mock_db.get_anomaly_baseline.return_value = {
        "baseline_data": json.dumps(existing),
        "baseline_ready": False,
    }
    await detector.update_baseline("agent-1", _make_event())
    args = mock_db.upsert_anomaly_baseline.call_args[0]
    data = json.loads(args[1])
    assert data["tx_count"] == 6


@pytest.mark.asyncio
async def test_baseline_not_ready_insufficient_data(detector, mock_db):
    """Baseline needs 72h and 10+ transactions."""
    event = _make_event()
    await detector.update_baseline("agent-1", event)
    args = mock_db.upsert_anomaly_baseline.call_args[0]
    data = json.loads(args[1])
    assert data["ready"] is False


@pytest.mark.asyncio
async def test_check_anomaly_returns_none_before_ready(detector, mock_db):
    mock_db.get_anomaly_baseline.return_value = {
        "baseline_data": json.dumps({"ready": False}),
        "baseline_ready": False,
    }
    result = await detector.check_anomaly("agent-1", _make_event())
    assert result is None


@pytest.mark.asyncio
async def test_value_spike_detected(detector, mock_db):
    """5x+ normal value should trigger value_spike."""
    mock_db.get_anomaly_baseline.return_value = _make_ready_baseline(
        values=[100, 120, 90, 110, 105, 95, 115, 100, 108, 92],
    )
    event = _make_event(tx_value_usd=5000)  # ~50x normal
    result = await detector.check_anomaly("agent-1", event)
    assert result is not None
    assert result["alert_type"] == "value_spike"
    assert result["severity"] == "high"


@pytest.mark.asyncio
async def test_value_spike_not_triggered_normal(detector, mock_db):
    """Normal value should not trigger."""
    mock_db.get_anomaly_baseline.return_value = _make_ready_baseline(
        values=[100, 120, 90, 110, 105, 95, 115, 100, 108, 92],
    )
    event = _make_event(tx_value_usd=110)
    result = await detector.check_anomaly("agent-1", event)
    assert result is None


@pytest.mark.asyncio
async def test_frequency_spike_detected(detector, mock_db):
    """3x+ hourly rate should trigger."""
    current_hour = str(int(time.time() / 3600))
    hourly = {str(int(time.time() / 3600) - i): 3 for i in range(1, 73)}
    hourly[current_hour] = 15  # 5x normal
    mock_db.get_anomaly_baseline.return_value = _make_ready_baseline(hourly=hourly)
    event = _make_event()
    result = await detector.check_anomaly("agent-1", event)
    assert result is not None
    assert result["alert_type"] == "frequency_spike"


@pytest.mark.asyncio
async def test_method_anomaly_dangerous_first_time(detector, mock_db):
    """First-time approve() call should trigger."""
    mock_db.get_anomaly_baseline.return_value = _make_ready_baseline(
        methods={"0x38ed1739": 80},  # only swapExactTokensForTokens known
    )
    event = _make_event(method_selector="0x095ea7b3")  # approve()
    result = await detector.check_anomaly("agent-1", event)
    assert result is not None
    assert result["alert_type"] == "method_anomaly"
    assert "approve" in result["title"]


@pytest.mark.asyncio
async def test_method_anomaly_not_triggered_known(detector, mock_db):
    """Known method should not trigger."""
    mock_db.get_anomaly_baseline.return_value = _make_ready_baseline(
        methods={"0x38ed1739": 80, "0x095ea7b3": 10},
    )
    event = _make_event(method_selector="0x095ea7b3")
    result = await detector.check_anomaly("agent-1", event)
    # approve is known, shouldn't trigger method_anomaly
    # (but might trigger other alerts depending on other values)
    if result:
        assert result["alert_type"] != "method_anomaly"


@pytest.mark.asyncio
async def test_new_contract_burst(detector, mock_db):
    """Unknown contract with 20+ known contracts should trigger."""
    contracts = {f"0xcontract{i}": 5 for i in range(25)}
    mock_db.get_anomaly_baseline.return_value = _make_ready_baseline(contracts=contracts)
    event = _make_event(target_address="0xNeverSeenBefore")
    result = await detector.check_anomaly("agent-1", event)
    assert result is not None
    assert result["alert_type"] == "new_contract_burst"


@pytest.mark.asyncio
async def test_get_baseline(detector, mock_db):
    mock_db.get_anomaly_baseline.return_value = _make_ready_baseline()
    result = await detector.get_baseline("agent-1")
    assert result is not None
    assert result["baseline_ready"] is True


@pytest.mark.asyncio
async def test_get_baseline_none(detector, mock_db):
    mock_db.get_anomaly_baseline.return_value = None
    result = await detector.get_baseline("agent-1")
    assert result is None
