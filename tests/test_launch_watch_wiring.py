"""The container wires one 4663 RPC guard through discovery, the hunter and the launch watch."""

from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from agent.launch_watch import LaunchWatch
from core.config import Settings
from services.rpc_guard import RPC_BUDGET_RPS, RpcGuard

PATCHED = (
    "Web3Client", "AIAnalyzer", "ScamDatabase", "CalldataDecoder", "OnchainRecorder",
    "TransactionScanner", "TokenScanner", "DexService", "EthosService", "HoneypotService",
    "ContractService", "GreenfieldService", "TenderlySimulator", "RiskEngine",
)


def build_container():
    from core.container import ServiceContainer

    patches = [patch(f"core.container.{name}") for name in PATCHED]
    for active in patches:
        active.start()
    try:
        return ServiceContainer(Settings(_env_file=None, robinhood_rpc_url="https://rpc.example/4663"))
    finally:
        for active in patches:
            active.stop()


def test_discovery_hunter_and_watch_share_one_guard_at_the_budget_rate():
    container = build_container()

    guard = container.robinhood_rpc_guard
    assert isinstance(guard, RpcGuard) and guard.rate == RPC_BUDGET_RPS
    assert container.hunter.rpc_guard is guard
    assert container.hunter.discovery.guard is guard
    assert container.hunter.discovery.rpc_url == "https://rpc.example/4663"
    assert isinstance(container.launch_watch, LaunchWatch)
    assert container.launch_watch.hunter is container.hunter
    assert container.hunter.launch_watch is container.launch_watch


@pytest.mark.asyncio
async def test_shutdown_stops_the_watch_before_the_hunter():
    container = build_container()
    order = MagicMock()
    for name in ("launch_watch", "hunter", "mempool_monitor", "indexer"):
        order.attach_mock(AsyncMock(), f"{name}_stop")
        getattr(container, name).stop = getattr(order, f"{name}_stop")
    for name in ("db", "greenfield_service", "tenderly_simulator", "token_sniffer", "cache"):
        setattr(container, name, MagicMock(close=AsyncMock()))

    await container.shutdown()

    assert order.mock_calls[:2] == [call.launch_watch_stop(), call.hunter_stop()]
