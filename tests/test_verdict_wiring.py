"""Wiring of the verdict publisher: container, permalink endpoint and the bot's Robinhood Chain scan paths."""

import ast
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from eth_utils import keccak, to_checksum_address
from fastapi.testclient import TestClient

from core.config import Settings
from core.database import Database
from core.extension_formatter import is_scan_incomplete
from services.verdict_publisher import VerdictPublisher
from utils.web3_client import UnsupportedChainError, Web3Client
from tests.test_lifespan import mock_container  # noqa: F401  (pytest fixture)

TOKEN = "0x" + "7a" * 20
COMPLETE_HIGH = {
    "status": "ok",
    "risk_level": "HIGH",
    "rug_probability": 85.0,
    "coverage": {"structural": 1, "honeypot": 1},
    "coverage_reasons": {},
}


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------


def test_container_exposes_the_verdict_publisher(monkeypatch):
    monkeypatch.delenv("ROBINHOOD_VERDICT_REGISTRY", raising=False)
    monkeypatch.delenv("ROBINHOOD_RECORDER_PRIVATE_KEY", raising=False)
    with (
        patch("core.container.Web3Client"),
        patch("core.container.AIAnalyzer"),
        patch("core.container.OnchainRecorder"),
        patch("core.container.GreenfieldService"),
        patch("core.container.TenderlySimulator"),
    ):
        from core.container import ServiceContainer

        settings = Settings(_env_file=None, robinhood_rpc_url="https://rpc.example/4663")
        container = ServiceContainer(settings)

    publisher = container.verdict_publisher
    assert isinstance(publisher, VerdictPublisher)
    assert publisher._db is container.db
    assert publisher._rpc_url == "https://rpc.example/4663"
    assert not publisher.is_onchain_enabled()


# ---------------------------------------------------------------------------
# GET /api/verdict/{chain_id}/{address}
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def verdict_api(monkeypatch):
    import api

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {chain_id: MagicMock(chain_id=chain_id) for chain_id in (56, 4663)}
    database = Database(":memory:")
    await database.initialize()
    services = MagicMock()
    services.db = database
    services.web3_client = registry
    services.settings = SimpleNamespace(trusted_proxies=[], admin_secret="")
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", registry)
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    client = TestClient(api.app, raise_server_exceptions=False)
    yield api, client, database
    client.close()
    await database.close()


async def publish(database, scan, honeypot=None):
    publisher = VerdictPublisher(
        database, rpc_url="https://rpc.invalid", registry_address=""
    )
    return await publisher.publish(4663, TOKEN, scan, honeypot_data=honeypot)


@pytest.mark.asyncio
async def test_permalink_serves_the_latest_evidence_and_how_to_verify(verdict_api):
    _, client, database = verdict_api
    await publish(database, {**COMPLETE_HIGH, "status": "unknown"})
    summary = await publish(database, COMPLETE_HIGH)
    await database.update_verdict_onchain(
        summary["evidence_id"], "submitted", tx_hash="0x" + "ab" * 32
    )

    response = client.get(f"/api/verdict/4663/{to_checksum_address(TOKEN)}")
    assert response.status_code == 200
    body = response.json()
    assert body["chain_id"] == 4663
    assert body["subject"] == TOKEN
    assert body["verdict"] == "HIGH"
    assert body["verdict_code"] == 3
    assert body["evidence_hash"] == summary["evidence_hash"]
    assert body["evidence_hash"] == "0x" + keccak(body["canonical"].encode("utf-8")).hex()
    assert body["evidence"] == json.loads(body["canonical"])
    assert body["evidence"]["verdict"] == "HIGH"
    assert body["onchain_status"] == "submitted"
    assert body["tx_hash"] == "0x" + "ab" * 32
    assert body["published_at"] > 0
    assert "VerdictRecorded" in body["verify"]
    assert "canonical" in body["verify"]
    for status in ("confirmed", "reverted", "pending", "sending", "submitted", "unconfirmed", "failed", "off"):
        assert f"`{status}`" in body["verify"]


@pytest.mark.asyncio
async def test_permalink_reports_an_unsent_unknown_verdict(verdict_api):
    _, client, database = verdict_api
    await publish(database, {**COMPLETE_HIGH, "coverage": {"structural": 1, "honeypot": 0.5}})
    body = client.get(f"/api/verdict/4663/{TOKEN}").json()
    assert body["verdict"] == "UNKNOWN"
    assert body["verdict_code"] == 0
    assert body["evidence"]["status"] == "unknown"
    assert (body["onchain_status"], body["tx_hash"], body["registry"]) == ("off", None, None)


@pytest.mark.asyncio
async def test_permalink_is_404_when_never_published(verdict_api):
    _, client, _ = verdict_api
    assert client.get(f"/api/verdict/4663/{TOKEN}").status_code == 404


@pytest.mark.asyncio
async def test_permalink_is_scoped_to_the_chain(verdict_api):
    _, client, database = verdict_api
    await publish(database, COMPLETE_HIGH)
    assert client.get(f"/api/verdict/4663/{TOKEN}").status_code == 200
    assert client.get(f"/api/verdict/56/{TOKEN}").status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,status",
    [
        (f"/api/verdict/999999/{TOKEN}", 400),
        ("/api/verdict/4663/not-an-address", 400),
        (f"/api/verdict/4663/{TOKEN[:-2]}", 400),
        (f"/api/verdict/abc/{TOKEN}", 422),
    ],
)
async def test_permalink_rejects_bad_input(verdict_api, path, status):
    _, client, _ = verdict_api
    assert client.get(path).status_code == status


@pytest.mark.asyncio
async def test_permalink_is_503_without_a_database(verdict_api, monkeypatch):
    api, client, _ = verdict_api
    monkeypatch.setattr(api.container, "db", None)
    assert client.get(f"/api/verdict/4663/{TOKEN}").status_code == 503


@pytest.mark.asyncio
async def test_permalink_uses_the_global_ip_rate_limit(verdict_api, monkeypatch):
    api, client, _ = verdict_api
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(requests_per_minute=2, burst=10))
    codes = [client.get(f"/api/verdict/4663/{TOKEN}").status_code for _ in range(3)]
    assert codes == [404, 404, 429]


def test_permalink_is_placed_right_after_the_base_attestations_handler():
    tree = ast.parse(Path("api.py").read_text(encoding="utf-8"))
    routes = [
        decorator.args[0].value
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef)
        for decorator in node.decorator_list
        if isinstance(decorator, ast.Call)
        and getattr(decorator.func, "attr", "") in {"get", "post"}
    ]
    index = routes.index("/api/base/attestations")
    assert routes[index + 1] == "/api/verdict/{chain_id}/{address}"
    assert routes.count("/api/verdict/{chain_id}/{address}") == 1


# ---------------------------------------------------------------------------
# Bot: 4663 scan paths publish; other chains and the BSC recorder are unchanged
# ---------------------------------------------------------------------------

HONEYPOT_DATA = {"is_honeypot": True, "field_providers": {"is_honeypot": "eth_simulateV1"}}


@pytest.fixture
def bot_scan_functions():
    """Load bot.py's scan handlers without importing the optional Telegram package."""
    tree = ast.parse(Path("bot.py").read_text(encoding="utf-8"))
    names = {"scan_contract", "check_token"}
    module = ast.Module(
        body=[
            node
            for node in tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name in names
        ],
        type_ignores=[],
    )
    client = Web3Client.__new__(Web3Client)
    client._adapters = {56: MagicMock(), 4663: MagicMock()}
    client.get_token_info = AsyncMock(return_value={})
    services = MagicMock()
    services.registry.run_all = AsyncMock(
        return_value=[SimpleNamespace(name="honeypot", data=HONEYPOT_DATA)]
    )
    recorder = MagicMock()
    recorder.is_available.return_value = True
    recorder.record_scan_fire_and_forget = AsyncMock()
    recorder.attest_fire_and_forget = AsyncMock()
    namespace = {
        "asyncio": asyncio,
        "is_scan_incomplete": is_scan_incomplete,
        "UnsupportedChainError": UnsupportedChainError,
        "logger": MagicMock(),
        "container": services,
        "ai_analyzer": MagicMock(is_available=MagicMock(return_value=False)),
        "risk_engine": MagicMock(compute_from_results=MagicMock(return_value=dict(COMPLETE_HIGH))),
        "onchain_recorder": recorder,
        "base_attestor": recorder,
        "tx_scanner": SimpleNamespace(scan_address=AsyncMock(return_value={"risk_level": "low"})),
        "token_scanner": SimpleNamespace(
            check_token=AsyncMock(return_value={"safety_level": "safe"})
        ),
        "_get_cached": MagicMock(return_value=None),
        "_set_cache": MagicMock(),
        "format_full_report": MagicMock(return_value="Report"),
        "format_scan_result": MagicMock(return_value="Report"),
        "format_token_result": MagicMock(return_value="Report"),
        "_scan_buttons": MagicMock(return_value=None),
        "_token_buttons": MagicMock(return_value=None),
        "get_chain_name": str,
        "web3_client": client,
        "Update": object,
    }
    exec(compile(module, "bot.py", "exec"), namespace)
    return namespace


def update():
    return SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
async def test_robinhood_scans_publish_the_composite_result(bot_scan_functions, handler):
    ns = bot_scan_functions
    await ns[handler](update(), TOKEN, chain_id=4663)
    publish_call = ns["container"].verdict_publisher.publish_fire_and_forget
    publish_call.assert_called_once_with(
        4663,
        TOKEN,
        ns["risk_engine"].compute_from_results.return_value,
        honeypot_data=HONEYPOT_DATA,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
async def test_robinhood_legacy_fallback_publishes_the_fallback_result(bot_scan_functions, handler):
    ns = bot_scan_functions
    ns["container"].registry.run_all.side_effect = RuntimeError("provider down")
    await ns[handler](update(), TOKEN, chain_id=4663)
    publish_call = ns["container"].verdict_publisher.publish_fire_and_forget
    publish_call.assert_called_once()
    args, kwargs = publish_call.call_args
    assert args[:2] == (4663, TOKEN)
    # The fallback result carries no coverage, so it is always published as UNKNOWN.
    assert args[2]["status"] == "unknown"
    assert kwargs == {"honeypot_data": None}


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
async def test_cached_robinhood_scans_are_not_published_again(bot_scan_functions, handler):
    ns = bot_scan_functions
    ns["_get_cached"].return_value = {"status": "ok", "coverage": {"honeypot": 1}}
    await ns[handler](update(), TOKEN, chain_id=4663)
    ns["container"].verdict_publisher.publish_fire_and_forget.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
async def test_other_chains_never_publish_and_keep_bsc_recording(bot_scan_functions, handler):
    ns = bot_scan_functions
    await ns[handler](update(), TOKEN, chain_id=56)
    ns["container"].verdict_publisher.publish_fire_and_forget.assert_not_called()
    ns["onchain_recorder"].record_scan_fire_and_forget.assert_awaited_once()
    ns["base_attestor"].attest_fire_and_forget.assert_awaited_once()


# ---------------------------------------------------------------------------
# Single sender: only the API lifespan starts the drain
# ---------------------------------------------------------------------------


def test_api_lifespan_starts_the_drain_after_the_container_and_stops_it_before_shutdown(mock_container):
    import api

    order = []
    mock_container.startup.side_effect = lambda: order.append("container startup")
    mock_container.verdict_publisher.start.side_effect = lambda: order.append("drain start")
    mock_container.hunter.start.side_effect = lambda: order.append("hunter start")
    mock_container.hunter.stop.side_effect = lambda: order.append("hunter stop")
    mock_container.verdict_publisher.stop.side_effect = lambda: order.append("drain stop")
    mock_container.shutdown.side_effect = lambda: order.append("container shutdown")
    with TestClient(api.app):
        assert order == ["container startup", "drain start", "hunter start"]
    assert order == [
        "container startup", "drain start", "hunter start", "hunter stop", "drain stop", "container shutdown",
    ]
    mock_container.verdict_publisher.start.assert_called_once_with()
    mock_container.verdict_publisher.stop.assert_called_once_with()


def test_only_the_api_process_starts_the_drain_or_reads_the_key():
    """The bot shares the container and the .env file, so no code path it runs may start the drain."""
    root = Path(__file__).resolve().parent.parent
    starters, key_readers = [], []
    for path in root.rglob("*.py"):
        relative = path.relative_to(root).as_posix()
        if relative.startswith(("tests/", "sdk/", "scripts/census_4663/")) or "node_modules" in relative:
            continue
        source = path.read_text(encoding="utf-8")
        if "verdict_publisher.start(" in source:
            starters.append(relative)
        if "ROBINHOOD_RECORDER_PRIVATE_KEY" in source:
            key_readers.append(relative)
    assert starters == ["api.py"]
    assert key_readers == ["services/verdict_publisher.py"]
