"""MCP: Robinhood Chain support in tool descriptions and the read-only launch verdicts tool."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.database import Database
from mcp_server.tools import TOOL_DEFINITIONS, execute_tool
from utils.web3_client import Web3Client


AUTH_HEADERS = {"X-API-Key": "sb_testkey123456789012345678901234"}
TOKEN = "0x" + "12" * 20
TOOLS = {tool["name"]: tool for tool in TOOL_DEFINITIONS}


def _container(db):
    container = MagicMock()
    container.web3_client = Web3Client.__new__(Web3Client)
    container.web3_client._adapters = {56: MagicMock(), 4663: MagicMock()}
    container.auth_manager.validate_key = AsyncMock(return_value={"key_id": "k1"})
    container.db = db
    return container


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "mcp.db"))
    await database.initialize()
    yield database
    await database.close()


def _call(container, arguments):
    from mcp_server.server import create_mcp_router

    app = FastAPI()
    app.include_router(create_mcp_router(container), prefix="/mcp")
    return TestClient(app).post(
        "/mcp/messages",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_robinhood_launches", "arguments": arguments},
        },
        headers=AUTH_HEADERS,
    )


def test_every_chain_id_parameter_names_robinhood_chain():
    chain_tools = {
        name: tool
        for name, tool in TOOLS.items()
        if "chain_id" in tool["inputSchema"]["properties"]
    }

    assert set(chain_tools) == {
        "scan_contract",
        "simulate_transaction",
        "check_deployer",
        "check_approval_risk",
        "query_threat_graph",
        "get_robinhood_launches",
    }
    for tool in chain_tools.values():
        description = tool["inputSchema"]["properties"]["chain_id"]["description"]
        assert "4663" in description and "Robinhood Chain" in description


def test_scan_contract_description_states_how_unknown_is_represented():
    description = TOOLS["scan_contract"]["description"]

    for phrase in (
        "status 'unknown'",
        "verdict 'UNKNOWN'",
        "coverage_reasons",
        "never reported as safe",
    ):
        assert phrase in description


def test_launch_tool_is_registered_read_only_and_describes_outcomes():
    tool = TOOLS["get_robinhood_launches"]

    assert tool["inputSchema"]["type"] == "object"
    assert set(tool["inputSchema"]["properties"]) == {"chain_id", "limit", "cursor"}
    assert tool["inputSchema"]["properties"]["chain_id"]["default"] == 4663
    assert "required" not in tool["inputSchema"]
    for phrase in (
        "4663",
        "blocked",
        "watching",
        "cleared",
        "unknown",
        "not_scanned",
        "never safe",
        "Read-only",
    ):
        assert phrase in tool["description"]


@pytest.mark.asyncio
async def test_launch_tool_returns_the_feed_query_page(db):
    await db.upsert_discovered_launches(
        4663,
        [
            {
                "token_address": TOKEN,
                "source": "doppler",
                "launchpad": "Doppler",
                "source_rank": 4,
                "pool_id": None,
                "block_number": 100,
                "tx_hash": "0x" + "ab" * 32,
                "block_timestamp": 1_758_000_000,
            }
        ],
    )
    await db.record_launch_scan(4663, TOKEN, "unknown", 40)
    expected, next_cursor = await db.get_launch_feed(4663, 20)

    result = await execute_tool(_container(db), "get_robinhood_launches", {})

    assert result == {
        "launches": expected,
        "count": 1,
        "chain_id": 4663,
        "next_cursor": next_cursor,
    }
    assert result["launches"][0]["scan"]["outcome"] == "unknown"
    assert result["launches"][0]["scan"]["status"] == "unknown"
    assert result["launches"][0]["scan"]["risk_score"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("requested,expected", [(1000, 100), (0, 1), (5, 5)])
async def test_launch_tool_bounds_the_page_size(requested, expected):
    db = MagicMock(get_launch_feed=AsyncMock(return_value=([], "100:" + TOKEN)))

    result = await execute_tool(
        _container(db), "get_robinhood_launches", {"limit": requested, "cursor": "7:" + TOKEN}
    )

    db.get_launch_feed.assert_awaited_once_with(4663, expected, "7:" + TOKEN)
    assert result["next_cursor"] == "100:" + TOKEN


@pytest.mark.asyncio
@pytest.mark.parametrize("cursor", ["nope", 123, "9" * 19 + ":" + TOKEN, "1" + "0" * 40 + ":" + TOKEN])
async def test_launch_tool_reports_a_malformed_cursor_as_a_tool_error(db, cursor):
    from mcp_server.server import process_jsonrpc

    response = await process_jsonrpc(_container(db), {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "get_robinhood_launches", "arguments": {"cursor": cursor}},
    })

    result = response["result"]
    assert result["isError"] is True
    assert json.loads(result["content"][0]["text"]) == {"error": "Invalid cursor"}


def test_launch_tool_rejects_an_unsupported_chain_before_the_database():
    db = MagicMock(get_launch_feed=AsyncMock())

    response = _call(_container(db), {"chain_id": 999999})

    assert response.status_code == 400
    assert "4663" in response.json()["error"]["message"]
    db.get_launch_feed.assert_not_awaited()


@pytest.mark.asyncio
async def test_launch_tool_says_discovery_is_unavailable_on_other_chains():
    db = MagicMock(get_launch_feed=AsyncMock())

    result = await execute_tool(_container(db), "get_robinhood_launches", {"chain_id": 56})

    assert result == {
        "launches": [],
        "count": 0,
        "chain_id": 56,
        "next_cursor": None,
        "discovery_unavailable": "Launch discovery is not available on this chain",
    }
    db.get_launch_feed.assert_not_awaited()
