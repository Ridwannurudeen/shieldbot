"""Hunter-path verdicts: AgentTools.scan_contract carries the honeypot analyzer's data to the publisher.

The hunter publishes `await verdict_publisher.publish(chain_id, token, result)` with the result of
AgentTools.scan_contract, so a simulation-proven honeypot and its simulation block must survive that path.
"""

import copy
import json
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from agent.tools import AgentTools
from analyzers.honeypot import HoneypotAnalyzer
from core.analyzer import AnalyzerResult
from core.database import Database
from core.risk_engine import RiskEngine
from core.verdict_evidence import Verdict, build_evidence, verdict_for
from services.honeypot_service import HoneypotService
from services.verdict_publisher import VerdictPublisher
from tests.test_robinhood_simulation import (
    adapter_with,
    calls_by_label,
    client_with,
    error_string,
    fresh_addresses,
    load,
    make_revert,
    rpc_for,
)
from utils.scam_db import ScamDatabase

NO_GOPLUS = {"status": "unknown", "reason": "GoPlus has no data", "data": {}}


async def hunter_scan(fixture):
    """Run AgentTools.scan_contract for a 4663 token whose simulation replays a recorded fixture."""
    service = HoneypotService(client_with(adapter_with(rpc_for(fixture))))
    container = MagicMock()
    container.risk_engine = RiskEngine()

    async def run_all(ctx, deadline=None):
        # The merged registry passes the background deadline through; this fake ignores it.
        return [await HoneypotAnalyzer(service).analyze(ctx)]

    container.registry.run_all = run_all
    with (
        fresh_addresses(fixture),
        patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock(return_value=NO_GOPLUS)),
    ):
        return await AgentTools(container).scan_contract(fixture["token"], chain_id=4663)


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


@pytest.mark.asyncio
async def test_hunter_result_for_a_recorded_honeypot_is_published_as_honeypot(db):
    fixture = load("v2_honeypot_sell_reverts")
    result = await hunter_scan(fixture)

    honeypot = result["honeypot_data"]
    assert honeypot["is_honeypot"] is True
    assert honeypot["can_sell"] is False
    assert honeypot["simulation_block"] == 65554454
    assert honeypot["field_providers"]["is_honeypot"] == "eth_simulateV1"
    assert verdict_for(result) is Verdict.HONEYPOT

    publisher = VerdictPublisher(db, rpc_url="https://rpc.invalid", registry_address="")
    summary = await publisher.publish(4663, fixture["token"], result)
    assert summary["verdict"] == "HONEYPOT"
    stored = await db.get_latest_verdict_evidence(4663, fixture["token"])
    evidence = json.loads(stored["canonical"])
    assert evidence["verdict"] == "HONEYPOT"
    assert evidence["observed_block"] == stored["observed_block"] == 65554454
    assert evidence["honeypot"]["simulation_block"] == 65554454
    assert evidence["honeypot"]["field_providers"]["is_honeypot"] == "eth_simulateV1"


@pytest.mark.asyncio
async def test_hunter_result_for_an_unmeasured_simulation_stays_unknown():
    fixture = copy.deepcopy(load("v4_native_liquidity_launcher"))
    make_revert(calls_by_label(fixture)["buy"], error_string("TRANSFER_FAILED"))
    result = await hunter_scan(fixture)
    assert result["status"] == "unknown"
    assert result["honeypot_data"]["is_honeypot"] is None
    assert verdict_for(result) is Verdict.UNKNOWN
    evidence = build_evidence(4663, fixture["token"], result, None, scanned_at=1)
    assert evidence["verdict"] == "UNKNOWN"
    # A simulation that reached a block still records it, even though it proved nothing.
    assert evidence["observed_block"] == int(fixture["response"]["result"][0]["number"], 16)


@pytest.mark.asyncio
async def test_hunter_result_for_a_measured_sellable_token_keeps_its_block():
    fixture = load("v4_native_liquidity_launcher")
    result = await hunter_scan(fixture)
    assert result["honeypot_data"]["is_honeypot"] is False
    assert result["honeypot_data"]["simulation_block"] == 65551497
    assert (
        build_evidence(4663, fixture["token"], result, None, scanned_at=1)["observed_block"]
        == 65551497
    )


def test_explicit_honeypot_data_wins_over_the_result_key():
    scan = {
        "status": "unknown",
        "risk_level": "HIGH",
        "coverage": {"honeypot": 0.8},
        "honeypot_data": {
            "is_honeypot": True,
            "field_providers": {"is_honeypot": "eth_simulateV1"},
        },
    }
    assert verdict_for(scan) is Verdict.HONEYPOT
    assert verdict_for(scan, {"is_honeypot": False}) is Verdict.UNKNOWN


@pytest.mark.parametrize("value", [None, "text", 1, []])
def test_a_malformed_result_key_is_ignored(value):
    scan = {
        "status": "ok",
        "risk_level": "LOW",
        "coverage": {"honeypot": 1},
        "honeypot_data": value,
    }
    assert verdict_for(scan) is Verdict.LOW
    evidence = build_evidence(4663, "0x" + "ab" * 20, scan, None, scanned_at=1)
    assert "honeypot" not in evidence
    assert evidence["observed_block"] == 0


# --- AgentTools.scan_contract: one additive key ------------------------------------------------


@pytest.mark.asyncio
async def test_scan_contract_adds_only_the_honeypot_data_key():
    risk = {
        "rug_probability": 12.0,
        "risk_level": "LOW",
        "status": "ok",
        "coverage": {"honeypot": 1},
    }
    honeypot = {"is_honeypot": False, "simulation_block": 7}
    container = MagicMock()
    container.registry.run_all = AsyncMock(
        return_value=[
            AnalyzerResult(name="structural", weight=0.4, score=0, data={"is_verified": True}),
            AnalyzerResult(name="honeypot", weight=0.15, score=0, data=honeypot),
        ]
    )
    container.risk_engine.compute_from_results = MagicMock(return_value=dict(risk))
    result = await AgentTools(container).scan_contract("0x" + "ab" * 20, chain_id=4663)
    assert result == {**risk, "honeypot_data": honeypot}


@pytest.mark.asyncio
async def test_scan_contract_without_a_honeypot_analyzer_sets_the_key_to_none():
    container = MagicMock()
    container.registry.run_all = AsyncMock(return_value=[])
    container.risk_engine.compute_from_results = MagicMock(return_value={"risk_level": "LOW"})
    result = await AgentTools(container).scan_contract("0x" + "ab" * 20)
    assert result == {"risk_level": "LOW", "honeypot_data": None}


# --- BSC parity: HoneypotService output is byte-identical to the base commit ---------------------


BASE_HONEYPOT_SERVICE = Path(__file__).parent / "fixtures" / "honeypot_service_00b3c81.py.txt"


def base_honeypot_service():
    """HoneypotService as of 00b3c81, from a snapshot: CI checks out with depth 1, so git history is absent.

    The snapshot is `git show 00b3c81:services/honeypot_service.py` (blob f27e8baf76).
    """
    source = BASE_HONEYPOT_SERVICE.read_text(encoding="utf-8")
    module = types.ModuleType("base_honeypot_service")
    exec(compile(source, "base_honeypot_service.py", "exec"), module.__dict__)
    return module.HoneypotService


HONEYPOT_IS_SHAPES = [
    # honeypot.is: sellable, taxed
    (
        {"is_honeypot": False, "simulation_success": True, "reason": None},
        {"buy_tax": 1.5, "sell_tax": 2.0, "reason": None},
        None,
    ),
    # honeypot.is: proven honeypot with provider attribution
    (
        {
            "is_honeypot": True,
            "can_sell": False,
            "field_providers": {"is_honeypot": "honeypot.is"},
            "reason": "x",
        },
        {"buy_tax": 0.0, "sell_tax": 100.0},
        None,
    ),
    # honeypot.is: failed simulation, taxes from GoPlus
    (
        {
            "is_honeypot": None,
            "simulation_failed": True,
            "simulation_success": False,
            "reason": "failed",
        },
        {"buy_tax": None, "sell_tax": None, "reason": "no tax"},
        {
            "status": "ok",
            "reason": None,
            "data": {
                "is_honeypot": "0",
                "buy_tax": "0.01",
                "sell_tax": "0.02",
                "cannot_buy": "0",
                "cannot_sell_all": "0",
                "transfer_pausable": "0",
            },
        },
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("honeypot,taxes,goplus", HONEYPOT_IS_SHAPES)
async def test_bsc_honeypot_data_is_byte_identical_to_the_base_commit(honeypot, taxes, goplus):
    outputs = []
    for service_class in (base_honeypot_service(), HoneypotService):
        client = MagicMock()
        client.get_supported_chain_ids.return_value = [56]
        client.check_honeypot = AsyncMock(return_value=dict(honeypot))
        client.get_tax_info = AsyncMock(return_value=dict(taxes))
        with patch.object(
            ScamDatabase, "fetch_token_security", new=AsyncMock(return_value=goplus or NO_GOPLUS)
        ):
            data = await service_class(client).fetch_honeypot_data("0x" + "ab" * 20, chain_id=56)
        outputs.append(json.dumps(data))
    assert outputs[0] == outputs[1]
    assert "simulation_block" not in outputs[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("block", [None, "65554454", True, 1.5])
async def test_only_an_integer_simulation_block_is_carried(block):
    client = MagicMock()
    client.get_supported_chain_ids.return_value = [4663]
    response = {
        "is_honeypot": False,
        "can_buy": True,
        "can_sell": True,
        "buy_tax": 0.0,
        "sell_tax": 0.0,
        "status": "ok",
        "reason": "ok",
        "simulation_block": block,
        "field_providers": {"is_honeypot": "eth_simulateV1"},
    }
    client.check_honeypot = AsyncMock(return_value=response)
    client.get_tax_info = AsyncMock(return_value=response)
    data = await HoneypotService(client).fetch_honeypot_data("0x" + "ab" * 20, chain_id=4663)
    assert "simulation_block" not in data
