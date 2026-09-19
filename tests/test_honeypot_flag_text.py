"""A proven can_sell=False is never flagged as sellability unknown, and unknown flags are not repeated."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from analyzers.honeypot import HoneypotAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.risk_engine import RiskEngine
from services.honeypot_service import HoneypotService
from tests.test_robinhood_simulation import (
    adapter_with,
    client_with,
    fresh_addresses,
    load,
    rpc_for,
)
from utils.scam_db import ScamDatabase


ADDRESS = "0x" + "7a" * 20
STRUCTURAL = AnalyzerResult(
    "structural",
    0.4,
    10,
    data={
        "is_contract": True,
        "is_verified": True,
        "contract_age_days": 1,
        "coverage": {"bytecode": True},
    },
)


async def _proven_honeypot():
    fixture = load("v2_honeypot_sell_reverts")
    service = HoneypotService(client_with(adapter_with(rpc_for(fixture))))
    unavailable = AsyncMock(
        return_value={"status": "unknown", "reason": "GoPlus has no data", "data": {}}
    )
    with (
        fresh_addresses(fixture),
        patch.object(ScamDatabase, "fetch_token_security", new=unavailable),
    ):
        return await HoneypotAnalyzer(service).analyze(
            AnalysisContext(fixture["token"], chain_id=4663)
        )


def _unknown_flags(flags):
    return [
        flag
        for flag in flags
        if flag.startswith(("Sellability unknown: ", "Honeypot coverage unknown: "))
    ]


@pytest.mark.asyncio
async def test_simulation_proven_honeypot_is_not_described_as_sellability_unknown():
    honeypot = await _proven_honeypot()
    assert honeypot.data["can_sell"] is False and honeypot.data["is_honeypot"] is True
    assert honeypot.data["field_providers"]["is_honeypot"] == "eth_simulateV1"
    assert honeypot.data["sell_tax"] is None

    risk = RiskEngine().compute_from_results([STRUCTURAL, honeypot])

    reason = honeypot.data["reason"]
    assert (risk["rug_probability"], risk["risk_level"], risk["risk_archetype"]) == (
        80,
        "HIGH",
        "honeypot",
    )
    assert risk["status"] == "unknown"
    assert risk["coverage"]["honeypot"] == 0.8
    assert risk["coverage_reasons"]["honeypot"] == reason
    assert (
        "Honeypot detected" in risk["critical_flags"]
        and "Cannot sell token" in risk["critical_flags"]
    )
    assert not any(flag.startswith("Sellability unknown") for flag in risk["critical_flags"])
    assert _unknown_flags(risk["critical_flags"]) == [f"Honeypot coverage unknown: {reason}"]
    assert sum(reason in flag for flag in risk["critical_flags"]) == 1


def test_known_cannot_sell_without_analyzer_flags_names_only_the_missing_coverage():
    honeypot = AnalyzerResult(
        "honeypot",
        0.15,
        100,
        flags=[],
        data={
            "is_honeypot": True,
            "can_sell": False,
            "can_buy": True,
            "buy_tax": 0.0,
            "sell_tax": None,
            "coverage": {
                "is_honeypot": True,
                "buy_tax": True,
                "sell_tax": False,
                "can_buy": True,
                "can_sell": True,
            },
            "status": "unknown",
            "reason": "sell tax unmeasured",
        },
    )

    risk = RiskEngine().compute_from_results([STRUCTURAL, honeypot])

    assert risk["status"] == "unknown"
    assert _unknown_flags(risk["critical_flags"]) == [
        "Honeypot coverage unknown: sell tax unmeasured"
    ]


@pytest.mark.parametrize("with_analyzer_flags", [True, False])
def test_unknown_sellability_is_still_flagged_once(with_analyzer_flags):
    data = {
        "is_honeypot": None,
        "can_sell": None,
        "buy_tax": None,
        "sell_tax": None,
        "status": "unknown",
        "reason": "honeypot.is is unsupported for this chain",
    }
    flags = (
        ["Sellability unknown: honeypot.is is unsupported for this chain"]
        if with_analyzer_flags
        else []
    )
    honeypot = AnalyzerResult("honeypot", 0.15, 0, flags=flags, data=data)

    risk = RiskEngine().compute_from_results([STRUCTURAL, honeypot])

    assert _unknown_flags(risk["critical_flags"]) == [
        "Sellability unknown: honeypot.is is unsupported for this chain"
    ]


@pytest.mark.asyncio
async def test_repeated_sellability_flags_with_different_reasons_collapse_to_one():
    service = MagicMock()
    service.fetch_honeypot_data = AsyncMock(
        return_value={
            "is_honeypot": False,
            "can_sell": True,
            "buy_tax": 1.0,
            "sell_tax": 2.0,
            "can_buy": True,
            "simulation_failed": True,
            "reason": "honeypot.is simulation errored",
        }
    )
    honeypot = await HoneypotAnalyzer(service).analyze(AnalysisContext(ADDRESS))
    assert "Sellability unknown: honeypot.is simulation errored" in honeypot.flags

    risk = RiskEngine().compute_from_results([STRUCTURAL, honeypot])

    assert risk["coverage_reasons"]["honeypot"] == "Honeypot simulation failed (unresolved)"
    assert _unknown_flags(risk["critical_flags"]) == [
        "Sellability unknown: honeypot.is simulation errored"
    ]
    assert len(risk["critical_flags"]) == len(set(risk["critical_flags"]))


def test_error_without_honeypot_data_is_still_sellability_unknown():
    honeypot = AnalyzerResult("honeypot", 0.15, 0, data={}, error="HoneypotAnalyzer timed out")

    risk = RiskEngine().compute_from_results([STRUCTURAL, honeypot])

    assert _unknown_flags(risk["critical_flags"]) == [
        "Sellability unknown: HoneypotAnalyzer timed out"
    ]
