"""A trap in one Arbitrum One pool that the deepest pool's clean sell kept from deciding the token leaves the
scan unknown, even beside a complete and clean GoPlus answer: the trap is evidence, and GoPlus misses the
honeypots the simulation exists to catch."""

import pytest

from core.telegram_formatter import format_full_report
from tests.test_arbitrum_simulation import (
    _pools_answering,
    error_string,
    failed_sell,
    fresh_addresses,
    load,
)
from tests.test_own_simulation_failure import arbitrum_adapter, scan


@pytest.mark.asyncio
async def test_a_trap_cleared_by_the_deepest_pools_sell_stays_unknown_beside_a_complete_clean_goplus_answer():
    clean = load("v3_arb")
    fixture, rpc = _pools_answering(clean, failed_sell(clean, error_string("STF")))
    with fresh_addresses(fixture):
        data, analyzed, risk, extension = await scan(42161, arbitrum_adapter(rpc), fixture["token"])
    assert data["status"] == analyzed.data["status"] == risk["status"] == "unknown"
    assert risk["risk_level"] != "LOW"
    assert extension["risk_classification"] != "SAFE"
    assert data["can_sell"] is None and "can_sell" not in data["field_providers"]
    assert data["coverage"]["can_sell"] is False
    # Left unknown as any sell simulation that could not settle the token: the simulator decided neither
    # way, so the scan takes the MEDIUM floor of missing coverage, not points.
    assert data["simulation_failed"] is True
    assert analyzed.score == 0
    assert not any("suspicious" in flag for flag in analyzed.flags)
    assert risk["risk_level"] == "MEDIUM" and risk["category_scores"]["honeypot"] is None
    assert "not counted as a trap" in data["reason"]
    # GoPlus's "not a honeypot" fills the field, as after any failed simulation, and is reported unresolved.
    assert (data["is_honeypot"], data["field_providers"]["is_honeypot"]) == (False, "goplus")
    report = format_full_report(risk, {}, {}, {}, honeypot_data=analyzed.data, chain_id=42161)
    assert "Not Honeypot" not in report
    assert "\n  Unknown (" in report
    assert "Sellability: Unknown" in report


@pytest.mark.asyncio
async def test_a_trapped_deepest_pool_is_still_a_honeypot_beside_a_shallower_clean_one_and_goplus():
    clean = load("v3_arb")
    fixture, rpc = _pools_answering(failed_sell(clean, error_string("STF")), clean)
    with fresh_addresses(fixture):
        data, analyzed, risk, extension = await scan(42161, arbitrum_adapter(rpc), fixture["token"])
    assert (data["is_honeypot"], data["can_sell"]) == (True, False)
    assert data["field_providers"]["is_honeypot"] == "eth_simulateV1"
    assert data["simulation_failed"] is False
    assert "Honeypot detected" in analyzed.flags and "Cannot sell token" in analyzed.flags
    assert risk["risk_level"] != "LOW"
    assert extension["risk_classification"] != "SAFE"
