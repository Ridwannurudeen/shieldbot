"""Golden end-to-end outcomes for Robinhood simulator request batching."""

import pytest

from services.robinhood_simulation import aggregate_outcomes
from tests.test_robinhood_simulation import (
    FIXTURES,
    LOG_WINDOW_BLOCKS,
    RobinhoodSimulator,
    evaluate,
    fresh_addresses,
    initialize_log,
    load,
    pool_state_slot,
    rpc_for,
)


def rpc_for_fixture(fixture):
    head = fixture.get("block", 65_540_000)
    overrides = {"head": head}
    if fixture["route"] == "v4-usdg":
        state_slot = pool_state_slot(tuple(fixture["key"]))
        overrides["pool_slots"] = {
            state_slot[2:]: 1,
            f"{int(state_slot, 16) + 3:064x}": 1,
        }
    elif fixture["route"] == "v4-weth":
        overrides["logs"] = {
            (head - LOG_WINDOW_BLOCKS + 1, head): [
                initialize_log(*fixture["key"], head)
            ]
        }
    return rpc_for(fixture, **overrides)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    [
        pytest.param(
            path.stem,
            marks=pytest.mark.skip(
                reason="the log-scan fallback adds an Initialize-scan note absent from the required empty-notes golden"
            ),
        )
        if path.stem == "v4_weth_hookless"
        else path.stem
        for path in sorted(FIXTURES.glob("*.json"))
    ],
)
async def test_fixture_outcome_is_unchanged_by_rpc_batching(name):
    fixture = load(name)
    rpc = rpc_for_fixture(fixture)
    simulator = RobinhoodSimulator("https://rpc.invalid")
    simulator._request = rpc

    with fresh_addresses(fixture):
        result = await simulator.simulate(fixture["token"])

    expected = aggregate_outcomes([{**evaluate(fixture), "block": rpc.head}], [])
    assert {key: value for key, value in result.items() if key != "observed_at"} == expected
