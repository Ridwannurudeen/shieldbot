import copy
from argparse import Namespace
from unittest.mock import AsyncMock, patch

import pytest

from scripts.census_4663.report import (
    NATIVE,
    WETH,
    build_report,
    parse_time,
    render_markdown,
    run,
)


TOKEN = "0x" + "11" * 20
OTHER = "0x" + "22" * 20


def census():
    return {
        "meta": {"chain_id": "4663", "v3_factory": ""},
        "blocks": [
            {"number": 1, "timestamp": 1000},
            {"number": 100, "timestamp": 4000},
        ],
        "pools": [],
        "events": [],
        "evidence": [],
    }


def pool(data, key="pair", token=TOKEN, source="v2", timestamp=1000, eth=WETH):
    data["pools"].append(
        {
            "pool_key": key,
            "token0": token,
            "token1": eth,
            "source": source,
            "timestamp": timestamp,
            "block_number": 1,
            "tx_hash": key,
            "data": {"sqrt_price_x96": 2**96},
        }
    )


def event(data, name, fields, key="pair", timestamp=1000, block=1):
    data["events"].append(
        {
            "pool_key": key,
            "name": name,
            "data": fields,
            "timestamp": timestamp,
            "block_number": block,
            "log_index": len(data["events"]),
            "ingested_at": timestamp + 65,
            "tx_hash": key,
        }
    )


def test_deduplication_young_exclusion_threshold_grid_and_missing_data():
    data = census()
    pool(data)
    pool(data, "second", source="v4")
    pool(data, "young", OTHER, timestamp=3000)
    event(data, "Sync", {"reserve0": 1, "reserve1": 5 * 10**17})
    event(data, "PairCreated", {})
    result = build_report(data)
    assert result["new_tokens"]["total"] == 2
    assert result["new_tokens"]["by_source"] == {"v4": 1, "v2": 2, "v3": 0}
    assert result["eligibility"] == {
        "swaps_threshold": 10,
        "eth_threshold": 0.5,
        "mature": 1,
        "young_excluded": 1,
        "passed": 1,
        "failed": 0,
        "unknown": 0,
        "pass_rate": 1.0,
    }
    assert len(result["threshold_grid"]) == 9
    assert result["threshold_grid"][-1]["unknown"] == 1
    assert result["discovery_latency_seconds"]["p50"] == 65
    assert "v3 not measured" in render_markdown(result)


def test_swaps_aggregate_across_pools_only_within_first_thirty_minutes():
    data = census()
    pool(data)
    pool(data, "second")
    for index in range(10):
        event(
            data,
            "Swap",
            {"amount0_out": 1},
            "pair" if index % 2 else "second",
            1000 + index,
            index + 1,
        )
    event(data, "Swap", {"amount0_in": 1}, timestamp=2801, block=30)
    token = build_report(data)["tokens"][0]
    assert token["swaps_30m"] == 10
    assert token["eligibility"] == "pass"
    assert token["buys_window"] == 10
    assert token["sells_window"] == 1


def test_v2_liquidity_uses_simultaneous_reserves_not_sum_of_peaks():
    data = census()
    pool(data)
    pool(data, "second")
    event(data, "Sync", {"reserve1": 3 * 10**17})
    event(data, "Sync", {"reserve1": 0}, block=2)
    event(data, "Sync", {"reserve1": 3 * 10**17}, "second", block=3)
    result = build_report(data)
    assert result["tokens"][0]["max_eth_liquidity_30m"] == 0.3
    assert result["eligibility"]["failed"] == 1


def test_v4_position_principal_and_removal_reprice_for_native_eth():
    data = census()
    pool(data, source="v4", eth=NATIVE)
    event(data, "Initialize", {"sqrt_price_x96": 2**96})
    fields = {
        "sender": OTHER,
        "tick_lower": -10000,
        "tick_upper": 10000,
        "salt": "0x00",
        "liquidity_delta": 2 * 10**18,
    }
    event(data, "ModifyLiquidity", fields, block=2)
    event(data, "ModifyLiquidity", {**fields, "liquidity_delta": -2 * 10**18}, block=3)
    result = build_report(data)
    assert result["tokens"][0]["max_eth_liquidity_30m"] == pytest.approx(0.786908355684)
    assert result["eligibility"]["passed"] == 1


def test_missing_liquidity_and_unobserved_v3_are_unknown():
    data = census()
    pool(data)
    assert build_report(data)["eligibility"]["unknown"] == 1
    data["pools"][0]["source"] = "v3"
    data["meta"]["v3_factory"] = OTHER
    result = build_report(data)
    assert result["eligibility"]["unknown"] == 1
    assert result["v3"].startswith("measured")


def test_candidates_only_attribute_atomic_tokens_and_histograms_count_logs():
    data = census()
    pool(data)
    pool(data, "prior", OTHER)
    data["evidence"] = [
        {
            "tx_hash": key,
            "data": {
                "to": "router",
                "emitters": ["router", token],
                "tokens": {token: {"first_transfer_mint": minted}},
                "logs": [{"address": "router", "topics": ["0x123"]}],
            },
        }
        for key, token, minted in (("pair", TOKEN, True), ("prior", OTHER, False))
    ]
    result = build_report(data)
    candidate = next(
        item
        for item in result["candidate_launch_contracts"]
        if item["address"] == "router"
    )
    assert candidate["new_tokens"] == 1
    assert candidate["topics"] == [
        {"topic0": "0x123", "count": 2, "example_tx": "pair"}
    ]
    assert result["new_tokens"]["atomic"] == result["new_tokens"]["prior"] == 1


def test_report_window_clamped_to_coverage_and_first_seen_global():
    data = census()
    pool(data)
    pool(data, "second", timestamp=3000)
    assert build_report(data, since=2000)["new_tokens"]["total"] == 0
    assert (
        build_report(data, until=999999)["window"]["until"]
        == "1970-01-01T01:06:40+00:00"
    )
    assert build_report(data, until=2000)["eligibility"]["young_excluded"] == 1
    with pytest.raises(ValueError, match="overlap"):
        build_report(data, since=5000)


@pytest.mark.parametrize("chain_id", [None, "1", "56"])
def test_wrong_or_missing_chain_rejected(chain_id):
    data = census()
    data["meta"]["chain_id"] = chain_id
    with pytest.raises(ValueError, match="4663"):
        build_report(data)


def test_report_does_not_mutate_input_and_timezone_required():
    data = census()
    pool(data)
    before = copy.deepcopy(data)
    build_report(data)
    assert data == before
    assert parse_time("1970-01-01T00:00:01Z") == 1
    with pytest.raises(ValueError, match="timezone"):
        parse_time("2026-09-13")


def test_later_pool_does_not_make_first_thirty_minutes_liquidity_unknown():
    data = census()
    pool(data)
    pool(data, "later", timestamp=3000)
    event(data, "Sync", {"reserve1": 1})
    event(data, "Swap", {"amount0_in": 2}, "later", timestamp=3001, block=30)
    token = build_report(data)["tokens"][0]
    assert token["eligibility"] == "fail"
    assert token["sells_window"] == 1
    assert token["swaps_30m"] == 0


def test_irrelevant_pool_swaps_do_not_affect_token_eligibility():
    data = census()
    pool(data)
    for index in range(10):
        event(data, "Swap", {"amount0_out": 1}, "untracked", block=index + 1)
    token = build_report(data)["tokens"][0]
    assert token["swaps_30m"] == 0
    assert token["eligibility"] == "unknown"


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {
            "sender": OTHER,
            "tick_lower": -10,
            "tick_upper": 10,
            "salt": "0x00",
            "liquidity_delta": -1,
        },
    ],
)
def test_incomplete_or_negative_v4_position_history_is_unknown(fields):
    data = census()
    pool(data, source="v4")
    event(data, "ModifyLiquidity", fields)
    token = build_report(data)["tokens"][0]
    assert token["max_eth_liquidity_30m"] is None
    assert token["eligibility"] == "unknown"


@pytest.mark.asyncio
async def test_report_command_writes_json_and_markdown(tmp_path):
    data = census()
    pool(data)
    with patch(
        "scripts.census_4663.storage.load_data", new=AsyncMock(return_value=data)
    ):
        await run(Namespace(data_dir=tmp_path, since=None, until=None))
    assert '"chain_id": 4663' in (tmp_path / "report.json").read_text(encoding="utf-8")
    assert "v3 not measured" in (tmp_path / "report.md").read_text(encoding="utf-8")


def test_missing_launch_evidence_is_unknown_not_prior():
    data = census()
    pool(data)
    data["evidence"] = [
        {
            "tx_hash": "pair",
            "data": {
                "to": None,
                "emitters": [],
                "tokens": {TOKEN: {}},
                "logs": [],
            },
        }
    ]
    assert build_report(data)["new_tokens"]["prior"] == 0
    assert build_report(data)["new_tokens"]["launch_source_unknown"] == 1


@pytest.mark.parametrize("source", ["v2", "v4"])
@pytest.mark.parametrize("threshold_wei", [10**17, 5 * 10**17, 10**18])
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_liquidity_thresholds_preserve_one_wei(source, threshold_wei, offset):
    data = census()
    pool(data, source=source)
    wei = threshold_wei + offset
    if source == "v2":
        event(data, "Sync", {"reserve1": wei})
    else:
        # Above tick 2, side-1 principal is L * (1.0001 - 1) = L / 10000.
        event(data, "Initialize", {"sqrt_price_x96": 2**97})
        event(
            data,
            "ModifyLiquidity",
            {
                "sender": OTHER,
                "tick_lower": 0,
                "tick_upper": 2,
                "salt": "0x00",
                "liquidity_delta": wei * 10000,
            },
        )
    result = build_report(data)
    expected = int(offset >= 0)
    for grid in result["threshold_grid"]:
        if grid["eth_threshold"] == threshold_wei / 10**18:
            assert grid["passed"] == expected
            assert grid["failed"] == 1 - expected
            assert grid["unknown"] == 0
    if threshold_wei == 5 * 10**17:
        assert result["eligibility"]["passed"] == expected
        assert result["tokens"][0]["eligibility"] == ("pass" if expected else "fail")


@pytest.mark.parametrize(
    "excluded",
    [
        "0x8366a39cc670b4001a1121b8f6a443a643e40951",  # PoolManager
        "0x58daec3116aae6d93017baaea7749052e8a04fa7",
        "0x8876789976decbfcbbbe364623c63652db8c0904",
        "0x000000000022d473030f116ddee9f6b43ac78ba3",
        "0x8dc178efb8111bb0973dd9d722ebeff267c98f94",
        "0xf3334192d15450cdd385c8b70e03f9a6bd9e673b",
        "0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f",
        "0x89e5db8b5aa49aa85ac63f691524311aeb649eba",
        WETH,
        TOKEN,
        "0x" + "33" * 20,  # Observed pair contract
    ],
)
def test_launch_ranking_excludes_infrastructure_tokens_and_pairs(excluded):
    data = census()
    pair = "0x" + "33" * 20
    pool(data, key=pair)
    data["evidence"] = [
        {
            "tx_hash": pair,
            "data": {
                "to": excluded,
                "emitters": [excluded, OTHER],
                "tokens": {TOKEN: {"first_transfer_mint": True}},
                "logs": [{"address": excluded, "topics": ["0x123"]}],
            },
        }
    ]
    before = copy.deepcopy(data)
    result = build_report(data)
    assert [item["address"] for item in result["candidate_launch_contracts"]] == [OTHER]
    assert excluded not in result["new_tokens_per_day"]["1970-01-01"]
    assert data == before


def test_doppler_components_form_one_deduplicated_launch_stack():
    data = census()
    hook = "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"
    airlock = "0xeb7c034704ef8dcd2d32324c1545f62fb4ad0862"
    third = "0x" + "33" * 20
    for key, token, emitters in (
        ("first", TOKEN, [hook, airlock]),
        ("second", OTHER, [hook]),
        ("third", third, [airlock]),
    ):
        pool(data, key=key, token=token)
        data["evidence"].append(
            {
                "tx_hash": key,
                "data": {
                    "to": emitters[0],
                    "emitters": emitters,
                    "tokens": {token: {"first_transfer_mint": True}},
                    "logs": [
                        {"address": address, "topics": ["0x123"]}
                        for address in emitters
                    ],
                },
            }
        )
    result = build_report(data)
    assert result["launch_sources"] == [
        {"name": "Doppler", "new_tokens": 3, "contracts": sorted([hook, airlock])}
    ]
    assert result["new_tokens_per_day"]["1970-01-01"]["Doppler"] == 3
    assert hook not in result["new_tokens_per_day"]["1970-01-01"]
    assert airlock not in result["new_tokens_per_day"]["1970-01-01"]
    assert {item["label"] for item in result["candidate_launch_contracts"]} == {
        "Doppler HookInitializer",
        "Doppler Airlock",
    }
    assert all(
        item["launch_stack"] == "Doppler"
        for item in result["candidate_launch_contracts"]
    )
    markdown = render_markdown(result)
    assert "| Doppler | 3 |" in markdown
    assert "must not be summed" in markdown
    assert (
        "https://raw.githubusercontent.com/whetstoneresearch/doppler/main/deployments.config.toml"
        in markdown
    )
