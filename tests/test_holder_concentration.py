"""Top-10 holder concentration from GoPlus: one structural signal, and a note when the list is missing."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from adapters.bsc import KNOWN_LOCKERS, BscAdapter
from analyzers.structural import HOLDERS_UNKNOWN, StructuralAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.risk_engine import RiskEngine
from core.telegram_formatter import escape_markdown, format_full_report
from services.contract_service import ContractService, top_holder_share
from utils.scam_db import ScamDatabase

TOKEN = "0x1111111111111111111111111111111111111111"
DEAD = "0x000000000000000000000000000000000000dead"
PAIR = "0x2222222222222222222222222222222222222222"
POOL_MANAGER = "0x3333333333333333333333333333333333333333"
LOCKED = "0x4444444444444444444444444444444444444444"
PINKLOCK = "0x407993575c91ce7643a4d4ccacc9a98c36ee1bbe"
WHALE = "0x5555555555555555555555555555555555555555"
CONTRACT = "0x6666666666666666666666666666666666666666"
EXCLUDED = {DEAD, PINKLOCK}

# CAKE on BSC as GoPlus listed it on 2026-09-24: 93.75% burned to 0x...dead, the rest spread thin.
CAKE_HOLDERS = [
    {"address": DEAD, "is_contract": 0, "percent": "0.937532374288254027", "is_locked": 1},
    {
        "address": "0xf977814e90da44bfa03b6295a0616a897441acec",
        "is_contract": 0,
        "percent": "0.014658813647925620",
        "is_locked": 0,
    },
    {
        "address": "0x5a52e96bacdabb82fd05763e25335261b270efcb",
        "is_contract": 0,
        "percent": "0.007300020060787805",
        "is_locked": 0,
    },
    {
        "address": "0x45c54210128a065de780c4b0df3d16664f7f859e",
        "is_contract": 1,
        "percent": "0.002489556269661266",
        "is_locked": 0,
    },
    {
        "address": "0x86ac3974e2bd0d60825230fa6f355ff11409df5c",
        "is_contract": 1,
        "percent": "0.002274591179335482",
        "is_locked": 0,
    },
    {
        "address": "0xb274202daba6ae180c665b4fbe59857b7c3a8091",
        "is_contract": 1,
        "percent": "0.001847491813010080",
        "is_locked": 0,
    },
    {
        "address": "0x73feaa1ee314f8c655e354234017be2193c9e24e",
        "is_contract": 1,
        "percent": "0.001349390461267176",
        "is_locked": 0,
    },
    {
        "address": "0x0ee833adb865377dbba5e9e53fec5f2072c0d34e",
        "is_contract": 0,
        "percent": "0.001237380785372707",
        "is_locked": 0,
    },
    {
        "address": "0x91b3927f100bb6c19e5434bfaba07d60670b98d6",
        "is_contract": 1,
        "percent": "0.000990491680771831",
        "is_locked": 0,
    },
    {
        "address": "0xd183f2bbf8b28d9fec8367cb06fe72b88778c86b",
        "is_contract": 0,
        "percent": "0.000987168586043352",
        "is_locked": 0,
    },
]


def holder(address, percent, is_locked=0, is_contract=0):
    return {
        "address": address,
        "percent": percent,
        "is_locked": is_locked,
        "is_contract": is_contract,
    }


def record(holders, dex=None):
    data = {"is_open_source": "1", "holder_count": "1000"}
    if holders is not None:
        data["holders"] = holders
    if dex is not None:
        data["dex"] = dex
    return {"status": "ok", "reason": None, "data": data}


MIXED = [
    holder(DEAD, "0.30", is_locked=1),
    holder(LOCKED, "0.10", is_locked=1),
    holder(PAIR, "0.20", is_contract=1),
    holder(POOL_MANAGER, "0.05", is_contract=1),
    holder(PINKLOCK, "0.05", is_contract=1),
    holder(WHALE, "0.20"),
    holder(CONTRACT, "0.08", is_contract=1),
]
MIXED_DEX = [
    {"name": "PancakeV2", "pair": PAIR},
    {"name": "UniswapV4", "pair": "0x" + "ab" * 32, "pool_manager": POOL_MANAGER},
]


def test_share_excludes_burn_locked_pool_and_locker_holders():
    assert top_holder_share(record(MIXED, MIXED_DEX)["data"], EXCLUDED) == 28.0


def test_a_burned_supply_leaves_a_blue_chip_spread_thin():
    assert top_holder_share(record(CAKE_HOLDERS)["data"], EXCLUDED) == 3.31


@pytest.mark.parametrize(
    "holders",
    [
        None,
        [],
        [holder(WHALE, "not a number")],
        [holder(WHALE, "1.5")],
        [holder(WHALE, "-0.1")],
        [holder(WHALE, "NaN")],
        [{"percent": "0.5"}],
        ["0x5555555555555555555555555555555555555555"],
    ],
    ids=["absent", "empty", "text", "above-one", "negative", "nan", "no-address", "not-a-dict"],
)
def test_a_missing_or_unreadable_holder_list_is_unknown_not_zero(holders):
    data = record(holders)["data"]
    if holders is None:
        data["holders"] = None
    assert top_holder_share(data, EXCLUDED) is None


def test_the_adapter_lists_its_chain_lockers():
    assert (
        BscAdapter(rpc_url="https://bsc-dataseed1.binance.org/").get_known_lockers()
        == KNOWN_LOCKERS
    )


async def _structural(mock_web3_client, goplus, is_token=True):
    mock_web3_client._get_adapter.return_value.get_known_lockers.return_value = {
        PINKLOCK: "PinkLock"
    }
    service = ContractService(mock_web3_client, ScamDatabase())
    with (
        patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock(return_value=goplus)),
        patch("services.contract_service.BSCSCAN_DELAY", 0),
    ):
        return await StructuralAnalyzer(service).analyze(
            AnalysisContext(TOKEN, chain_id=56, is_token=is_token)
        )


@pytest.mark.asyncio
async def test_contract_service_excludes_the_chain_lockers(mock_web3_client):
    structural = await _structural(mock_web3_client, record(MIXED, MIXED_DEX))
    mock_web3_client._get_adapter.assert_called_once_with(56)
    assert structural.data["top10_holder_percent"] == 28.0
    assert "top10_holder_percent" not in structural.data["coverage"]
    assert structural.data["status"] == "ok"


def _covered(name, weight):
    return AnalyzerResult(name, weight, 0, data={"status": "ok", "coverage": {"field": True}})


def _with_covered_others(structural):
    others = [_covered("market", 0.25), _covered("behavioral", 0.2), _covered("honeypot", 0.15)]
    return [replace(structural, weight=0.4), *others]


NO_RECORD = {
    "status": "unknown",
    "reason": "GoPlus has no data for this token on this chain",
    "data": {},
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "goplus, status",
    [
        (record(None), "ok"),
        (NO_RECORD, "ok"),
        ({"status": "unknown", "reason": "GoPlus HTTP 500", "data": {}}, "unknown"),
    ],
    ids=["no-holders", "no-record", "goplus-failed"],
)
async def test_a_missing_holder_list_is_named_not_a_coverage_gap(mock_web3_client, goplus, status):
    structural = await _structural(mock_web3_client, goplus)
    mock_web3_client._get_adapter.assert_not_called()
    assert structural.data["top10_holder_percent"] is None
    # Named, and it adds nothing: an add-only signal's absence cannot make a token read safer.
    assert structural.data["notes"] == [HOLDERS_UNKNOWN]
    assert HOLDERS_UNKNOWN not in structural.flags
    assert structural.score == StructuralAnalyzer(None)._compute(structural.data, {})[0]
    assert "top10_holder_percent" not in structural.data["coverage"]
    assert "Top-10" not in (structural.data.get("reason") or "")
    # Only the scam lookup's own failure leaves the verdict unknown.
    assert structural.data["status"] == status
    risk = RiskEngine().compute_from_results(_with_covered_others(structural))
    assert risk["status"] == status
    # A note is information, not a danger signal: it has its own list.
    assert risk["notes"] == [HOLDERS_UNKNOWN]
    assert HOLDERS_UNKNOWN not in risk["critical_flags"]


@pytest.mark.asyncio
async def test_the_missing_list_note_stays_out_of_the_danger_flags(mock_web3_client):
    mock_web3_client.is_verified_contract.return_value = (False, None)
    structural = await _structural(mock_web3_client, NO_RECORD)
    honeypot = AnalyzerResult(
        "honeypot",
        0.15,
        80,
        flags=["Honeypot detected", "Cannot sell token"],
        data={"is_honeypot": True, "can_sell": False, "buy_tax": 0, "sell_tax": 100},
    )
    others = [_covered("market", 0.25), _covered("behavioral", 0.2), honeypot]
    risk = RiskEngine().compute_from_results([replace(structural, weight=0.4), *others])
    assert risk["critical_flags"] == [
        "Contract not verified",
        "Honeypot detected",
        "Cannot sell token",
    ]
    assert risk["notes"] == [HOLDERS_UNKNOWN]


@pytest.mark.asyncio
async def test_a_fresh_launch_without_a_holder_list_reads_as_before_apart_from_the_note(
    mock_web3_client,
):
    mock_web3_client.is_verified_contract.return_value = (False, None)
    mock_web3_client.get_contract_creation_info.return_value = {"age_days": 0}
    mock_web3_client.get_ownership_info.return_value = {"owner": WHALE, "is_renounced": False}
    structural = await _structural(mock_web3_client, NO_RECORD)
    # _compute is the structural scoring without the holder signal, as before this branch.
    assert StructuralAnalyzer(None)._compute(structural.data, {}) == (
        structural.score,
        structural.flags,
    )
    assert structural.score == 50
    assert structural.flags == ["Contract not verified", "Contract age: 0 days"]
    assert structural.data["notes"] == [HOLDERS_UNKNOWN]
    assert set(structural.data["coverage"]) == {"is_verified", "contract_age_days"}
    assert structural.data["status"] == "ok"

    risk = RiskEngine().compute_from_results(_with_covered_others(structural))
    assert (risk["status"], risk["coverage"]["structural"]) == ("ok", 1.0)
    assert risk["rug_probability"] == 20.0
    assert risk["critical_flags"] == ["Contract not verified", "Contract age: 0 days"]
    assert risk["notes"] == [HOLDERS_UNKNOWN]


def test_the_container_less_entry_point_runs_no_analyzer_and_has_no_notes():
    assert RiskEngine().compute_composite_risk({}, {}, {}, {})["notes"] == []


@pytest.mark.asyncio
async def test_telegram_shows_notes_under_their_own_heading(mock_web3_client):
    structural = await _structural(mock_web3_client, NO_RECORD)
    risk = RiskEngine().compute_from_results(_with_covered_others(structural))
    lines = format_full_report(risk, structural.data, {}, {}, {}, address=TOKEN).splitlines()
    assert not any("Critical Flags" in line for line in lines)
    heading = lines.index("*ℹ Notes:*")
    assert lines[heading + 1] == "  • " + escape_markdown(HOLDERS_UNKNOWN)


@pytest.mark.asyncio
async def test_the_signal_does_not_apply_to_a_non_token(mock_web3_client):
    structural = await _structural(mock_web3_client, record(None), is_token=False)
    assert "top10_holder_percent" not in structural.data["coverage"]
    assert "notes" not in structural.data
    assert structural.data["status"] == "ok"


@pytest.mark.asyncio
async def test_a_safe_blue_chip_is_unchanged(mock_web3_client):
    listed = await _structural(mock_web3_client, record(CAKE_HOLDERS))
    assert listed.data["top10_holder_percent"] == 3.31
    assert listed.data["status"] == "ok"
    assert not any("holders own" in flag for flag in listed.flags)
    assert "notes" not in listed.data
    # The same token scored without the holder signal.
    assert (listed.score, listed.flags) == StructuralAnalyzer(None)._compute(listed.data, {})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "top, points",
    [("0.69", 0), ("0.70", 10), ("0.8999", 10), ("0.90", 20), ("0.995", 20)],
)
async def test_a_concentrated_token_is_raised_with_a_visible_reason(mock_web3_client, top, points):
    spread = await _structural(mock_web3_client, record([holder(WHALE, "0.05")]))
    concentrated = await _structural(
        mock_web3_client, record([holder(WHALE, top), holder(DEAD, "0.004")])
    )
    assert concentrated.score == spread.score + points
    share = round(float(top) * 100, 2)
    reason = (
        f"Top 10 holders own {share}% of supply (burn, locked, pool and locker addresses excluded)"
    )
    assert (reason in concentrated.flags) is bool(points)

    before = RiskEngine().compute_from_results(_with_covered_others(spread))
    after = RiskEngine().compute_from_results(_with_covered_others(concentrated))
    assert after["rug_probability"] == pytest.approx(before["rug_probability"] + points * 0.4)
    assert (reason in after["critical_flags"]) is bool(points)
