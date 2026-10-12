"""Contract age on Robinhood Chain from ShieldBot's own launch table.

A launchpad's creation event dates the token exactly; a pool's creation bounds its age from below and
decides the 7-day rule only when the pool is at least 7 days old. Anything else, and any failed read,
leaves the explorer (Blockscout) path as it was.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from analyzers.structural import StructuralAnalyzer
from core.analyzer import AnalysisContext
from core.database import Database
from core.risk_engine import RiskEngine
from core.telegram_formatter import format_full_report
from services.contract_service import ContractService
from utils.scam_db import ScamMatches

CHAIN = 4663
TOKEN = "0x" + "ab" * 20
RANKS = {"long": 5, "doppler": 4, "liquidity_launcher": 3, "uniswap_v4": 2, "uniswap_v2": 1}


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "launches.db"))
    await database.initialize()
    yield database
    await database.close()


async def record(db, source, days_ago, token=TOKEN, block=100):
    # An hour inside the day, so the day count cannot cross a boundary while the test runs.
    await db.upsert_discovered_launches(CHAIN, [{
        "token_address": token.lower(), "source": source, "launchpad": source,
        "source_rank": RANKS[source], "pool_id": None, "block_number": block,
        "tx_hash": "0x" + "cd" * 32, "block_timestamp": int(time.time() - days_ago * 86400 - 3600),
    }])


def scam_db(goplus_record=None):
    return MagicMock(check_address=AsyncMock(
        return_value=ScamMatches(observed_at=time.time(), goplus_record=goplus_record),
    ))


async def scan(web3, database=None, goplus_record=None):
    service = ContractService(web3, scam_db(goplus_record))
    service.db = database
    return await StructuralAnalyzer(service).analyze(
        AnalysisContext(TOKEN, CHAIN, extra={"deadline": time.monotonic() + 5}),
    )


def blockscout_answer(mock_web3_client, age_days, verified=True):
    """What the explorer path answers for this token: its true age and verification."""
    mock_web3_client.is_verified_contract = AsyncMock(return_value=(verified, None))
    mock_web3_client.get_contract_creation_info = AsyncMock(return_value={"age_days": age_days})


def same_verdict(table, explorer):
    engine = RiskEngine()
    by_table, by_explorer = engine.compute_from_results([table]), engine.compute_from_results([explorer])
    assert table.score == explorer.score
    assert [flag for flag in table.flags] == [flag for flag in explorer.flags]
    assert by_table["score_before_community_floor"] == by_explorer["score_before_community_floor"]
    assert by_table["coverage"] == by_explorer["coverage"]


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["long", "doppler", "liquidity_launcher"])
@pytest.mark.parametrize("days", [3, 40])
async def test_a_creation_event_gives_the_exact_age_without_blockscout(db, mock_web3_client, source, days):
    await record(db, source, days)
    blockscout_answer(mock_web3_client, days)

    result = await scan(mock_web3_client, db)

    mock_web3_client.get_contract_creation_info.assert_not_awaited()
    mock_web3_client.is_verified_contract.assert_not_awaited()  # Sourcify verified it
    mock_web3_client.is_sourcify_verified.assert_awaited_once_with(TOKEN, chain_id=CHAIN)
    assert result.data["contract_age_days"] == days
    assert result.data["field_providers"]["contract_age_days"] == "launch_table"
    assert result.data["status"] == "ok"
    same_verdict(result, await scan(mock_web3_client))


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["uniswap_v2", "uniswap_v4"])
async def test_an_old_pool_gives_a_lower_bound_and_no_blockscout_when_goplus_answers(db, mock_web3_client, source):
    await record(db, source, 40)
    # The token is older than its pool: 100 days, as the explorer would say.
    blockscout_answer(mock_web3_client, 100)
    mock_web3_client.is_sourcify_verified = AsyncMock(return_value=(False, None))
    goplus = {"is_open_source": "1"}

    result = await scan(mock_web3_client, db, goplus)

    mock_web3_client.get_contract_creation_info.assert_not_awaited()
    mock_web3_client.is_verified_contract.assert_not_awaited()
    assert result.data["contract_age_days"] == 40
    assert result.data["field_providers"] == {
        "contract_age_days": "launch_table_lower_bound", "is_verified": "goplus",
    }
    assert not any(flag.startswith("Contract age") for flag in result.flags)
    assert result.data["notes"][0] == (
        "Contract age: at least 40 days (a pool for it was created then; ShieldBot's launch table)"
    )
    same_verdict(result, await scan(mock_web3_client, goplus_record=goplus))


@pytest.mark.asyncio
async def test_verification_goes_to_the_explorer_when_neither_sourcify_nor_goplus_answers(db, mock_web3_client):
    await record(db, "doppler", 40)
    blockscout_answer(mock_web3_client, 40, verified=False)
    mock_web3_client.is_sourcify_verified = AsyncMock(return_value=(False, None))

    result = await scan(mock_web3_client, db)

    mock_web3_client.is_verified_contract.assert_awaited_once_with(TOKEN, chain_id=CHAIN)
    mock_web3_client.get_contract_creation_info.assert_not_awaited()
    assert (result.data["is_verified"], result.data["contract_age_days"]) == (False, 40)
    same_verdict(result, await scan(mock_web3_client))


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["uniswap_v2", "uniswap_v4"])
async def test_a_young_pool_leaves_the_age_to_blockscout(db, mock_web3_client, source):
    await record(db, source, 3)
    # Created 30 days before its pool: only the explorer can say so.
    blockscout_answer(mock_web3_client, 33)

    result = await scan(mock_web3_client, db)

    mock_web3_client.get_contract_creation_info.assert_awaited_once()
    mock_web3_client.is_sourcify_verified.assert_not_awaited()
    assert result.data["contract_age_days"] == 33
    assert "field_providers" not in result.data
    same_verdict(result, await scan(mock_web3_client))


@pytest.mark.asyncio
async def test_a_token_missing_from_the_table_uses_blockscout(db, mock_web3_client):
    await record(db, "doppler", 3, token="0x" + "12" * 20)
    blockscout_answer(mock_web3_client, 3)

    result = await scan(mock_web3_client, db)

    mock_web3_client.get_contract_creation_info.assert_awaited_once()
    mock_web3_client.is_verified_contract.assert_awaited_once()
    assert result.data["contract_age_days"] == 3
    assert "field_providers" not in result.data


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["error", "slow"])
async def test_a_failed_table_read_uses_blockscout(mock_web3_client, failure):
    async def slow(*args):
        await asyncio.sleep(5)

    database = MagicMock(get_launch=AsyncMock(
        side_effect=RuntimeError("database is locked") if failure == "error" else slow,
    ))
    blockscout_answer(mock_web3_client, 3)

    result = await scan(mock_web3_client, database)

    database.get_launch.assert_awaited_once_with(CHAIN, TOKEN)
    mock_web3_client.get_contract_creation_info.assert_awaited_once()
    assert result.data["contract_age_days"] == 3
    assert "field_providers" not in result.data


@pytest.mark.asyncio
async def test_other_chains_never_read_the_table(mock_web3_client):
    database = MagicMock(get_launch=AsyncMock(return_value={"source": "doppler", "block_timestamp": 0}))
    service = ContractService(mock_web3_client, scam_db())
    service.db = database

    await service.fetch_contract_data(TOKEN, chain_id=56)

    database.get_launch.assert_not_awaited()
    mock_web3_client.get_contract_creation_info.assert_awaited_once()


@pytest.mark.asyncio
async def test_the_launch_row_is_read_by_its_key_with_the_earliest_block(db):
    await record(db, "uniswap_v4", 10, block=200)
    await record(db, "doppler", 12, block=100)

    launch = await db.get_launch(CHAIN, TOKEN.upper().replace("0X", "0x"))

    # The higher-ranked source labels the row; the earliest event dates it.
    assert launch["source"] == "doppler"
    assert (time.time() - launch["block_timestamp"]) // 86400 == 12
    assert await db.get_launch(CHAIN, "0x" + "99" * 20) is None
    assert await db.get_launch(1, TOKEN) is None


def test_a_lower_bound_age_is_never_shown_as_exact():
    contract = {
        "is_contract": True, "is_verified": True, "contract_age_days": 40,
        "field_providers": {"contract_age_days": "launch_table_lower_bound"},
    }
    risk = RiskEngine().compute_composite_risk(contract, {}, {}, {})
    assert "Age: at least 40 days" in format_full_report(risk, contract, {}, {}, chain_id=CHAIN)
    exact = {**contract, "field_providers": {}}
    assert "Age: 40 days" in format_full_report(risk, exact, {}, {}, chain_id=CHAIN)
