"""Contract age on Robinhood Chain from ShieldBot's own launch table, used only when proven.

A launchpad's creation event (LONG, Doppler, Uniswap LiquidityLauncher) dates the token exactly, once the
receipt of the row's transaction, in the row's block, holds that event for this token: its emitter, its
topic and the token where discovery reads it. A pool (Uniswap V2 PairCreated, V4 Initialize) never calls
the token and can be made for a predicted address before it exists, so it dates nothing. Anything else,
and any failed or slow read, leaves the explorer (Blockscout) path as it was.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from adapters.robinhood import POOL_MANAGER_ADDRESS, RobinhoodAdapter
from analyzers.structural import StructuralAnalyzer
from core.analyzer import AnalysisContext
from core.database import Database
from core.risk_engine import RiskEngine
from services.contract_service import ContractService
from services.launch_discovery import SOURCES
from utils.scam_db import ScamMatches

CHAIN = 4663
TOKEN = "0x" + "ab" * 20
OTHER_TOKEN = "0x" + "12" * 20
BLOCK = 100
POOL_BLOCK = 90
CREATION_TX = "0x" + "cd" * 32
POOL_TX = "0x" + "ce" * 32
BLOCK_HASH = "0x" + "ef" * 32
RANKS = {source.name: source.rank for source in SOURCES}
SOURCE = {source.name: source for source in SOURCES}


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "launches.db"))
    await database.initialize()
    yield database
    await database.close()


async def record(db, source, days_ago, token=TOKEN, block=BLOCK, tx_hash=CREATION_TX):
    # An hour inside the day, so the day count cannot cross a boundary while the test runs.
    await db.upsert_discovered_launches(CHAIN, [{
        "token_address": token.lower(), "source": source, "launchpad": source,
        "source_rank": RANKS[source], "pool_id": None, "block_number": block,
        "tx_hash": tx_hash, "block_timestamp": int(time.time() - days_ago * 86400 - 3600),
    }])


def word(address):
    return "0x" + "0" * 24 + address[2:].lower()


def log(emitter, topics, block=BLOCK, tx_hash=CREATION_TX):
    return {
        "address": emitter, "topics": topics, "data": "0x", "blockNumber": hex(block),
        "transactionHash": tx_hash, "blockHash": BLOCK_HASH, "logIndex": "0x0", "removed": False,
    }


def creation_log(source, token=TOKEN, emitter=None):
    """A launchpad's creation event as a receipt carries it (checked live on the oldest row of each):
    LONG names the token at topics[1] and [2], Doppler at [2], LiquidityLauncher at [1]."""
    launchpad = SOURCE[source]
    other = word("0x" + "11" * 20)
    topics = {
        "long": [launchpad.topic, word(token), word(token), other],
        "doppler": [launchpad.topic, other, word(token), other],
        "liquidity_launcher": [launchpad.topic, word(token)],
    }[source]
    return log(emitter or launchpad.address, topics)


def pool_log(token=TOKEN, block=BLOCK, tx_hash=CREATION_TX):
    """A V4 Initialize naming the token: in the same transaction as every launch, and proof of nothing."""
    initialize = SOURCE["uniswap_v4"]
    return log(POOL_MANAGER_ADDRESS, [
        initialize.topic, "0x" + "77" * 32, word(token), word("0x" + "22" * 20),
    ], block, tx_hash)


def receipt(*logs, block=BLOCK):
    return {"blockNumber": hex(block), "status": "0x1", "logs": list(logs)}


def scam_db(goplus_record=None):
    return MagicMock(check_address=AsyncMock(
        return_value=ScamMatches(observed_at=time.time(), goplus_record=goplus_record),
    ))


def service_for(web3, database=None):
    service = ContractService(web3, scam_db())
    service.db = database
    return service


async def scan(service):
    return await StructuralAnalyzer(service).analyze(
        AnalysisContext(TOKEN, CHAIN, extra={"deadline": time.monotonic() + 5}),
    )


def chain(mock_web3_client, age_days, answer=None, verified=True):
    """The explorer path's answers for this token (its true age and verification) and the receipt the
    read RPC returns for the row's transaction."""
    mock_web3_client.is_verified_contract = AsyncMock(return_value=(verified, None))
    mock_web3_client.get_contract_creation_info = AsyncMock(return_value={"age_days": age_days})
    mock_web3_client.get_transaction_receipt = AsyncMock(
        side_effect=answer if callable(answer) or isinstance(answer, Exception) else None,
        return_value=answer,
    )


def same_verdict(table, explorer):
    engine = RiskEngine()
    by_table, by_explorer = engine.compute_from_results([table]), engine.compute_from_results([explorer])
    assert table.score == explorer.score
    assert table.flags == explorer.flags
    assert by_table["score_before_community_floor"] == by_explorer["score_before_community_floor"]
    assert by_table["coverage"] == by_explorer["coverage"]


def assert_explorer_dated(mock_web3_client, result, age_days):
    mock_web3_client.get_contract_creation_info.assert_awaited_once_with(TOKEN, chain_id=CHAIN)
    assert result.data["contract_age_days"] == age_days
    assert "field_providers" not in result.data


@pytest.mark.asyncio
@pytest.mark.parametrize("logs", [
    ("long", "long"),
    ("long", "doppler"),  # a LONG launch goes through Doppler: its Create proves the creation too
    ("doppler", "doppler"),
    ("liquidity_launcher", "liquidity_launcher"),
], ids=lambda pair: "-".join(pair))
@pytest.mark.parametrize("days", [3, 40])
async def test_a_proven_creation_gives_the_exact_age_without_blockscout(db, mock_web3_client, logs, days):
    source, emitted = logs
    await record(db, source, days)
    chain(mock_web3_client, days, receipt(pool_log(), creation_log(emitted)))

    result = await scan(service_for(mock_web3_client, db))

    mock_web3_client.get_transaction_receipt.assert_awaited_once_with(CREATION_TX, chain_id=CHAIN)
    mock_web3_client.get_contract_creation_info.assert_not_awaited()
    mock_web3_client.is_verified_contract.assert_not_awaited()  # Sourcify verified it
    assert result.data["contract_age_days"] == days
    assert result.data["field_providers"] == {"contract_age_days": "launch_table"}
    assert result.data["status"] == "ok"
    same_verdict(result, await scan(service_for(mock_web3_client)))


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["uniswap_v2", "uniswap_v4"])
@pytest.mark.parametrize("days", [3, 40])
async def test_a_pool_row_gives_no_age(db, mock_web3_client, source, days):
    # The pool may predate the token it names: a fresh token must keep its under-7-days flag.
    await record(db, source, days, tx_hash=POOL_TX)
    chain(mock_web3_client, 2, receipt(pool_log(tx_hash=POOL_TX)))

    result = await scan(service_for(mock_web3_client, db))

    mock_web3_client.get_transaction_receipt.assert_not_awaited()
    assert_explorer_dated(mock_web3_client, result, 2)
    assert "Contract age: 2 days" in result.flags


@pytest.mark.asyncio
async def test_a_pool_made_before_the_launch_leaves_the_creation_unproven(db, mock_web3_client):
    # The row keeps its earliest event: a pool made for the predicted address 30 days earlier. Its
    # transaction holds no creation event, so the token's real age (2 days) comes from Blockscout.
    await record(db, "doppler", 2)
    await record(db, "uniswap_v4", 32, block=POOL_BLOCK, tx_hash=POOL_TX)
    chain(mock_web3_client, 2, receipt(pool_log(block=POOL_BLOCK, tx_hash=POOL_TX), block=POOL_BLOCK))

    result = await scan(service_for(mock_web3_client, db))

    mock_web3_client.get_transaction_receipt.assert_awaited_once_with(POOL_TX, chain_id=CHAIN)
    assert_explorer_dated(mock_web3_client, result, 2)
    assert "Contract age: 2 days" in result.flags


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [
    receipt(pool_log()),
    receipt(creation_log("doppler", emitter="0x" + "99" * 20)),
    receipt(creation_log("doppler", token=OTHER_TOKEN)),
    receipt({**creation_log("doppler"), "removed": True}),
    receipt(creation_log("doppler"), block=BLOCK + 1),
    {"blockNumber": "not a number", "logs": [creation_log("doppler")]},
    None,
], ids=[
    "no-creation-log", "wrong-emitter", "another-token", "removed-log", "another-block",
    "malformed", "no-receipt",
])
async def test_an_unproven_creation_gives_no_age(db, mock_web3_client, answer):
    await record(db, "doppler", 40)
    chain(mock_web3_client, 3, answer)

    result = await scan(service_for(mock_web3_client, db))

    assert_explorer_dated(mock_web3_client, result, 3)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["error", "slow"])
async def test_a_failed_receipt_read_uses_blockscout(db, mock_web3_client, failure):
    async def slow(*args, **kwargs):
        await asyncio.sleep(5)

    await record(db, "doppler", 40)
    chain(mock_web3_client, 3, ConnectionError("read RPC down") if failure == "error" else slow)

    result = await scan(service_for(mock_web3_client, db))

    mock_web3_client.get_transaction_receipt.assert_awaited_once()
    assert_explorer_dated(mock_web3_client, result, 3)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["error", "slow"])
async def test_a_failed_table_read_uses_blockscout(mock_web3_client, failure):
    async def slow(*args):
        await asyncio.sleep(5)

    database = MagicMock(get_launch=AsyncMock(
        side_effect=RuntimeError("database is locked") if failure == "error" else slow,
    ))
    chain(mock_web3_client, 3, receipt(creation_log("doppler")))

    result = await scan(service_for(mock_web3_client, database))

    database.get_launch.assert_awaited_once_with(CHAIN, TOKEN)
    mock_web3_client.get_transaction_receipt.assert_not_awaited()
    assert_explorer_dated(mock_web3_client, result, 3)


@pytest.mark.asyncio
async def test_a_token_missing_from_the_table_uses_blockscout(db, mock_web3_client):
    await record(db, "doppler", 3, token=OTHER_TOKEN)
    chain(mock_web3_client, 3, receipt(creation_log("doppler")))

    result = await scan(service_for(mock_web3_client, db))

    mock_web3_client.get_transaction_receipt.assert_not_awaited()
    assert_explorer_dated(mock_web3_client, result, 3)


@pytest.mark.asyncio
async def test_a_proven_creation_is_cached(db, mock_web3_client):
    await record(db, "doppler", 40)
    chain(mock_web3_client, 40, receipt(creation_log("doppler")))
    service = service_for(mock_web3_client, db)
    service.db = MagicMock(get_launch=AsyncMock(side_effect=db.get_launch))

    first, second = await scan(service), await scan(service)

    assert first.data["contract_age_days"] == second.data["contract_age_days"] == 40
    service.db.get_launch.assert_awaited_once()
    mock_web3_client.get_transaction_receipt.assert_awaited_once()
    mock_web3_client.get_contract_creation_info.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_unproven_creation_is_asked_again(db, mock_web3_client):
    await record(db, "doppler", 40)
    chain(mock_web3_client, 40, ConnectionError("read RPC down"))
    service = service_for(mock_web3_client, db)

    await scan(service)
    mock_web3_client.get_transaction_receipt.side_effect = None
    mock_web3_client.get_transaction_receipt.return_value = receipt(creation_log("doppler"))
    result = await scan(service)

    assert mock_web3_client.get_transaction_receipt.await_count == 2
    assert result.data["field_providers"] == {"contract_age_days": "launch_table"}


@pytest.mark.asyncio
async def test_verification_goes_to_the_explorer_when_neither_sourcify_nor_goplus_answers(db, mock_web3_client):
    await record(db, "doppler", 40)
    chain(mock_web3_client, 40, receipt(creation_log("doppler")), verified=False)
    mock_web3_client.is_sourcify_verified = AsyncMock(return_value=(False, None))

    result = await scan(service_for(mock_web3_client, db))

    mock_web3_client.is_verified_contract.assert_awaited_once_with(TOKEN, chain_id=CHAIN)
    mock_web3_client.get_contract_creation_info.assert_not_awaited()
    assert (result.data["is_verified"], result.data["contract_age_days"]) == (False, 40)
    same_verdict(result, await scan(service_for(mock_web3_client)))


@pytest.mark.asyncio
async def test_goplus_answers_verification_without_the_explorer(db, mock_web3_client):
    await record(db, "doppler", 40)
    chain(mock_web3_client, 40, receipt(creation_log("doppler")))
    mock_web3_client.is_sourcify_verified = AsyncMock(return_value=(False, None))
    service = ContractService(mock_web3_client, scam_db({"is_open_source": "1"}))
    service.db = db

    result = await scan(service)

    mock_web3_client.is_verified_contract.assert_not_awaited()
    mock_web3_client.get_contract_creation_info.assert_not_awaited()
    assert result.data["is_verified"] is True
    assert result.data["field_providers"] == {"contract_age_days": "launch_table", "is_verified": "goplus"}


@pytest.mark.asyncio
async def test_other_chains_never_read_the_table(mock_web3_client):
    database = MagicMock(get_launch=AsyncMock())
    chain(mock_web3_client, 3, receipt(creation_log("doppler")))

    await service_for(mock_web3_client, database).fetch_contract_data(TOKEN, chain_id=56)

    database.get_launch.assert_not_awaited()
    mock_web3_client.get_transaction_receipt.assert_not_awaited()
    mock_web3_client.get_contract_creation_info.assert_awaited_once()


@pytest.mark.asyncio
async def test_the_launch_row_is_read_by_its_key_with_its_earliest_event(db):
    await record(db, "uniswap_v4", 10, block=200, tx_hash=POOL_TX)
    await record(db, "doppler", 12, block=BLOCK)

    launch = await db.get_launch(CHAIN, "0x" + "AB" * 20)

    # The higher-ranked source labels the row; the earliest event gives its block and transaction.
    assert (launch["source"], launch["block_number"], launch["tx_hash"]) == ("doppler", BLOCK, CREATION_TX)
    assert (time.time() - launch["block_timestamp"]) // 86400 == 12
    assert await db.get_launch(CHAIN, OTHER_TOKEN) is None
    assert await db.get_launch(1, TOKEN) is None


@pytest.mark.asyncio
async def test_the_receipt_is_read_from_the_read_rpc_in_one_request():
    adapter = RobinhoodAdapter("https://official.invalid", read_rpc_url="https://read.invalid")
    assert adapter.w3.provider.endpoint_uri == "https://read.invalid"
    answer = receipt(creation_log("doppler"))
    adapter.w3.provider.make_request = MagicMock(return_value={"jsonrpc": "2.0", "id": 1, "result": answer})

    assert await adapter.get_transaction_receipt(CREATION_TX) == answer
    adapter.w3.provider.make_request.assert_called_once_with("eth_getTransactionReceipt", [CREATION_TX])

    adapter.w3.provider.make_request = MagicMock(return_value={"jsonrpc": "2.0", "id": 1, "error": {"code": -32000}})
    with pytest.raises(ValueError):
        await adapter.get_transaction_receipt(CREATION_TX)
