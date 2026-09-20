"""Storage of published verdict evidence, keyed by (chain_id, subject) with history."""

import asyncio
import sqlite3
import time
from contextlib import suppress

import aiosqlite
import pytest
import pytest_asyncio

from core.database import Database

TOKEN = "0x" + "ab" * 20
OTHER = "0x" + "cd" * 20
HASH_A = "0x" + "11" * 32
HASH_B = "0x" + "22" * 32
TX_A = "0x" + "44" * 32
TX_B = "0x" + "55" * 32
REGISTRY = "0x" + "33" * 20


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


async def insert(
    db, subject=TOKEN, chain_id=4663, verdict="UNKNOWN", evidence_hash=HASH_A, **kwargs
):
    return await db.insert_verdict_evidence(
        chain_id=chain_id,
        subject=subject,
        verdict=verdict,
        evidence_hash=evidence_hash,
        canonical='{"verdict":"%s"}' % verdict,
        observed_block=kwargs.pop("observed_block", 0),
        onchain_status=kwargs.pop("onchain_status", "off"),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_never_published_subject_has_no_evidence(db):
    assert await db.get_latest_verdict_evidence(4663, TOKEN) is None


@pytest.mark.asyncio
async def test_insert_and_read_back_latest(db):
    evidence_id = await insert(
        db,
        verdict="HONEYPOT",
        observed_block=65704949,
        onchain_status="pending",
        registry=REGISTRY,
    )
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert stored["id"] == evidence_id
    assert stored["chain_id"] == 4663
    assert stored["subject"] == TOKEN
    assert stored["verdict"] == "HONEYPOT"
    assert stored["evidence_hash"] == HASH_A
    assert stored["canonical"] == '{"verdict":"HONEYPOT"}'
    assert stored["observed_block"] == 65704949
    assert stored["onchain_status"] == "pending"
    assert stored["registry"] == REGISTRY
    assert stored["tx_hash"] is None
    assert stored["onchain_error"] is None
    assert stored["created_at"] > 0


@pytest.mark.asyncio
async def test_history_is_kept_and_latest_wins(db):
    first = await insert(db, verdict="UNKNOWN", evidence_hash=HASH_A)
    second = await insert(db, verdict="HIGH", evidence_hash=HASH_B)
    assert second > first
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["id"], stored["verdict"], stored["evidence_hash"]) == (second, "HIGH", HASH_B)
    cursor = await db._db.execute(
        "SELECT verdict FROM verdict_evidence WHERE chain_id = ? AND subject = ? ORDER BY id",
        (4663, TOKEN),
    )
    assert [row[0] for row in await cursor.fetchall()] == ["UNKNOWN", "HIGH"]


@pytest.mark.asyncio
async def test_latest_is_scoped_by_chain_and_subject(db):
    await insert(db, verdict="LOW", chain_id=56)
    await insert(db, verdict="HIGH", subject=OTHER)
    assert await db.get_latest_verdict_evidence(4663, TOKEN) is None
    assert (await db.get_latest_verdict_evidence(56, TOKEN))["verdict"] == "LOW"
    assert (await db.get_latest_verdict_evidence(4663, OTHER))["verdict"] == "HIGH"


@pytest.mark.asyncio
async def test_onchain_outcome_is_recorded_against_the_evidence(db):
    sent = await insert(db, onchain_status="pending", registry=REGISTRY)
    await db.update_verdict_onchain(sent, "submitted", tx_hash="0x" + "44" * 32)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"], stored["onchain_error"]) == (
        "submitted",
        "0x" + "44" * 32,
        None,
    )

    failed = await insert(db, subject=OTHER, onchain_status="pending", registry=REGISTRY)
    await db.update_verdict_onchain(failed, "failed", onchain_error="RateCapExceeded")
    stored = await db.get_latest_verdict_evidence(4663, OTHER)
    assert (stored["onchain_status"], stored["tx_hash"], stored["onchain_error"]) == (
        "failed",
        None,
        "RateCapExceeded",
    )
    # Updating one row leaves the other untouched.
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "submitted"


@pytest.mark.asyncio
async def test_table_creation_is_idempotent_and_keeps_rows(db):
    await insert(db)
    await db._create_tables()
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["evidence_hash"] == HASH_A


# ---------------------------------------------------------------------------
# On-chain outbox: claim before send
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claim_takes_the_oldest_pending_robinhood_row(db):
    await insert(db, onchain_status="off")
    await insert(db, chain_id=56, onchain_status="pending")
    first = await insert(db, onchain_status="pending", evidence_hash=HASH_A)
    second = await insert(db, subject=OTHER, onchain_status="pending", evidence_hash=HASH_B)

    claimed = await db.claim_next_pending_verdict(4663)
    assert claimed == {
        "id": first, "subject": TOKEN, "verdict": "UNKNOWN", "evidence_hash": HASH_A, "observed_block": 0,
        "tx_hash": None, "nonce": None, "attempts": 0,
    }
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "sending"
    assert (await db.claim_next_pending_verdict(4663))["id"] == second
    assert await db.claim_next_pending_verdict(4663) is None


@pytest.mark.asyncio
async def test_tx_hash_and_nonce_are_stored_on_the_claimed_row_before_broadcast(db):
    evidence_id = await insert(db, onchain_status="pending")
    await db.claim_next_pending_verdict(4663)
    await db.set_verdict_tx_hash(evidence_id, TX_A, 7)
    assert await db.get_claimed_verdicts(4663) == [
        {"id": evidence_id, "tx_hash": TX_A, "nonce": 7, "attempts": 1},
    ]


@pytest.mark.asyncio
async def test_a_released_claim_is_pending_again_and_keeps_its_last_transaction(db):
    evidence_id = await insert(db, onchain_status="pending")
    await db.claim_next_pending_verdict(4663)
    await db.set_verdict_tx_hash(evidence_id, TX_A, 7)
    await db.release_verdict_claim(evidence_id)
    assert await db.get_claimed_verdicts(4663) == []
    claimed = await db.claim_next_pending_verdict(4663)
    assert (claimed["id"], claimed["tx_hash"], claimed["nonce"], claimed["attempts"]) == (evidence_id, TX_A, 7, 1)


@pytest.mark.asyncio
async def test_release_and_tx_hash_only_touch_claimed_rows(db):
    evidence_id = await insert(db, onchain_status="pending")
    await db.set_verdict_tx_hash(evidence_id, TX_A, 7)
    await db.release_verdict_claim(evidence_id)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == ("pending", None)


async def signed_row(db, status, subject=TOKEN, tx_hash=TX_A):
    evidence_id = await insert(db, subject=subject, onchain_status="pending")
    await db.claim_next_pending_verdict(4663)
    await db.set_verdict_tx_hash(evidence_id, tx_hash, 7)
    await db.update_verdict_onchain(evidence_id, status, tx_hash=tx_hash)
    return evidence_id


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["submitted", "unconfirmed", "failed"])
async def test_unresolved_records_are_listed_and_can_be_requeued(db, status):
    evidence_id = await signed_row(db, status)
    later = time.time() + 1
    assert await db.get_unresolved_verdicts(4663, later, limit=10) == [
        {"id": evidence_id, "tx_hash": TX_A, "nonce": 7, "attempts": 1},
    ]
    await db.requeue_verdict(evidence_id)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == ("pending", TX_A)
    assert await db.get_unresolved_verdicts(4663, later, limit=10) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["confirmed", "reverted", "off", "pending", "sending"])
async def test_resolved_or_active_records_are_never_listed_or_requeued(db, status):
    evidence_id = await signed_row(db, status)
    assert await db.get_unresolved_verdicts(4663, time.time() + 1, limit=10) == []
    await db.requeue_verdict(evidence_id)
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == status


@pytest.mark.asyncio
async def test_unresolved_listing_honours_age_limit_and_least_recently_looked_at_order(db):
    first = await signed_row(db, "submitted")
    second = await signed_row(db, "unconfirmed", subject=OTHER, tx_hash=TX_B)
    assert await db.get_unresolved_verdicts(4663, time.time() - 60, limit=10) == []
    later = time.time() + 1
    assert [r["id"] for r in await db.get_unresolved_verdicts(4663, later, limit=10)] == [first, second]
    assert [r["id"] for r in await db.get_unresolved_verdicts(4663, later, limit=1)] == [first]
    assert await db.get_unresolved_verdicts(56, later, limit=10) == []
    # A row just looked at goes to the back of the line (fixed times: Windows clocks tick every ~16 ms).
    for evidence_id, updated_at in ((first, 100.0), (second, 200.0)):
        await db._db.execute("UPDATE verdict_evidence SET updated_at = ? WHERE id = ?", (updated_at, evidence_id))
    await db.touch_verdict(first)
    assert [r["id"] for r in await db.get_unresolved_verdicts(4663, time.time() + 1, limit=10)] == [second, first]


@pytest.mark.asyncio
async def test_rows_at_the_attempt_cap_are_still_listed(db):
    evidence_id = await signed_row(db, "unconfirmed")
    for i in range(9):
        tx_hash = "0x" + f"{i:02x}" * 32
        await db.requeue_verdict(evidence_id)
        await db.claim_next_pending_verdict(4663)
        await db.set_verdict_tx_hash(evidence_id, tx_hash, 7)
        await db.update_verdict_onchain(evidence_id, "unconfirmed", tx_hash=tx_hash)
    [row] = await db.get_unresolved_verdicts(4663, time.time() + 1, limit=10)
    assert (row["id"], row["attempts"]) == (evidence_id, 10)


@pytest.mark.asyncio
async def test_every_broadcast_transaction_is_kept_with_its_bytes(db):
    evidence_id = await insert(db, onchain_status="pending")
    await db.claim_next_pending_verdict(4663)
    assert await db.set_verdict_tx_hash(evidence_id, TX_A, 7, "02aa", 112_000_000)
    # The same bytes sent again add no second transaction and no attempt.
    assert await db.set_verdict_tx_hash(evidence_id, TX_A, 7, "02aa", 112_000_000)
    assert await db.set_verdict_tx_hash(evidence_id, TX_B, 8, "02bb", 800_000_000)
    assert await db.get_verdict_transactions([evidence_id, 999]) == {
        evidence_id: [
            {"tx_hash": TX_A, "nonce": 7, "raw_tx": "02aa", "max_fee_per_gas": 112_000_000},
            {"tx_hash": TX_B, "nonce": 8, "raw_tx": "02bb", "max_fee_per_gas": 800_000_000},
        ],
        999: [],
    }
    [claimed] = await db.get_claimed_verdicts(4663)
    assert (claimed["tx_hash"], claimed["nonce"], claimed["attempts"]) == (TX_B, 8, 2)


@pytest.mark.asyncio
async def test_a_transaction_is_only_recorded_for_a_row_that_is_still_claimed(db):
    evidence_id = await insert(db, onchain_status="pending")
    assert not await db.set_verdict_tx_hash(evidence_id, TX_A, 7, "02aa")
    assert await db.get_verdict_transactions([evidence_id]) == {evidence_id: []}


@pytest.mark.asyncio
async def test_claims_can_be_listed_by_age(db):
    evidence_id = await insert(db, onchain_status="pending")
    await db.claim_next_pending_verdict(4663)
    assert await db.get_claimed_verdicts(4663, time.time() - 60) == []
    assert [row["id"] for row in await db.get_claimed_verdicts(4663, time.time() + 1)] == [evidence_id]
    assert [row["id"] for row in await db.get_claimed_verdicts(4663)] == [evidence_id]


@pytest.mark.asyncio
async def test_two_connections_never_claim_the_same_row(tmp_path):
    """Two processes sharing one SQLite file: every pending row is claimed exactly once."""
    path = str(tmp_path / "shared.db")
    first, second = Database(path), Database(path)
    await first.initialize()
    await second.initialize()
    try:
        ids = [await insert(first, subject="0x" + f"{n:040x}", onchain_status="pending") for n in range(1, 21)]
        claimed = []

        async def claimer(database):
            while (row := await database.claim_next_pending_verdict(4663)) is not None:
                claimed.append(row["id"])

        await asyncio.gather(claimer(first), claimer(second), claimer(first), claimer(second))
        assert sorted(claimed) == ids
    finally:
        await first.close()
        await second.close()


@pytest.mark.asyncio
async def test_the_claim_query_uses_the_outbox_index(db):
    cursor = await db._db.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_verdict_evidence_outbox'"
    )
    [sql] = await cursor.fetchone()
    assert "verdict_evidence(chain_id, onchain_status, id)" in " ".join(sql.split())
    cursor = await db._db.execute(
        "EXPLAIN QUERY PLAN SELECT id FROM verdict_evidence "
        "WHERE chain_id = ? AND onchain_status = 'pending' ORDER BY id LIMIT 1",
        (4663,),
    )
    plan = " ".join(row[-1] for row in await cursor.fetchall())
    assert "idx_verdict_evidence_outbox" in plan


@pytest.mark.asyncio
async def test_a_failed_transaction_insert_rolls_the_whole_record_back(tmp_path):
    """The row update and the transaction insert commit together or not at all, even if a later commit follows."""
    path = str(tmp_path / "shieldbot.db")
    database, committed = Database(path), Database(path)
    await database.initialize()
    await committed.initialize()
    try:
        evidence_id = await insert(database, onchain_status="pending")
        await database.claim_next_pending_verdict(4663)
        outbox = await database._outbox()
        execute = outbox.execute

        async def failing_insert(sql, parameters=()):
            if "INSERT OR IGNORE INTO verdict_transactions" in sql:
                raise sqlite3.OperationalError("disk I/O error")
            return await execute(sql, parameters)

        outbox.execute = failing_insert
        with pytest.raises(sqlite3.OperationalError):
            await database.set_verdict_tx_hash(evidence_id, TX_A, 7, "02aa")
        outbox.execute = execute
        # Any later write on the drain's own connection must not commit half of the failed record.
        await database.touch_verdict(evidence_id)
        [claimed] = await committed.get_claimed_verdicts(4663)
        assert (claimed["id"], claimed["tx_hash"], claimed["nonce"], claimed["attempts"]) == (
            evidence_id, None, None, 0,
        )
        assert await committed.get_verdict_transactions([evidence_id]) == {evidence_id: []}
    finally:
        await database.close()
        await committed.close()

# verdict_evidence as first created, before the outbox's nonce and attempts columns.
VERDICT_EVIDENCE_WITHOUT_OUTBOX_COLUMNS = """
    CREATE TABLE verdict_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chain_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        verdict TEXT NOT NULL,
        evidence_hash TEXT NOT NULL,
        canonical TEXT NOT NULL,
        observed_block INTEGER NOT NULL,
        created_at REAL NOT NULL,
        onchain_status TEXT NOT NULL,
        registry TEXT,
        tx_hash TEXT,
        onchain_error TEXT,
        updated_at REAL NOT NULL
    )
"""

# verdict_transactions as first created, before the signed maxFeePerGas was kept.
VERDICT_TRANSACTIONS_WITHOUT_THE_FEE = """
    CREATE TABLE verdict_transactions (
        evidence_id INTEGER NOT NULL,
        tx_hash TEXT NOT NULL,
        nonce INTEGER NOT NULL,
        raw_tx TEXT,
        created_at REAL NOT NULL,
        PRIMARY KEY (evidence_id, tx_hash)
    )
"""


@pytest.mark.asyncio
async def test_a_verdict_table_without_the_outbox_columns_is_migrated_in_place(tmp_path):
    path = str(tmp_path / "shieldbot.db")
    old = sqlite3.connect(path)
    try:
        old.execute(VERDICT_EVIDENCE_WITHOUT_OUTBOX_COLUMNS)
        old.execute(VERDICT_TRANSACTIONS_WITHOUT_THE_FEE)
        old.execute(
            "INSERT INTO verdict_transactions (evidence_id, tx_hash, nonce, raw_tx, created_at) "
            "VALUES (1, ?, 6, '02aa', 1.0)",
            (TX_B,),
        )
        old.execute(
            "INSERT INTO verdict_evidence (chain_id, subject, verdict, evidence_hash, canonical, observed_block, "
            "created_at, onchain_status, registry, updated_at) "
            "VALUES (4663, ?, 'HIGH', ?, '{}', 1, 1.0, 'pending', ?, 1.0)",
            (TOKEN, HASH_A, REGISTRY),
        )
        old.commit()
    finally:
        old.close()
    first = Database(path)
    try:
        await first.initialize()
    finally:
        await first.close()
    # A second start finds the columns in place and changes nothing.
    database = Database(path)
    try:
        await database.initialize()
        cursor = await database._db.execute("PRAGMA table_info(verdict_evidence)")
        columns = {column[1]: column[2:5] for column in await cursor.fetchall()}
        assert columns["nonce"] == ("INTEGER", 0, None)
        assert columns["attempts"] == ("INTEGER", 1, "0")
        claimed = await database.claim_next_pending_verdict(4663)
        assert (claimed["subject"], claimed["evidence_hash"], claimed["nonce"], claimed["attempts"]) == (
            TOKEN, HASH_A, None, 0,
        )
        assert await database.set_verdict_tx_hash(claimed["id"], TX_A, 7, "02aa", 112_000_000)
        [row] = await database.get_claimed_verdicts(4663)
        assert (row["tx_hash"], row["nonce"], row["attempts"]) == (TX_A, 7, 1)
        # The transaction stored before the fee column keeps its row, with an unknown fee.
        assert (await database.get_verdict_transactions([1]))[1] == [
            {"tx_hash": TX_B, "nonce": 6, "raw_tx": "02aa", "max_fee_per_gas": None},
            {"tx_hash": TX_A, "nonce": 7, "raw_tx": "02aa", "max_fee_per_gas": 112_000_000},
        ]
    finally:
        await database.close()

async def claimed_row(database):
    """A verdict claimed by the drain, ready for set_verdict_tx_hash."""
    evidence_id = await insert(database, onchain_status="pending")
    claimed = await database.claim_next_pending_verdict(4663)
    assert claimed["id"] == evidence_id
    return evidence_id


def fail_the_transaction_insert(monkeypatch, before_failing):
    """Fail the drain's INSERT on whichever connection it uses, after awaiting `before_failing`."""
    real_execute = aiosqlite.Connection.execute

    async def execute(self, sql, parameters=()):
        if "INSERT OR IGNORE INTO verdict_transactions" in sql:
            await before_failing()
            raise sqlite3.OperationalError("database is locked")
        return await real_execute(self, sql, parameters)

    monkeypatch.setattr(aiosqlite.Connection, "execute", execute)


@pytest.mark.asyncio
async def test_a_failed_drain_transaction_never_discards_another_verdict_being_stored(
    tmp_path, monkeypatch
):
    """The hunter publishes in the API process: the drain's rollback must not undo its insert."""
    database = Database(str(tmp_path / "shieldbot.db"))
    await database.initialize()
    try:
        evidence_id = await claimed_row(database)
        hunter_may_insert = asyncio.Event()

        async def let_the_hunter_insert():
            hunter_may_insert.set()
            await asyncio.sleep(0)
            await asyncio.sleep(0)

        fail_the_transaction_insert(monkeypatch, let_the_hunter_insert)

        async def drain():
            with pytest.raises(sqlite3.OperationalError):
                await database.set_verdict_tx_hash(evidence_id, TX_A, 7, "02aa", 112_000_000)

        async def hunter():
            await hunter_may_insert.wait()
            return await insert(database, subject=OTHER, onchain_status="pending")

        _, hunter_id = await asyncio.gather(drain(), hunter())
        monkeypatch.undo()
        stored = await database.get_latest_verdict_evidence(4663, OTHER)
        assert stored is not None and stored["id"] == hunter_id
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_another_verdicts_commit_never_lands_a_hash_without_its_bytes(tmp_path, monkeypatch):
    """The converse: a commit from elsewhere must not commit the drain's half-written row."""
    database = Database(str(tmp_path / "shieldbot.db"))
    await database.initialize()
    try:
        evidence_id = await claimed_row(database)
        hunter_may_run, hunter_done = asyncio.Event(), asyncio.Event()

        async def let_the_hunter_finish():
            hunter_may_run.set()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(hunter_done.wait(), 0.5)

        fail_the_transaction_insert(monkeypatch, let_the_hunter_finish)

        async def drain():
            with pytest.raises(sqlite3.OperationalError):
                await database.set_verdict_tx_hash(evidence_id, TX_A, 7, "02aa", 112_000_000)

        async def hunter():
            await hunter_may_run.wait()
            try:
                return await insert(database, subject=OTHER, onchain_status="pending")
            finally:
                hunter_done.set()

        _, hunter_id = await asyncio.gather(drain(), hunter())
        monkeypatch.undo()
        [claimed] = await database.get_claimed_verdicts(4663)
        assert (claimed["id"], claimed["tx_hash"], claimed["nonce"], claimed["attempts"]) == (
            evidence_id, None, None, 0,
        )
        assert await database.get_verdict_transactions([evidence_id]) == {evidence_id: []}
        stored = await database.get_latest_verdict_evidence(4663, OTHER)
        assert stored is not None and stored["id"] == hunter_id
    finally:
        await database.close()

@pytest.mark.asyncio
async def test_the_drains_connection_is_opened_by_the_drain_and_by_nothing_else(tmp_path):
    """A process that only publishes, like the bot, must not hold a connection it never writes on."""
    database = Database(str(tmp_path / "shieldbot.db"))
    await database.initialize()
    try:
        assert database._drain_db is None
        await insert(database, onchain_status="pending")
        assert await database.get_latest_verdict_evidence(4663, TOKEN) is not None
        assert database._drain_db is None
        assert (await database.claim_next_pending_verdict(4663)) is not None
        assert database._drain_db is not None
    finally:
        await database.close()
    assert database._drain_db is None


@pytest.mark.asyncio
async def test_closing_a_database_that_never_drained_is_safe(tmp_path):
    database = Database(str(tmp_path / "shieldbot.db"))
    await database.initialize()
    await database.close()
    assert database._drain_db is None

@pytest.mark.asyncio
async def test_a_write_after_close_never_reopens_the_drains_connection(tmp_path):
    """The lifespan can close the database under a send that is still settling; reopening it would leak a handle."""
    database = Database(str(tmp_path / "shieldbot.db"))
    await database.initialize()
    evidence_id = await insert(database, onchain_status="pending")
    await database.claim_next_pending_verdict(4663)
    await database.close()

    with pytest.raises(AttributeError):
        await database.update_verdict_onchain(evidence_id, "submitted")
    assert database._drain_db is None
