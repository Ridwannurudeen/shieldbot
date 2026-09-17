"""Tests for core.database.Database using in-memory SQLite."""

import pytest
import pytest_asyncio
import time
from unittest.mock import AsyncMock, patch

import aiosqlite

from core.database import Database
from services.campaign_service import CampaignService


@pytest_asyncio.fixture
async def db():
    """Create an in-memory database for testing."""
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


class TestContractScores:
    @pytest.mark.asyncio
    async def test_upsert_and_get(self, db):
        await db.upsert_contract_score(
            address="0xABC123",
            chain_id=56,
            risk_score=75.5,
            risk_level="HIGH",
            archetype="honeypot",
            category_scores={"structural": 80, "market": 50},
            flags=["Honeypot detected", "Low liquidity"],
            confidence=85.0,
        )

        result = await db.get_contract_score("0xABC123", 56, max_age_seconds=60)
        assert result is not None
        assert result['risk_score'] == 75.5
        assert result['risk_level'] == "HIGH"
        assert result['archetype'] == "honeypot"
        assert result['category_scores'] == {"structural": 80, "market": 50}
        assert result['flags'] == ["Honeypot detected", "Low liquidity"]
        assert result['confidence'] == 85.0
        assert result['scan_count'] == 1
        assert result['cached'] is True

    @pytest.mark.asyncio
    async def test_upsert_increments_scan_count(self, db):
        await db.upsert_contract_score("0xABC", 56, 50.0, "MEDIUM")
        await db.upsert_contract_score("0xABC", 56, 60.0, "HIGH")

        result = await db.get_contract_score("0xABC", 56, max_age_seconds=60)
        assert result['scan_count'] == 2
        assert result['risk_score'] == 60.0  # Updated

    @pytest.mark.asyncio
    async def test_get_returns_none_when_stale(self, db):
        await db.upsert_contract_score("0xOLD", 56, 50.0, "MEDIUM")
        assert await db.get_contract_score("0xOLD", 56, max_age_seconds=300) is not None

        # Back-date the scan past the freshness window by manipulating the DB directly
        await db._db.execute(
            "UPDATE contract_scores SET last_scanned_at = ? WHERE address = ? AND chain_id = ?",
            (time.time() - 1000, "0xold", 56),
        )
        await db._db.commit()

        result = await db.get_contract_score("0xOLD", 56, max_age_seconds=300)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_returns_none_when_missing(self, db):
        result = await db.get_contract_score("0xNONE", 56)
        assert result is None

    @pytest.mark.asyncio
    async def test_case_insensitive_address(self, db):
        await db.upsert_contract_score("0xABC", 56, 50.0, "MEDIUM")
        result = await db.get_contract_score("0xabc", 56, max_age_seconds=60)
        assert result is not None

    @pytest.mark.asyncio
    async def test_different_chains_are_separate(self, db):
        await db.upsert_contract_score("0xABC", 56, 50.0, "MEDIUM")
        await db.upsert_contract_score("0xABC", 1, 30.0, "LOW")

        bsc = await db.get_contract_score("0xABC", 56, max_age_seconds=60)
        eth = await db.get_contract_score("0xABC", 1, max_age_seconds=60)
        assert bsc['risk_score'] == 50.0
        assert eth['risk_score'] == 30.0


class TestOutcomeEvents:
    @pytest.mark.asyncio
    async def test_record_and_get(self, db):
        await db.record_outcome(
            address="0xDEF",
            chain_id=56,
            risk_score_at_scan=80.0,
            user_decision="block",
            outcome="scam",
            tx_hash="0xtxhash123",
        )

        outcomes = await db.get_outcomes("0xDEF", 56)
        assert len(outcomes) == 1
        assert outcomes[0]['user_decision'] == "block"
        assert outcomes[0]['outcome'] == "scam"
        assert outcomes[0]['tx_hash'] == "0xtxhash123"
        assert outcomes[0]['risk_score_at_scan'] == 80.0

    @pytest.mark.asyncio
    async def test_multiple_outcomes(self, db):
        for i in range(5):
            await db.record_outcome(
                address="0xMULTI",
                user_decision="proceed",
            )

        outcomes = await db.get_outcomes("0xMULTI")
        assert len(outcomes) == 5

    @pytest.mark.asyncio
    async def test_outcome_limit(self, db):
        for i in range(10):
            await db.record_outcome(address="0xMANY", user_decision="proceed")

        outcomes = await db.get_outcomes("0xMANY", limit=3)
        assert len(outcomes) == 3


LEGACY_FUNDER_SCHEMA = """
    CREATE TABLE funder_links (
        deployer_address TEXT NOT NULL,
        chain_id INTEGER NOT NULL,
        funder_address TEXT NOT NULL,
        funding_value_wei INTEGER DEFAULT 0,
        indexed_at REAL NOT NULL,
        PRIMARY KEY (deployer_address, chain_id)
    );
    CREATE INDEX idx_funder_address ON funder_links(funder_address);
"""


class TestFundingValueStorage:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", [0, 2**63 - 1, 2**63, 2**256 - 1])
    async def test_decimal_round_trip_and_campaign_reads(self, db, value):
        await db._db.execute(
            "INSERT INTO funder_links VALUES (?, ?, ?, ?, ?)",
            ("0xdeployer", 4663, "0xfunder", str(value), 123.5),
        )
        await db._db.commit()

        cursor = await db._db.execute(
            "SELECT funding_value_wei, typeof(funding_value_wei) FROM funder_links"
        )
        assert await cursor.fetchone() == (str(value), "text")
        graph = await db.get_campaign_graph("0xdeployer", 4663)
        assert graph["funder_value_wei"] == str(value)
        campaign = await CampaignService(None, db).get_entity_graph("0xdeployer")
        assert campaign["funder_value_wei"] == str(value)
        assert campaign["funder_cluster"][0]["funding_value_wei"] == str(value)

    @pytest.mark.asyncio
    async def test_migrate_integer_rows_in_wal_and_initialize_twice(self, tmp_path):
        path = (tmp_path / "legacy.sqlite").as_posix()
        rows = [
            (7, "0xzero", 56, "0xfunder", 0, 123.5),
            (19, "0xmax", 4663, "0xfunder", 2**63 - 1, 234.5),
            (25, "0xnull", 8453, "0xfunder", None, 345.5),
        ]
        async with aiosqlite.connect(path) as reader:
            await reader.execute("PRAGMA journal_mode=WAL")
            await reader.executescript(LEGACY_FUNDER_SCHEMA)
            await reader.execute(
                "CREATE INDEX idx_funder_chain ON funder_links(chain_id, indexed_at)"
            )
            await reader.executescript("""
                CREATE TABLE funding_audit (deployer_address TEXT);
                CREATE TRIGGER funding_insert AFTER INSERT ON funder_links
                BEGIN
                    INSERT INTO funding_audit VALUES (NEW.deployer_address);
                END;
            """)
            await reader.executemany(
                "INSERT INTO funder_links (rowid, deployer_address, chain_id, "
                "funder_address, funding_value_wei, indexed_at) VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
            await reader.commit()
            cursor = await reader.execute(
                "SELECT name, sql FROM sqlite_master WHERE tbl_name = 'funder_links' "
                "AND type IN ('index', 'trigger') ORDER BY name"
            )
            schema_objects = await cursor.fetchall()
            await reader.execute("BEGIN")
            cursor = await reader.execute("SELECT rowid, * FROM funder_links ORDER BY rowid")
            assert await cursor.fetchall() == rows

            database = Database(path)
            try:
                await database.initialize()
                cursor = await database._db.execute(
                    "PRAGMA table_info(funder_links)"
                )
                columns = await cursor.fetchall()
                assert columns[3][2] == "TEXT"
                cursor = await database._db.execute(
                    "SELECT rowid, * FROM funder_links ORDER BY rowid"
                )
                expected = [
                    (*row[:4], str(row[4]) if row[4] is not None else None, row[5])
                    for row in rows
                ]
                assert await cursor.fetchall() == expected
                cursor = await database._db.execute(
                    "SELECT name, sql FROM sqlite_master WHERE tbl_name = 'funder_links' "
                    "AND type IN ('index', 'trigger') ORDER BY name"
                )
                assert await cursor.fetchall() == schema_objects
                cursor = await database._db.execute("SELECT COUNT(*) FROM funding_audit")
                assert await cursor.fetchone() == (len(rows),)

                cursor = await reader.execute("SELECT rowid, * FROM funder_links ORDER BY rowid")
                assert await cursor.fetchall() == rows
                await reader.commit()
                cursor = await reader.execute("SELECT rowid, * FROM funder_links ORDER BY rowid")
                assert await cursor.fetchall() == expected

                with pytest.raises(aiosqlite.IntegrityError):
                    await database._db.execute(
                        "INSERT INTO funder_links VALUES (?, ?, ?, ?, ?)",
                        ("0xzero", 56, "0xother", "1", 500),
                    )
                await database._db.rollback()
                with pytest.raises(aiosqlite.IntegrityError):
                    await database._db.execute(
                        "INSERT INTO funder_links VALUES (?, ?, ?, ?, ?)",
                        ("0xmissing", 56, None, "1", 500),
                    )
                await database._db.rollback()
                cursor = await database._db.execute("PRAGMA schema_version")
                schema_version = await cursor.fetchone()
                await database.close()
                await database.initialize()
                cursor = await database._db.execute("PRAGMA schema_version")
                assert await cursor.fetchone() == schema_version
                cursor = await database._db.execute(
                    "SELECT rowid, * FROM funder_links ORDER BY rowid"
                )
                assert await cursor.fetchall() == expected
                await database._db.execute(
                    "INSERT INTO funder_links (deployer_address, chain_id, funder_address, indexed_at) "
                    "VALUES ('0xdefault', 56, '0xfunder', 500)"
                )
                cursor = await database._db.execute(
                    "SELECT funding_value_wei, typeof(funding_value_wei) FROM funder_links "
                    "WHERE deployer_address = '0xdefault'"
                )
                assert await cursor.fetchone() == ("0", "text")
                cursor = await database._db.execute("SELECT COUNT(*) FROM funding_audit")
                assert await cursor.fetchone() == (len(rows) + 1,)
            finally:
                await database.close()

    @pytest.mark.asyncio
    async def test_failed_migration_rolls_back_table_and_rows(self, db):
        await db._db.execute("DROP TABLE funder_links")
        await db._db.executescript(LEGACY_FUNDER_SCHEMA)
        await db._db.execute(
            "INSERT INTO funder_links VALUES ('0xdeployer', 56, '0xfunder', 123, 500)"
        )
        await db._db.commit()
        execute = db._db.execute

        async def fail_rename(sql, parameters=None):
            if "RENAME TO funder_links" in sql:
                raise aiosqlite.OperationalError("injected migration failure")
            return await execute(sql, parameters)

        with patch.object(db._db, "execute", AsyncMock(side_effect=fail_rename)):
            with pytest.raises(aiosqlite.OperationalError, match="injected migration failure"):
                await db._create_tables()

        cursor = await db._db.execute("PRAGMA table_info(funder_links)")
        assert (await cursor.fetchall())[3][2] == "INTEGER"
        cursor = await db._db.execute("SELECT * FROM funder_links")
        assert await cursor.fetchall() == [("0xdeployer", 56, "0xfunder", 123, 500.0)]
        cursor = await db._db.execute(
            "SELECT name FROM sqlite_master WHERE name = 'funder_links_new'"
        )
        assert await cursor.fetchall() == []
        assert db._db.in_transaction is False

    @pytest.mark.asyncio
    async def test_migration_refuses_lossy_real_values(self, db):
        await db._db.execute("DROP TABLE funder_links")
        await db._db.executescript(LEGACY_FUNDER_SCHEMA)
        await db._db.execute(
            "INSERT INTO funder_links VALUES (?, ?, ?, ?, ?)",
            ("0xdeployer", 56, "0xfunder", str(2**256 - 1), 500),
        )
        await db._db.commit()
        cursor = await db._db.execute("SELECT funding_value_wei FROM funder_links")
        original = await cursor.fetchone()

        with pytest.raises(ValueError, match="lossless"):
            await db._create_tables()

        cursor = await db._db.execute("PRAGMA table_info(funder_links)")
        assert (await cursor.fetchall())[3][2] == "INTEGER"
        cursor = await db._db.execute("SELECT funding_value_wei FROM funder_links")
        assert await cursor.fetchone() == original
        assert db._db.in_transaction is False


class TestContractScoreCoverage:
    @pytest.mark.asyncio
    async def test_scan_metadata_round_trips_to_top_level(self, db):
        metadata = {
            "status": "unknown", "coverage": {"honeypot": 0},
            "coverage_reasons": {"honeypot": "Simulation failed"},
        }
        await db.upsert_contract_score(
            "0xUNKNOWN", 4663, 0.0, "UNKNOWN",
            category_scores={"honeypot": None, "_scan_metadata": metadata},
        )

        cached = await db.get_contract_score("0xUNKNOWN", 4663, max_age_seconds=60)
        scored = await db.get_all_scored_contracts(min_risk_score=0)

        for row in (cached, scored[0]):
            assert {key: row[key] for key in metadata} == metadata
            assert row["category_scores"]["_scan_metadata"] == metadata

    @pytest.mark.asyncio
    @pytest.mark.parametrize("category_scores", [{"honeypot": 0}, None])
    async def test_score_without_metadata_is_unknown(self, db, category_scores):
        await db.upsert_contract_score("0xLEGACY", 56, 0.0, "LOW", category_scores=category_scores)

        cached = await db.get_contract_score("0xLEGACY", 56, max_age_seconds=60)
        scored = await db.get_all_scored_contracts(min_risk_score=0)

        for row in (cached, scored[0]):
            assert row["status"] == "unknown"
            assert row["coverage_reasons"] == {"coverage": "Score predates coverage tracking"}
            assert row["category_scores"] == (category_scores or {})
