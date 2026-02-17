"""Tests for core.database.Database using in-memory SQLite."""

import pytest
import pytest_asyncio
import time
from core.database import Database


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

        # max_age_seconds=0 means everything is stale
        result = await db.get_contract_score("0xOLD", 56, max_age_seconds=0)
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
