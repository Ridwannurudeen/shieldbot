"""Tests for community reports database operations."""

import pytest
import pytest_asyncio
from core.database import Database


@pytest_asyncio.fixture
async def db(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    await db.initialize()
    yield db
    await db.close()


@pytest.mark.asyncio
async def test_record_and_retrieve_report(db):
    """Record a community report and retrieve it."""
    await db.record_community_report(
        address="0x" + "a" * 40,
        chain_id=56,
        report_type="false_positive",
        reporter_id="127.0.0.1",
        reason="Token is safe, I've been trading it for months",
    )

    reports = await db.get_reports("0x" + "a" * 40, chain_id=56)
    assert len(reports) == 1
    assert reports[0]['report_type'] == "false_positive"
    assert reports[0]['reason'] == "Token is safe, I've been trading it for months"
    assert reports[0]['reporter_id'] == "127.0.0.1"


@pytest.mark.asyncio
async def test_multiple_reports_for_same_address(db):
    """Multiple reports for the same address are stored and returned."""
    for i in range(3):
        await db.record_community_report(
            address="0x" + "b" * 40,
            chain_id=56,
            report_type="scam",
            reporter_id=f"user_{i}",
            reason=f"Scam reason {i}",
        )

    reports = await db.get_reports("0x" + "b" * 40, chain_id=56)
    assert len(reports) == 3


@pytest.mark.asyncio
async def test_get_all_reports(db):
    """get_all_reports returns reports across all addresses."""
    await db.record_community_report(address="0x" + "a" * 40, chain_id=56, report_type="scam")
    await db.record_community_report(address="0x" + "b" * 40, chain_id=56, report_type="false_positive")

    all_reports = await db.get_all_reports()
    assert len(all_reports) == 2


@pytest.mark.asyncio
async def test_reports_case_insensitive(db):
    """Address lookups are case-insensitive."""
    await db.record_community_report(
        address="0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
        chain_id=56,
        report_type="false_negative",
    )

    reports = await db.get_reports(
        "0xabcdef1234567890abcdef1234567890abcdef12", chain_id=56
    )
    assert len(reports) == 1
