"""Hunter findings: stored before a pair reads blocked."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from agent.hunter import Hunter
from core.database import Database

DAY = 24 * 3600


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "findings.db"))
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture(autouse=True)
def unpaced():
    with patch("agent.hunter.SCAN_INTERVAL_SECONDS", 0):
        yield


def blocked_result():
    return {
        "rug_probability": 90,
        "risk_level": "HIGH",
        "critical_flags": ["rug"],
        "status": "ok",
        "coverage": {"structural": 1, "honeypot": 1},
        "coverage_reasons": {},
    }


def make_hunter(db, ai=None):
    tools = MagicMock()
    tools.scan_contract = AsyncMock(return_value=blocked_result())
    tools.auto_watch_deployer = AsyncMock()
    return Hunter(
        tools=tools, db=db, ai_analyzer=ai or MagicMock(is_available=MagicMock(return_value=False)),
        sentinel=MagicMock(),
    )


async def watching(db, pair, chain_id):
    await db.upsert_tracked_pair(pair, token_address=pair, chain_id=chain_id, deployer="0xdeployer")
    await db._db.execute(
        "UPDATE tracked_pairs SET last_checked = ? WHERE pair_address = ?", (time.time() - DAY, pair)
    )
    await db._db.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [56, 4663])
async def test_a_recheck_stores_its_finding_before_the_pair_reads_blocked(db, chain_id):
    await watching(db, "0xpair", chain_id)
    hunter = make_hunter(db)
    seen = []
    update_status = db.update_tracked_pair_status

    async def spy(pair_address, status):
        seen.append((status, [finding["address"] for finding in await db.get_agent_findings()]))
        await update_status(pair_address, status)

    db.update_tracked_pair_status = spy

    assert await hunter._recheck_warn_contracts("sweep") == ["0xpair"]

    assert seen == [("blocked", ["0xpair"])]
    assert [row["pair_address"] for row in await db.get_tracked_pairs(status="blocked")] == ["0xpair"]
    hunter.tools.auto_watch_deployer.assert_awaited_once()
