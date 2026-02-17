"""Tests for core.indexer.DeployerIndexer."""

import pytest
import pytest_asyncio
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from core.database import Database
from core.indexer import DeployerIndexer


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


@pytest_asyncio.fixture
async def mock_web3():
    client = MagicMock()
    client.get_contract_creation_info = AsyncMock(return_value={
        'tx_hash': '0xabc123',
        'creator': '0xDeployerAddress',
        'creation_time': '2024-01-01T00:00:00+00:00',
        'age_days': 100,
    })
    client._bsc_adapter = MagicMock()
    client._bsc_adapter.bscscan_api_key = 'test_key'
    return client


class TestDeployerIndexer:
    @pytest.mark.asyncio
    async def test_enqueue_and_process(self, db, mock_web3):
        indexer = DeployerIndexer(mock_web3, db)

        # Patch _fetch_funder to avoid real API calls
        indexer._fetch_funder = AsyncMock(return_value={
            'funder': '0xFunderAddress',
            'value': 1000000000000000000,
        })

        await indexer.start()

        # Enqueue a contract
        indexer.enqueue("0xContractAddr", 56)

        # Give worker time to process
        await asyncio.sleep(0.5)

        await indexer.stop()

        # Check deployer was stored
        cursor = await db._db.execute(
            "SELECT * FROM deployers WHERE contract_address = ?",
            ("0xcontractaddr",)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[2] == "0xdeployeraddress"  # deployer_address

        # Check funder was stored
        cursor = await db._db.execute(
            "SELECT * FROM funder_links WHERE deployer_address = ?",
            ("0xdeployeraddress",)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[2] == "0xfunderaddress"  # funder_address

    @pytest.mark.asyncio
    async def test_enqueue_no_creation_info(self, db):
        web3 = MagicMock()
        web3.get_contract_creation_info = AsyncMock(return_value=None)

        indexer = DeployerIndexer(web3, db)
        await indexer.start()

        indexer.enqueue("0xNoCreation", 56)
        await asyncio.sleep(0.5)
        await indexer.stop()

        cursor = await db._db.execute("SELECT COUNT(*) FROM deployers")
        count = (await cursor.fetchone())[0]
        assert count == 0

    @pytest.mark.asyncio
    async def test_start_stop(self, db):
        web3 = MagicMock()
        indexer = DeployerIndexer(web3, db)
        await indexer.start()
        assert indexer._running is True
        await indexer.stop()
        assert indexer._running is False
