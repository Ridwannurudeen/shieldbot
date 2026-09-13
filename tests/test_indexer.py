"""Tests for core.indexer.DeployerIndexer."""

import pytest
import pytest_asyncio
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace
from core.database import Database
from core.indexer import DeployerIndexer
from services.explorer_service import ExplorerService


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
    client._get_adapter.return_value = SimpleNamespace(chain_id=56, etherscan_api_key='test_key')
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
        web3._get_adapter.return_value = SimpleNamespace(chain_id=56, etherscan_api_key='')

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

    @pytest.mark.asyncio
    @pytest.mark.parametrize('method', ['_index_contract', '_fetch_funder'])
    @pytest.mark.parametrize('chain_id,adapter_chain', [(999999, 999999), (4663, None), (4663, 56), (56, 8453)])
    async def test_explorer_lookup_rejects_unsupported_or_wrong_adapter(self, db, method, chain_id, adapter_chain):
        web3 = MagicMock()
        web3._get_adapter.return_value = (
            SimpleNamespace(chain_id=adapter_chain, etherscan_api_key='key')
            if adapter_chain is not None else None
        )
        web3.get_contract_creation_info = AsyncMock(return_value=None)
        indexer = DeployerIndexer(web3, db)
        with patch('aiohttp.ClientSession') as session:
            with pytest.raises(ValueError):
                await getattr(indexer, method)('0xAddress', chain_id)
            session.assert_not_called()
        web3.get_contract_creation_info.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize('chain_id', [56, 8453])
    async def test_existing_chain_funder_request_unchanged(self, db, chain_id):
        web3 = MagicMock()
        web3._get_adapter.return_value = SimpleNamespace(chain_id=chain_id, etherscan_api_key='test_key')
        response = AsyncMock()
        response.status = 200
        response.json.return_value = {'status': '1', 'result': [
            {'from': '0xFunder', 'to': '0xDeployer', 'value': '123'}
        ]}
        session = MagicMock()
        session.get.return_value.__aenter__.return_value = response
        with patch('aiohttp.ClientSession') as factory:
            factory.return_value.__aenter__.return_value = session
            result = await DeployerIndexer(web3, db)._fetch_funder('0xDeployer', chain_id)
        assert result == {'funder': '0xFunder', 'value': 123}
        args, kwargs = session.get.call_args
        assert args == ('https://api.etherscan.io/v2/api',)
        assert kwargs['params'] == {
            'chainid': chain_id, 'module': 'account', 'action': 'txlist',
            'address': '0xDeployer', 'startblock': 0, 'endblock': 99999999,
            'page': 1, 'offset': 5, 'sort': 'asc', 'apikey': 'test_key',
        }
        assert kwargs['timeout'].total == 10

    @pytest.mark.asyncio
    @pytest.mark.parametrize('status,missing_value', [(500, False), (200, True)])
    async def test_etherscan_funder_missing_value_or_http_error_is_unknown(self, db, status, missing_value):
        web3 = MagicMock()
        web3._get_adapter.return_value = SimpleNamespace(chain_id=56, etherscan_api_key='test_key')
        tx = {'from': '0xFunder', 'to': '0xDeployer'}
        if not missing_value:
            tx['value'] = '123'
        response = AsyncMock()
        response.status = status
        response.json.return_value = {'status': '1', 'result': [tx]}
        session = MagicMock()
        session.get.return_value.__aenter__.return_value = response
        with patch('aiohttp.ClientSession') as factory:
            factory.return_value.__aenter__.return_value = session
            result = await DeployerIndexer(web3, db)._fetch_funder('0xDeployer', 56)
        assert result is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize('known', [True, False])
    async def test_robinhood_funder_uses_explorer_result(self, db, known, caplog):
        web3 = MagicMock()
        web3._get_adapter.return_value = SimpleNamespace(chain_id=4663)
        service = MagicMock()
        data = {'funder': '0xFunder', 'value': 123} if known else None
        service.get_first_funder = AsyncMock(return_value=SimpleNamespace(
            status='known' if known else 'unknown', data=data, reason=None if known else 'missing_key',
        ))
        with patch('core.indexer.explorer_service', service), patch('aiohttp.ClientSession') as session:
            result = await DeployerIndexer(web3, db)._fetch_funder('0xDeployer', 4663)
            session.assert_not_called()
        assert result == data
        service.get_first_funder.assert_awaited_once_with('0xDeployer', 4663)
        if not known:
            assert 'missing_key' in caplog.text

    @pytest.mark.asyncio
    @pytest.mark.parametrize('known', [True, False])
    async def test_robinhood_deployer_uses_explorer_result(self, db, known, caplog):
        web3 = MagicMock()
        web3._get_adapter.return_value = SimpleNamespace(chain_id=4663)
        web3.get_contract_creation_info = AsyncMock(return_value=None)
        service = MagicMock()
        service.get_contract_creation_info = AsyncMock(return_value=SimpleNamespace(
            status='known' if known else 'unknown',
            data={'creator': '0xDeployer', 'tx_hash': '0xTx'} if known else None,
            reason=None if known else 'missing_key',
        ))
        indexer = DeployerIndexer(web3, db)
        indexer._fetch_funder = AsyncMock(return_value=None)
        with patch('core.indexer.explorer_service', service), patch('aiohttp.ClientSession') as session:
            await indexer._index_contract('0xContract', 4663)
            session.assert_not_called()
        service.get_contract_creation_info.assert_awaited_once_with('0xContract', 4663)
        web3.get_contract_creation_info.assert_not_awaited()
        cursor = await db._db.execute('SELECT chain_id, deployer_address, deploy_tx_hash FROM deployers')
        rows = await cursor.fetchall()
        assert [tuple(row) for row in rows] == ([(4663, '0xdeployer', '0xTx')] if known else [])
        if not known:
            assert 'missing_key' in caplog.text
            indexer._fetch_funder.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize('chain_id', [56, 8453])
    async def test_existing_chain_deployer_still_uses_adapter(self, db, mock_web3, chain_id):
        mock_web3._get_adapter.return_value = SimpleNamespace(chain_id=chain_id, etherscan_api_key='test_key')
        indexer = DeployerIndexer(mock_web3, db)
        indexer._fetch_funder = AsyncMock(return_value=None)
        with patch('core.indexer.explorer_service') as service:
            await indexer._index_contract('0xContract', chain_id)
            service.get_contract_creation_info.assert_not_called()
        mock_web3.get_contract_creation_info.assert_awaited_once_with('0xContract', chain_id=chain_id)
        cursor = await db._db.execute('SELECT chain_id, deployer_address FROM deployers')
        assert [tuple(row) for row in await cursor.fetchall()] == [(chain_id, '0xdeployeraddress')]

    @pytest.mark.asyncio
    @pytest.mark.parametrize('has_key', [True, False])
    async def test_robinhood_funder_with_and_without_blockscout_key(self, db, monkeypatch, has_key):
        if has_key:
            monkeypatch.setenv('BLOCKSCOUT_API_KEY', 'test_key')
        else:
            monkeypatch.delenv('BLOCKSCOUT_API_KEY', raising=False)
        deployer = '0x' + '1' * 40
        funder = '0x' + '2' * 40
        web3 = MagicMock()
        web3._get_adapter.return_value = SimpleNamespace(chain_id=4663)
        response = AsyncMock()
        response.status = 200
        response.json.side_effect = [
            {'items': [{
                'from': {'hash': funder}, 'to': {'hash': deployer},
                'value': '123', 'status': 'ok', 'block_number': 100, 'position': 0,
            }], 'next_page_params': None},
            {'items': [], 'next_page_params': None},
        ]
        session = MagicMock()
        session.get.return_value.__aenter__.return_value = response
        with patch('core.indexer.explorer_service', ExplorerService()), patch('aiohttp.ClientSession') as factory:
            factory.return_value.__aenter__.return_value = session
            result = await DeployerIndexer(web3, db)._fetch_funder(deployer, 4663)
        if has_key:
            assert result == {'funder': funder, 'value': 123}
            assert [call.args[0] for call in session.get.call_args_list] == [
                f'https://api.blockscout.com/4663/api/v2/addresses/{deployer}/transactions',
                f'https://api.blockscout.com/4663/api/v2/addresses/{deployer}/internal-transactions',
            ]
            assert all(call.kwargs['params']['apikey'] == 'test_key' for call in session.get.call_args_list)
        else:
            assert result is None
            factory.assert_not_called()
