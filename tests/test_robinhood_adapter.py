"""Robinhood adapter configuration and container routing tests."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from adapters.evm_base import RPC_REQUEST_TIMEOUT_SECONDS
from core.config import Settings


def test_robinhood_adapter_configuration():
    from adapters import RobinhoodAdapter
    from adapters.robinhood import PERMIT2_ADDRESS, POOL_MANAGER_ADDRESS

    with patch('adapters.evm_base.Web3'):
        adapter = RobinhoodAdapter()

    assert adapter.chain_id == 4663
    assert adapter.chain_name == 'Robinhood Chain'
    assert adapter.etherscan_api_key == ''
    assert adapter._factory_address == '0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f'
    assert adapter._quote_tokens == [('WETH', '0x0bd7d308f8e1639fab988df18a8011f41eacad73')]
    routers = adapter.get_whitelisted_routers()
    assert set(routers) == {
        '0x89e5db8b5aa49aa85ac63f691524311aeb649eba',
        '0x8876789976decbfcbbbe364623c63652db8c0904',
        '0x204faca1764b154221e35c0d20abb3c525710498',
        '0x57fc55f719df19b4b90a03f9d78e1177d002e504',
        '0xe28c0e44f4016b073db20cf28971cac6ce3664d3',
        '0x13f4ea83d0bd40e75c8222255bc855a974568dd4',
        '0x1b81d678ffb9c0263b24a97847620c99d213eb14',
    }
    assert PERMIT2_ADDRESS.lower() not in routers
    assert POOL_MANAGER_ADDRESS.lower() not in routers
    assert set(adapter._known_lockers) == {
        '0x0000000000000000000000000000000000000000',
        '0x000000000000000000000000000000000000dead',
    }


def test_robinhood_passes_unsupported_honeypot_provider():
    from adapters.robinhood import RobinhoodAdapter

    with patch('adapters.evm_base.EvmAdapter.__init__', return_value=None) as init:
        RobinhoodAdapter()

    assert init.call_args.kwargs['honeypot_chain_id'] is None
    assert not init.call_args.kwargs.get('etherscan_api_key')


@pytest.mark.parametrize('rpc_url,env_url,expected', [
    (None, None, 'https://rpc.mainnet.chain.robinhood.com'),
    (None, '', 'https://rpc.mainnet.chain.robinhood.com'),
    (None, 'https://env.example', 'https://env.example'),
    ('https://setting.example', 'https://env.example', 'https://setting.example'),
])
def test_robinhood_rpc_precedence(monkeypatch, rpc_url, env_url, expected):
    from adapters.robinhood import RobinhoodAdapter

    if env_url is None:
        monkeypatch.delenv('ROBINHOOD_RPC_URL', raising=False)
    else:
        monkeypatch.setenv('ROBINHOOD_RPC_URL', env_url)
    with patch('adapters.evm_base.Web3') as web3:
        RobinhoodAdapter(rpc_url=rpc_url)

    web3.HTTPProvider.assert_called_once_with(
        expected, request_kwargs={'timeout': RPC_REQUEST_TIMEOUT_SECONDS},
    )


@pytest.mark.parametrize('read_rpc_url,env_url,expected', [
    (None, None, 'https://rpc.mainnet.chain.robinhood.com'),
    (None, '', 'https://rpc.mainnet.chain.robinhood.com'),
    (None, 'https://read-env.example', 'https://read-env.example'),
    ('https://read-setting.example', 'https://read-env.example', 'https://read-setting.example'),
])
def test_robinhood_read_rpc_precedence(monkeypatch, read_rpc_url, env_url, expected):
    """The read node serves the adapter's web3 reads; the simulator keeps the full node."""
    from adapters.robinhood import RobinhoodAdapter

    monkeypatch.delenv('ROBINHOOD_RPC_URL', raising=False)
    if env_url is None:
        monkeypatch.delenv('ROBINHOOD_READ_RPC_URL', raising=False)
    else:
        monkeypatch.setenv('ROBINHOOD_READ_RPC_URL', env_url)
    with patch('adapters.evm_base.Web3') as web3:
        adapter = RobinhoodAdapter(read_rpc_url=read_rpc_url)

    web3.HTTPProvider.assert_called_once_with(
        expected, request_kwargs={'timeout': RPC_REQUEST_TIMEOUT_SECONDS},
    )
    assert adapter._simulator._rpc_url == 'https://rpc.mainnet.chain.robinhood.com'


def test_robinhood_read_rpc_settings(monkeypatch):
    monkeypatch.delenv('ROBINHOOD_READ_RPC_URL', raising=False)
    assert Settings(_env_file=None).robinhood_read_rpc_url == ''
    monkeypatch.setenv('ROBINHOOD_READ_RPC_URL', 'https://read.example')
    assert Settings(_env_file=None).robinhood_read_rpc_url == 'https://read.example'


def test_container_splits_robinhood_reads_from_settings():
    from core.container import ServiceContainer

    with patch('core.container.Web3Client'), \
         patch('core.container.AIAnalyzer'), \
         patch('core.container.ScamDatabase'), \
         patch('adapters.evm_base.Web3') as web3:
        container = ServiceContainer(Settings(
            _env_file=None, robinhood_rpc_url='https://setting.example',
            robinhood_read_rpc_url='https://read.example',
        ))

    web3.HTTPProvider.assert_any_call(
        'https://read.example', request_kwargs={'timeout': RPC_REQUEST_TIMEOUT_SECONDS},
    )
    assert container.robinhood_adapter._simulator._rpc_url == 'https://setting.example'


def test_robinhood_settings(monkeypatch):
    monkeypatch.delenv('ROBINHOOD_RPC_URL', raising=False)
    assert Settings(_env_file=None).robinhood_rpc_url == 'https://rpc.mainnet.chain.robinhood.com'
    monkeypatch.setenv('ROBINHOOD_RPC_URL', 'https://setting.example')
    assert Settings(_env_file=None).robinhood_rpc_url == 'https://setting.example'


def test_container_registers_robinhood_from_settings():
    from core.container import ServiceContainer

    with patch('core.container.Web3Client') as client, \
         patch('core.container.AIAnalyzer'), \
         patch('core.container.ScamDatabase'), \
         patch('adapters.evm_base.Web3') as web3:
        container = ServiceContainer(Settings(
            _env_file=None, robinhood_rpc_url='https://setting.example',
        ))

    client.return_value.register_adapter.assert_any_call(container.robinhood_adapter)
    assert container.robinhood_adapter.chain_id == 4663
    web3.HTTPProvider.assert_any_call(
        'https://setting.example', request_kwargs={'timeout': RPC_REQUEST_TIMEOUT_SECONDS},
    )


@pytest.mark.asyncio
async def test_container_excludes_robinhood_from_pending_monitor():
    from core.container import ServiceContainer

    container = MagicMock()
    container.web3_client.get_supported_chain_ids.return_value = [56, 204, 4663]
    container.mempool_monitor.start = AsyncMock()

    await ServiceContainer.start_mempool_monitor(container)

    container.mempool_monitor.start.assert_awaited_once_with(chain_ids=[56, 204])
