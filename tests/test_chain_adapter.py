"""Tests for ChainAdapter interface and BscAdapter."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from adapters.bsc import BscAdapter, WHITELISTED_ROUTERS, KNOWN_LOCKERS


class TestBscAdapterProperties:
    def test_chain_id(self):
        adapter = BscAdapter(rpc_url="https://bsc-dataseed1.binance.org/")
        assert adapter.chain_id == 56

    def test_chain_name(self):
        adapter = BscAdapter(rpc_url="https://bsc-dataseed1.binance.org/")
        assert adapter.chain_name == "BSC"

    def test_whitelisted_routers(self):
        adapter = BscAdapter(rpc_url="https://bsc-dataseed1.binance.org/")
        routers = adapter.get_whitelisted_routers()
        assert "0x10ed43c718714eb63d5aa57b78b54704e256024e" in routers
        assert routers["0x10ed43c718714eb63d5aa57b78b54704e256024e"] == "PancakeSwap V2 Router"


class TestBscConstants:
    def test_known_lockers_has_burn_address(self):
        assert '0x0000000000000000000000000000000000000000' in KNOWN_LOCKERS

    def test_whitelisted_routers_count(self):
        assert len(WHITELISTED_ROUTERS) == 6


class TestCalldataDecoderChainId:
    def test_whitelisted_target_bsc(self):
        from utils.calldata_decoder import CalldataDecoder
        decoder = CalldataDecoder()
        result = decoder.is_whitelisted_target(
            "0x10ED43C718714eb63d5aA57B78B54704E256024E", chain_id=56
        )
        assert result == "PancakeSwap V2 Router"

    def test_whitelisted_target_other_chain_returns_none(self):
        from utils.calldata_decoder import CalldataDecoder
        decoder = CalldataDecoder()
        result = decoder.is_whitelisted_target(
            "0x10ED43C718714eb63d5aA57B78B54704E256024E", chain_id=1
        )
        assert result is None

    def test_whitelisted_target_default_chain_id(self):
        from utils.calldata_decoder import CalldataDecoder
        decoder = CalldataDecoder()
        # Default chain_id=56 should work
        result = decoder.is_whitelisted_target(
            "0x10ED43C718714eb63d5aA57B78B54704E256024E"
        )
        assert result == "PancakeSwap V2 Router"


class TestHoneypotProviderUnknowns:
    @pytest.mark.asyncio
    @pytest.mark.parametrize('method', ['check_honeypot', 'get_tax_info'])
    @pytest.mark.parametrize('failure', [404, 500, 'timeout', 'exception', 'missing'])
    async def test_provider_failure_is_unknown(self, method, failure):
        adapter = BscAdapter(rpc_url='https://example.invalid')
        response = AsyncMock()
        response.status = failure if isinstance(failure, int) else 200
        response.json.return_value = {}
        session = MagicMock()
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)
        if failure in ('timeout', 'exception'):
            error = TimeoutError('timed out') if failure == 'timeout' else RuntimeError('boom')
            session.get.side_effect = error
        with patch('adapters.evm_base.aiohttp.ClientSession') as client:
            client.return_value.__aenter__.return_value = session
            result = await getattr(adapter, method)('0xABC')
        assert result['status'] == 'unknown'
        assert result['reason']
        fields = ('is_honeypot',) if method == 'check_honeypot' else ('buy_tax', 'sell_tax')
        assert all(result[field] is None for field in fields)

    @pytest.mark.asyncio
    @pytest.mark.parametrize('method', ['check_honeypot', 'get_tax_info'])
    async def test_unsupported_provider_makes_no_request(self, method):
        adapter = BscAdapter(rpc_url='https://example.invalid')
        adapter._honeypot_chain_id = None
        with patch('adapters.evm_base.aiohttp.ClientSession') as client:
            result = await getattr(adapter, method)('0xABC')
        client.assert_not_called()
        assert result['status'] == 'unknown'
        assert 'unsupported' in result['reason'].lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize('method', ['check_honeypot', 'get_tax_info'])
    async def test_failed_simulation_is_unknown(self, method):
        adapter = BscAdapter(rpc_url='https://example.invalid')
        response = AsyncMock()
        response.status = 200
        response.json.return_value = {
            'simulationSuccess': False,
            'honeypotResult': {'isHoneypot': False},
            'simulationResult': {'buyTax': 0, 'sellTax': 0},
        }
        session = MagicMock()
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)
        with patch('adapters.evm_base.aiohttp.ClientSession') as client:
            client.return_value.__aenter__.return_value = session
            result = await getattr(adapter, method)('0xABC')
        assert result['status'] == 'unknown'
        assert result['simulation_failed'] is True
        fields = ('is_honeypot',) if method == 'check_honeypot' else ('buy_tax', 'sell_tax')
        assert all(result[field] is None for field in fields)

    @pytest.mark.asyncio
    async def test_partial_tax_response_preserves_known_value(self):
        adapter = BscAdapter(rpc_url='https://example.invalid')
        response = AsyncMock()
        response.status = 200
        response.json.return_value = {'simulationSuccess': True, 'simulationResult': {'buyTax': 5}}
        session = MagicMock()
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)
        with patch('adapters.evm_base.aiohttp.ClientSession') as client:
            client.return_value.__aenter__.return_value = session
            result = await adapter.get_tax_info('0xABC')
        assert result['buy_tax'] == 5
        assert result['sell_tax'] is None
        assert result['status'] == 'unknown'
        assert result['field_providers'] == {'buy_tax': 'honeypot.is'}


    @pytest.mark.asyncio
    async def test_taxes_without_simulation_success_are_unknown(self):
        adapter = BscAdapter(rpc_url='https://example.invalid')
        response = AsyncMock()
        response.status = 200
        response.json.return_value = {'simulationResult': {'buyTax': 0, 'sellTax': 0}}
        session = MagicMock()
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)
        with patch('adapters.evm_base.aiohttp.ClientSession') as client:
            client.return_value.__aenter__.return_value = session
            result = await adapter.get_tax_info('0xABC')
        assert result['status'] == 'unknown'
        assert result['buy_tax'] is None
        assert result['sell_tax'] is None


    @pytest.mark.asyncio
    @pytest.mark.parametrize('verified, expected', [(True, False), (False, True), (None, True)])
    async def test_verified_low_tax_rule_requires_actual_verification(self, verified, expected):
        adapter = BscAdapter(rpc_url='https://example.invalid')
        adapter.is_verified_contract = AsyncMock(return_value=(verified, None))
        response = AsyncMock()
        response.status = 200
        response.json.return_value = {
            'simulationSuccess': True,
            'honeypotResult': {'isHoneypot': True},
            'simulationResult': {'buyTax': 0, 'sellTax': 0},
        }
        session = MagicMock()
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)
        with patch('adapters.evm_base.aiohttp.ClientSession') as client:
            client.return_value.__aenter__.return_value = session
            result = await adapter.check_honeypot('0xABC')
        assert result['is_honeypot'] is expected
        assert result['status'] == 'ok'
        assert result['simulation_success'] is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize('value', ['', 'invalid', 'nan', 'inf', -1, True, None])
    async def test_invalid_taxes_are_unknown(self, value):
        adapter = BscAdapter(rpc_url='https://example.invalid')
        response = AsyncMock()
        response.status = 200
        response.json.return_value = {
            'simulationSuccess': True,
            'simulationResult': {'buyTax': value, 'sellTax': value},
        }
        session = MagicMock()
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)
        with patch('adapters.evm_base.aiohttp.ClientSession') as client:
            client.return_value.__aenter__.return_value = session
            result = await adapter.get_tax_info('0xABC')
        assert result['status'] == 'unknown'
        assert result['buy_tax'] is None
        assert result['sell_tax'] is None


class TestIsContract:
    ADDRESS = '0x10ED43C718714eb63d5aA57B78B54704E256024E'

    @pytest.mark.asyncio
    @pytest.mark.parametrize('code,expected', [(b'', False), (bytes.fromhex('6080'), True)])
    async def test_code_lookup_decides_contract(self, code, expected):
        adapter = BscAdapter(rpc_url='https://example.invalid')
        adapter.w3 = MagicMock()
        adapter.w3.eth.get_code.return_value = code
        assert await adapter.is_contract(self.ADDRESS) is expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize('error,attempts', [
        (RuntimeError('503 Service Unavailable'), 3),
        (ConnectionError('connection refused'), 1),
    ])
    async def test_failed_code_lookup_is_unknown(self, error, attempts):
        adapter = BscAdapter(rpc_url='https://example.invalid')
        adapter.w3 = MagicMock()
        adapter.w3.eth.get_code.side_effect = error
        with patch('adapters.evm_base.asyncio.sleep', new_callable=AsyncMock):
            assert await adapter.is_contract(self.ADDRESS) is None
        assert adapter.w3.eth.get_code.call_count == attempts
