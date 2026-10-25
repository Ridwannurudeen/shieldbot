"""BOT Chain adapter for chain-wide reads and approval scanning."""

import os
import asyncio
import logging
from typing import Dict

from adapters.evm_base import ERC20_ABI, EvmAdapter
from web3 import Web3

logger = logging.getLogger(__name__)

WBOT = '0xd5452816194a3784dba983426cce7c122f4abd30'
USDT = '0xababc7ddc03e501d190c676bf3d92ef0e6e87a3c'
V2_FACTORY = '0x117115f3b72c8d1989178089a67d0c26f8ee0aa3'

KNOWN_LOCKERS = {
    '0x82cb7cd6ad9ce3a1f1fc1821ad7dcab87c3d7663': 'BDexV2Locker',
    '0x32685b8db1559d6651fcdb8a22d11cc44d3b952b': 'BDexV3LiquidityLocker',
    '0x4807eac6fac2114153122977e8366c3dcef4a51b': 'FullRangeConvertorV2',
}

WHITELISTED_ROUTERS = {
    '0x1414ed29fdfd322c3c0a830330ed982e2d629e76': 'BDEX V2 Router02',
    '0x07032d47a1b9f8460cbee9dc17c1d3e438693929': 'BDEX V3 SwapRouter',
    '0xae6ae8630f7a888dec0b9195c85f7515d5887655': 'BDEX Universal Router',
}

KNOWN_SPENDERS = {
    '0x8366170f09a04f715a13549d616a06aed16db7c3': 'BDEX Permit2',
    '0xdac3fcff004d8a8675b94e44941a1a2e3b240090': 'BDEX V3 Position Manager',
}

ROUTER_V2_FACTORIES = {
    '0xae6ae8630f7a888dec0b9195c85f7515d5887655': V2_FACTORY,
}


class BotChainAdapter(EvmAdapter):
    """BOT Chain adapter for chain_id=677."""

    def __init__(self, rpc_url: str = None):
        rpc = rpc_url or os.getenv('BOTCHAIN_RPC_URL') or 'https://rpc.botchain.ai'
        super().__init__(
            chain_id_value=677,
            chain_name_value='BOT Chain',
            rpc_url=rpc,
            honeypot_chain_id=None,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=[('WBOT', WBOT)],
            factory_address=V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
            known_spenders=KNOWN_SPENDERS,
            router_v2_factories=ROUTER_V2_FACTORIES,
        )

    async def get_token_info(self, address: str) -> Dict:
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=ERC20_ABI,
            )
            reads = await asyncio.gather(
                self._call_with_retry(contract.functions.name().call),
                self._call_with_retry(contract.functions.symbol().call),
                self._call_with_retry(contract.functions.decimals().call),
                self._call_with_retry(contract.functions.totalSupply().call),
                return_exceptions=True,
            )
            for read in reads:
                if isinstance(read, BaseException):
                    raise read
            name, symbol, decimals, total_supply = reads
            return {
                'name': name, 'symbol': symbol,
                'decimals': decimals, 'total_supply': total_supply / (10 ** decimals),
            }
        except Exception as error:
            logger.error('[BOT Chain] Error getting token info: %s', type(error).__name__)
            return {}

    async def check_honeypot(self, address: str) -> Dict:
        return {
            'is_honeypot': None,
            'status': 'unknown',
            'reason': 'no sell simulation on BOT Chain yet',
            'field_providers': {},
        }

    async def get_tax_info(self, address: str) -> Dict:
        return {
            'buy_tax': None,
            'sell_tax': None,
            'status': 'unknown',
            'reason': 'no sell simulation on BOT Chain yet',
            'field_providers': {},
        }

    def capabilities(self) -> Dict:
        return {
            **super().capabilities(),
            'sell_simulation': 'none',
            'verification': 'blockscout',
        }
