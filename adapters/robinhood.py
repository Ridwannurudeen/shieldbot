"""Robinhood Chain adapter — extends shared EvmAdapter."""

import os
from typing import Dict

from adapters.evm_base import EvmAdapter

KNOWN_LOCKERS = {
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

UNISWAP_V2_FACTORY = '0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f'
UNISWAP_V2_ROUTER = '0x89e5db8b5aa49aa85ac63f691524311aeb649eba'
UNISWAP_V4_UNIVERSAL_ROUTER = '0x8876789976decbfcbbbe364623c63652db8c0904'
WETH_ADDRESS = '0x0bd7d308f8e1639fab988df18a8011f41eacad73'
PERMIT2_ADDRESS = '0x000000000022D473030F116dDEE9F6B43aC78BA3'
POOL_MANAGER_ADDRESS = '0x8366a39cc670b4001a1121b8f6a443a643e40951'

QUOTE_TOKENS = [
    ('WETH', WETH_ADDRESS),
]

WHITELISTED_ROUTERS = {
    UNISWAP_V2_ROUTER.lower(): 'Uniswap V2 Router02',
    UNISWAP_V4_UNIVERSAL_ROUTER.lower(): 'Uniswap Universal Router V2.1.1',
    '0x204FAca1764B154221e35c0d20aBb3c525710498'.lower(): 'Uniswap Universal Router V2.1.2',
    '0x57fc55F719DF19B4b90A03F9D78E1177D002E504'.lower(): 'PancakeSwap Infinity Universal Router',
    '0xE28c0e44F4016b073db20cF28971CAc6ce3664D3'.lower(): 'PancakeSwap V3 Universal Router',
    '0x13f4EA83D0bd40E75C8222255bc855a974568Dd4'.lower(): 'PancakeSwap V3 Smart Router',
    # Not in PancakeSwap's V3 table for Robinhood, but its factory(), deployer() and WETH9() read on 4663
    # (2026-09-28) are PancakeSwap's listed V3 factory 0x0BFbCF9f..., deployer 0x41ff9AA7... and WETH.
    '0x1b81D678ffb9C0263b24A97847620C99d213eB14'.lower(): 'PancakeSwap V3 SwapRouter',
}

# Protocol contracts a wallet approves or signs a permit for that are not swap entry points: they name
# the spender (services.counterparty_service), but never take a transaction down the router path.
KNOWN_SPENDERS = {
    '0x58daec3116aae6D93017bAAea7749052E8a04fA7'.lower(): 'Uniswap V4 PositionManager',
}

SIMULATION_PROVIDER = 'eth_simulateV1'


def _simulation_response(simulation: Dict, fields: tuple, required: tuple) -> Dict:
    return {
        **{field: simulation[field] for field in fields},
        **({'simulation_failed': True} if simulation.get('simulation_failed') else {}),
        'status': 'ok' if not simulation.get('simulation_failed')
        and all(simulation[field] is not None for field in required) else 'unknown',
        'reason': simulation['reason'],
        'simulation_block': simulation['simulation_block'],
        'observed_at': simulation.get('observed_at', 0),
        'field_providers': {field: SIMULATION_PROVIDER for field in fields if simulation[field] is not None},
    }


class RobinhoodAdapter(EvmAdapter):
    """Robinhood Chain adapter — chain_id=4663."""

    supports_honeypot_simulation = True

    def __init__(self, rpc_url: str = None):
        from services.robinhood_simulation import RobinhoodSimulator

        rpc = rpc_url or os.getenv('ROBINHOOD_RPC_URL') or 'https://rpc.mainnet.chain.robinhood.com'

        super().__init__(
            chain_id_value=4663,
            chain_name_value='Robinhood Chain',
            rpc_url=rpc,
            honeypot_chain_id=None,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=UNISWAP_V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
            known_spenders=KNOWN_SPENDERS,
        )
        self._simulator = RobinhoodSimulator(rpc)

    async def check_honeypot(self, address: str) -> Dict:
        simulation = await self._simulator.simulate(address)
        return _simulation_response(simulation, ('is_honeypot', 'can_buy', 'can_sell'), ('is_honeypot',))

    async def get_tax_info(self, address: str) -> Dict:
        simulation = await self._simulator.simulate(address)
        return _simulation_response(simulation, ('buy_tax', 'sell_tax'), ('buy_tax', 'sell_tax'))

    def capabilities(self) -> Dict:
        return {**super().capabilities(), 'sell_simulation': SIMULATION_PROVIDER}
