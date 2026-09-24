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
    UNISWAP_V4_UNIVERSAL_ROUTER.lower(): 'Uniswap V4 Universal Router',
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
