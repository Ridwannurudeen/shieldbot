"""Arbitrum One adapter — extends shared EvmAdapter."""

import os
from typing import Dict

from adapters.evm_base import EvmAdapter
from adapters.robinhood import SIMULATION_PROVIDER, _simulation_response

KNOWN_LOCKERS = {
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

# SushiSwap V2 factory on Arbitrum
SUSHISWAP_V2_FACTORY = '0xc35DADB65012eC5796536bD9864eD8773aBc74C4'
# Uniswap's V2 factory on this chain, which its Universal Routers swap V2 hops through.
UNISWAP_V2_FACTORY = '0xf1D7CC64Fb4452F05c498126312eBE29f30Fbcf9'
WETH_ADDRESS = '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1'
USDC_ADDRESS = '0xaf88d065e77c8cC2239327C5EDb3A432268e5831'
USDT_ADDRESS = '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9'

QUOTE_TOKENS = [
    ('WETH', WETH_ADDRESS),
    ('USDC', USDC_ADDRESS),
    ('USDT', USDT_ADDRESS),
]

WHITELISTED_ROUTERS = {
    "0xE592427A0AEce92De3Edee1F18E0157C05861564".lower(): "Uniswap V3 Router",
    "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506".lower(): "SushiSwap Router",
    "0xc873fEcbd354f5A56E00E710B90EF4201db2448d".lower(): "Camelot Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
    "0xA51afAFe0263b40EdaEf0Df8781eA9aa03E381a3".lower(): "Uniswap Universal Router V2",
    "0x8B844f885672f333Bc0042cB669255f93a4C1E6b".lower(): "Uniswap Universal Router V2.1.1",
    "0x2d01411773c8C24805306E89A41F7855C3c4Fe65".lower(): "Uniswap Universal Router V2.1.2",
    "0x5E325eDA8064b456f4781070C0738d849c824258".lower(): "Uniswap Universal Router V1.2",
    "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45".lower(): "Uniswap V3 SwapRouter02",
}

# Protocol contracts a wallet approves or signs a permit for that are not swap entry points: they name
# the spender (services.counterparty_service), but never take a transaction down the router path.
KNOWN_SPENDERS = {
    "0xC36442b4a4522E871399CD717aBDD847Ab11FE88".lower(): "Uniswap V3 NonfungiblePositionManager",
    "0xd88F38F930b7952f2DB2432Cb002E7abbF3dD869".lower(): "Uniswap V4 PositionManager",
}

# The V2 factory each Universal Router swaps V2 hops through, as its bytecode and its deploy parameters
# name it (checked 2026-09-28). A route that hands a swap's output straight to the next hop's V2 pool
# pays that factory's pool (api._analyze_router_swap confirms it on chain).
ROUTER_V2_FACTORIES = {
    router: UNISWAP_V2_FACTORY.lower()
    for router, name in WHITELISTED_ROUTERS.items() if name.startswith('Uniswap Universal Router')
}


# publicnode's Arbitrum One RPC answers eth_simulateV1, which Arbitrum's own RPC does not
# (services/arbitrum_simulation.py).
SIMULATION_RPC_URL = 'https://arbitrum-one-rpc.publicnode.com'


class ArbitrumAdapter(EvmAdapter):
    """Arbitrum One adapter — chain_id=42161."""

    supports_honeypot_simulation = True

    def __init__(self, rpc_url: str = None, arbiscan_api_key: str = None):
        from services.arbitrum_simulation import ArbitrumSimulator

        rpc = rpc_url or os.getenv('ARBITRUM_RPC_URL', 'https://arb1.arbitrum.io/rpc')
        api_key = arbiscan_api_key or os.getenv('ARBISCAN_API_KEY', '')

        super().__init__(
            chain_id_value=42161,
            chain_name_value="Arbitrum",
            rpc_url=rpc,
            etherscan_api_key=api_key,
            # honeypot.is answers HTTP 400 Invalid chain here; ShieldBot simulates the sell itself.
            honeypot_chain_id=None,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=SUSHISWAP_V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
            known_spenders=KNOWN_SPENDERS,
            router_v2_factories=ROUTER_V2_FACTORIES,
        )
        self._simulator = ArbitrumSimulator(os.getenv('ARBITRUM_SIMULATION_RPC_URL') or SIMULATION_RPC_URL)

    async def check_honeypot(self, address: str) -> Dict:
        simulation = await self._simulator.simulate(address)
        return _simulation_response(simulation, ('is_honeypot', 'can_buy', 'can_sell'), ('is_honeypot',))

    async def get_tax_info(self, address: str) -> Dict:
        simulation = await self._simulator.simulate(address)
        return _simulation_response(simulation, ('buy_tax', 'sell_tax'), ('buy_tax', 'sell_tax'))

    def capabilities(self) -> Dict:
        return {**super().capabilities(), 'sell_simulation': SIMULATION_PROVIDER}
