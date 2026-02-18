"""Arbitrum One adapter — extends shared EvmAdapter."""

import os

from adapters.evm_base import EvmAdapter

KNOWN_LOCKERS = {
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

# SushiSwap V2 factory on Arbitrum
SUSHISWAP_V2_FACTORY = '0xc35DADB65012eC5796536bD9864eD8773aBc74C4'
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
    "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".lower(): "Uniswap Universal Router",
    "0xc873fEcbd354f5A56E00E710B90EF4201db2448d".lower(): "Camelot Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
}


class ArbitrumAdapter(EvmAdapter):
    """Arbitrum One adapter — chain_id=42161."""

    def __init__(self, rpc_url: str = None, arbiscan_api_key: str = None):
        rpc = rpc_url or os.getenv('ARBITRUM_RPC_URL', 'https://arb1.arbitrum.io/rpc')
        api_key = arbiscan_api_key or os.getenv('ARBISCAN_API_KEY', '')

        super().__init__(
            chain_id_value=42161,
            chain_name_value="Arbitrum",
            rpc_url=rpc,
            etherscan_api_key=api_key,
            honeypot_chain_id=42161,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=SUSHISWAP_V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
        )
