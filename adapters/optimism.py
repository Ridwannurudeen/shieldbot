"""Optimism adapter — extends shared EvmAdapter."""

import os

from adapters.evm_base import EvmAdapter

KNOWN_LOCKERS = {
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

# Velodrome V2 factory on Optimism (largest DEX)
VELODROME_V2_FACTORY = '0xF1046053aa5682b4F9a81b5481394DA16BE5FF5a'
WETH_ADDRESS = '0x4200000000000000000000000000000000000006'
USDC_ADDRESS = '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85'
USDT_ADDRESS = '0x94b008aA00579c1307B0EF2c499aD98a8ce58e58'
OP_ADDRESS = '0x4200000000000000000000000000000000000042'

QUOTE_TOKENS = [
    ('WETH', WETH_ADDRESS),
    ('USDC', USDC_ADDRESS),
    ('USDT', USDT_ADDRESS),
    ('OP', OP_ADDRESS),
]

WHITELISTED_ROUTERS = {
    "0xE592427A0AEce92De3Edee1F18E0157C05861564".lower(): "Uniswap V3 Router",
    "0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43".lower(): "Velodrome V2 Router",
    "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".lower(): "Uniswap Universal Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
    "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506".lower(): "SushiSwap Router",
}


class OptimismAdapter(EvmAdapter):
    """Optimism adapter — chain_id=10."""

    def __init__(self, rpc_url: str = None, optimism_api_key: str = None):
        rpc = rpc_url or os.getenv('OPTIMISM_RPC_URL', 'https://mainnet.optimism.io')
        api_key = optimism_api_key or os.getenv('OPTIMISM_API_KEY', '')

        super().__init__(
            chain_id_value=10,
            chain_name_value="Optimism",
            rpc_url=rpc,
            etherscan_api_key=api_key,
            honeypot_chain_id=10,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=VELODROME_V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
        )
