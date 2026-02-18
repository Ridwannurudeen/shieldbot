"""Base chain adapter — extends shared EvmAdapter."""

import os

from adapters.evm_base import EvmAdapter

# Base Constants
KNOWN_LOCKERS = {
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

# Base uses Uniswap V3 — no V2 factory for getPair. Use Aerodrome's factory for V2 pairs.
AERODROME_FACTORY = '0x420DD381b31aEf6683db6B902084cB0FFECe40Da'
WETH_ADDRESS = '0x4200000000000000000000000000000000000006'
USDC_ADDRESS = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'

QUOTE_TOKENS = [
    ('WETH', WETH_ADDRESS),
    ('USDC', USDC_ADDRESS),
]

WHITELISTED_ROUTERS = {
    "0x2626664c2603336E57B271c5C0b26F421741e481".lower(): "Uniswap V3 Router (Base)",
    "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".lower(): "Uniswap Universal Router",
    "0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43".lower(): "Aerodrome Router",
    "0x327Df1E6de05895d2ab08513aaDD9313Fe505d86".lower(): "BaseSwap Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
}


class BaseChainAdapter(EvmAdapter):
    """Base chain adapter — chain_id=8453."""

    def __init__(self, rpc_url: str = None, basescan_api_key: str = None):
        rpc = rpc_url or os.getenv('BASE_RPC_URL', 'https://mainnet.base.org')
        api_key = basescan_api_key or os.getenv('BASESCAN_API_KEY', '')

        super().__init__(
            chain_id_value=8453,
            chain_name_value="Base",
            rpc_url=rpc,
            etherscan_api_key=api_key,
            honeypot_chain_id=8453,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=AERODROME_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
        )
