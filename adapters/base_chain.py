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
# Uniswap's V2 factory on this chain, which its Universal Routers swap V2 hops through.
UNISWAP_V2_FACTORY = '0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6'
WETH_ADDRESS = '0x4200000000000000000000000000000000000006'
USDC_ADDRESS = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'

QUOTE_TOKENS = [
    ('WETH', WETH_ADDRESS),
    ('USDC', USDC_ADDRESS),
]

WHITELISTED_ROUTERS = {
    "0x2626664c2603336E57B271c5C0b26F421741e481".lower(): "Uniswap V3 Router (Base)",
    "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".lower(): "Uniswap Universal Router V1.2",
    "0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43".lower(): "Aerodrome Router",
    "0x327Df1E6de05895d2ab08513aaDD9313Fe505d86".lower(): "BaseSwap Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
    "0x6fF5693b99212Da76ad316178A184AB56D299b43".lower(): "Uniswap Universal Router V2",
    "0xFdf682F51FE81Aa4898F0AE2163d8A55c127fbC7".lower(): "Uniswap Universal Router V2.1.1",
    "0xd6145b2D3F379919E8CdEda7B97e37c4b2Ca9c40".lower(): "Uniswap Universal Router V2.1.2",
    "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24".lower(): "Uniswap V2 Router02",
}

# Protocol contracts a wallet approves or signs a permit for that are not swap entry points: they name
# the spender (services.counterparty_service), but never take a transaction down the router path.
KNOWN_SPENDERS = {
    "0x03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1".lower(): "Uniswap V3 NonfungiblePositionManager",
    "0x7C5f5A4bBd8fD63184577525326123B519429bDc".lower(): "Uniswap V4 PositionManager",
}

# The V2 factory each Universal Router swaps V2 hops through, as its bytecode and its deploy parameters
# name it (checked 2026-09-28). A route that hands a swap's output straight to the next hop's V2 pool
# pays that factory's pool (api._analyze_router_swap confirms it on chain).
ROUTER_V2_FACTORIES = {
    router: UNISWAP_V2_FACTORY.lower()
    for router, name in WHITELISTED_ROUTERS.items() if name.startswith('Uniswap Universal Router')
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
            known_spenders=KNOWN_SPENDERS,
            router_v2_factories=ROUTER_V2_FACTORIES,
            solidly_factory=True,
        )
