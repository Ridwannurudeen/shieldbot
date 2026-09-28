"""Ethereum Mainnet adapter — extends shared EvmAdapter."""

import os

from adapters.evm_base import EvmAdapter

# Ethereum Constants
KNOWN_LOCKERS = {
    '0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214'.lower(): 'Unicrypt',
    '0xDba68f07d1b7Ca219f78ae8582C213d975c25cAf'.lower(): 'UNCX Token Vesting',
    '0xE2fE530C047f2d85298b07D9333C05737f1435fB'.lower(): 'Team Finance',
    '0x71B5759d73262FBb223956913ecF4ecC51057641'.lower(): 'PinkLock',
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

UNISWAP_V2_FACTORY = '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f'
WETH_ADDRESS = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'
USDC_ADDRESS = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
USDT_ADDRESS = '0xdAC17F958D2ee523a2206206994597C13D831ec7'

QUOTE_TOKENS = [
    ('WETH', WETH_ADDRESS),
    ('USDC', USDC_ADDRESS),
    ('USDT', USDT_ADDRESS),
]

WHITELISTED_ROUTERS = {
    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".lower(): "Uniswap V2 Router",
    "0xE592427A0AEce92De3Edee1F18E0157C05861564".lower(): "Uniswap V3 Router",
    "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45".lower(): "Uniswap V3 Router 02",
    "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B".lower(): "Uniswap Universal Router",
    "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".lower(): "Uniswap Universal Router V1.2",
    "0x1111111254EEB25477B68fb85Ed929f73A960582".lower(): "1inch V5 Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
    "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af".lower(): "Uniswap Universal Router V2",
    "0x4C82D1fBFe28C977cBB58D8C7FF8FCF9F70a2cCA".lower(): "Uniswap Universal Router V2.1.1",
    "0x23617e59A5925b2A4Bf75d73ff6711cD0b29De85".lower(): "Uniswap Universal Router V2.1.2",
}

# Protocol contracts a wallet approves or signs a permit for that are not swap entry points: they name
# the spender (services.counterparty_service), but never take a transaction down the router path.
KNOWN_SPENDERS = {
    "0xC36442b4a4522E871399CD717aBDD847Ab11FE88".lower(): "Uniswap V3 NonfungiblePositionManager",
    "0xbD216513d74C8cf14cf4747E6AaA6420FF64ee9e".lower(): "Uniswap V4 PositionManager",
}

# The V2 factory each Universal Router swaps V2 hops through, as its bytecode and its deploy parameters
# name it (checked 2026-09-28). A route that hands a swap's output straight to the next hop's V2 pool
# pays that factory's pool (api._analyze_router_swap confirms it on chain).
ROUTER_V2_FACTORIES = {
    router: UNISWAP_V2_FACTORY.lower()
    for router, name in WHITELISTED_ROUTERS.items() if name.startswith('Uniswap Universal Router')
}


class EthAdapter(EvmAdapter):
    """Ethereum Mainnet adapter — chain_id=1."""

    def __init__(self, rpc_url: str = None, etherscan_api_key: str = None):
        rpc = rpc_url or os.getenv('ETH_RPC_URL', 'https://ethereum-rpc.publicnode.com')
        api_key = etherscan_api_key or os.getenv('ETHERSCAN_API_KEY', '')

        super().__init__(
            chain_id_value=1,
            chain_name_value="Ethereum",
            rpc_url=rpc,
            etherscan_api_key=api_key,
            honeypot_chain_id=1,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=UNISWAP_V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
            known_spenders=KNOWN_SPENDERS,
            router_v2_factories=ROUTER_V2_FACTORIES,
        )
