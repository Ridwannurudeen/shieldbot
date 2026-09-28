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
    "0xa062aE8A9c5e11aaA026fc2670B0D65cCc8B2858".lower(): "Velodrome V2 Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
    "0x851116D9223fabED8E56C0E6b8Ad0c31d98B3507".lower(): "Uniswap Universal Router V2",
    "0x8B844f885672f333Bc0042cB669255f93a4C1E6b".lower(): "Uniswap Universal Router V2.1.1",
    "0xC09255D86DB563cBc11C2fCf4a0C512e160111B4".lower(): "Uniswap Universal Router V2.1.2",
    "0xCb1355ff08Ab38bBCE60111F1bb2B784bE25D7e8".lower(): "Uniswap Universal Router V1.2",
    "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45".lower(): "Uniswap V3 SwapRouter02",
}

# Protocol contracts a wallet approves or signs a permit for that are not swap entry points: they name
# the spender (services.counterparty_service), but never take a transaction down the router path.
KNOWN_SPENDERS = {
    "0xC36442b4a4522E871399CD717aBDD847Ab11FE88".lower(): "Uniswap V3 NonfungiblePositionManager",
    "0x3C3Ea4B57a46241e54610e5f022E5c45859A1017".lower(): "Uniswap V4 PositionManager",
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
            # honeypot.is answers HTTP 400 Invalid chain here; sellability comes from GoPlus.
            honeypot_chain_id=None,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=VELODROME_V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
            known_spenders=KNOWN_SPENDERS,
            solidly_factory=True,
        )
