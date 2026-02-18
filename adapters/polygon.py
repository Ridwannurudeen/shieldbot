"""Polygon PoS adapter — extends shared EvmAdapter."""

import os

from adapters.evm_base import EvmAdapter

KNOWN_LOCKERS = {
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

# QuickSwap V2 factory on Polygon
QUICKSWAP_V2_FACTORY = '0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32'
WMATIC_ADDRESS = '0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270'
USDC_ADDRESS = '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359'
USDT_ADDRESS = '0xc2132D05D31c914a87C6611C10748AEb04B58e8F'

QUOTE_TOKENS = [
    ('WMATIC', WMATIC_ADDRESS),
    ('USDC', USDC_ADDRESS),
    ('USDT', USDT_ADDRESS),
]

WHITELISTED_ROUTERS = {
    "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff".lower(): "QuickSwap Router",
    "0xE592427A0AEce92De3Edee1F18E0157C05861564".lower(): "Uniswap V3 Router",
    "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506".lower(): "SushiSwap Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
}


class PolygonAdapter(EvmAdapter):
    """Polygon PoS adapter — chain_id=137."""

    def __init__(self, rpc_url: str = None, polygonscan_api_key: str = None):
        rpc = rpc_url or os.getenv('POLYGON_RPC_URL', 'https://polygon-rpc.com')
        api_key = polygonscan_api_key or os.getenv('POLYGONSCAN_API_KEY', '')

        super().__init__(
            chain_id_value=137,
            chain_name_value="Polygon",
            rpc_url=rpc,
            etherscan_api_key=api_key,
            honeypot_chain_id=137,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=QUICKSWAP_V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
        )
