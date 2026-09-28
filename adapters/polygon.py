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
    "0x1095692A6237d83C6a72F3F5eFEdb9A670C49223".lower(): "Uniswap Universal Router V2",
    "0x8B844f885672f333Bc0042cB669255f93a4C1E6b".lower(): "Uniswap Universal Router V2.1.1",
    "0xDc264714F68d84CF29BC605589405E78bDBE7C9f".lower(): "Uniswap Universal Router V2.1.2",
    "0xec7BE89e9d109e7e3Fec59c222CF297125FEFda2".lower(): "Uniswap Universal Router V1.2",
    "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45".lower(): "Uniswap V3 SwapRouter02",
    "0xedf6066a2b290C185783862C7F4776A2C8077AD1".lower(): "Uniswap V2 Router02",
}

# Protocol contracts a wallet approves or signs a permit for that are not swap entry points: they name
# the spender (services.counterparty_service), but never take a transaction down the router path.
KNOWN_SPENDERS = {
    "0xC36442b4a4522E871399CD717aBDD847Ab11FE88".lower(): "Uniswap V3 NonfungiblePositionManager",
    "0x1Ec2eBf4F37E7363FDfe3551602425af0B3ceef9".lower(): "Uniswap V4 PositionManager",
}


class PolygonAdapter(EvmAdapter):
    """Polygon PoS adapter — chain_id=137."""

    def __init__(self, rpc_url: str = None, polygonscan_api_key: str = None):
        rpc = rpc_url or os.getenv('POLYGON_RPC_URL', 'https://polygon-bor-rpc.publicnode.com')
        api_key = polygonscan_api_key or os.getenv('POLYGONSCAN_API_KEY', '')

        super().__init__(
            chain_id_value=137,
            chain_name_value="Polygon",
            rpc_url=rpc,
            etherscan_api_key=api_key,
            # honeypot.is answers HTTP 400 Invalid chain here; sellability comes from GoPlus.
            honeypot_chain_id=None,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=QUICKSWAP_V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
            known_spenders=KNOWN_SPENDERS,
        )
