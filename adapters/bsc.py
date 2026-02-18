"""BSC (BNB Smart Chain) adapter — extends shared EvmAdapter."""

import os

from adapters.evm_base import EvmAdapter

# BSC Constants
KNOWN_LOCKERS = {
    '0x407993575c91ce7643a4d4cCACc9A98c36eE1BBE'.lower(): 'PinkLock',
    '0xC765bddB93b0D1c1A88282BA0fa6B2d00E3e0c83'.lower(): 'Unicrypt',
    '0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214'.lower(): 'DxLock',
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

PANCAKESWAP_V2_FACTORY = '0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73'
WBNB_ADDRESS = '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c'
BUSD_ADDRESS = '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56'
USDT_ADDRESS = '0x55d398326f99059fF775485246999027B3197955'

QUOTE_TOKENS = [
    ('WBNB', WBNB_ADDRESS),
    ('BUSD', BUSD_ADDRESS),
    ('USDT', USDT_ADDRESS),
]

WHITELISTED_ROUTERS = {
    "0x10ED43C718714eb63d5aA57B78B54704E256024E".lower(): "PancakeSwap V2 Router",
    "0x13f4EA83D0bd40E75C8222255bc855a974568Dd4".lower(): "PancakeSwap V3 Smart Router",
    "0x1a0A18AC4BECDdbd6389559687d1A73d8927E416".lower(): "PancakeSwap Universal Router",
    "0xd9C500DfF816a1Da21A48A732d3498Bf09dc9AEB".lower(): "PancakeSwap Universal Router 2",
    "0x1111111254EEB25477B68fb85Ed929f73A960582".lower(): "1inch V5 Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
}


class BscAdapter(EvmAdapter):
    """BNB Smart Chain (BSC) adapter — chain_id=56."""

    def __init__(self, rpc_url: str = None, bscscan_api_key: str = None):
        rpc = rpc_url or os.getenv('BSC_RPC_URL', 'https://bsc-dataseed1.binance.org/')
        api_key = bscscan_api_key or os.getenv('BSCSCAN_API_KEY', '')

        super().__init__(
            chain_id_value=56,
            chain_name_value="BSC",
            rpc_url=rpc,
            etherscan_api_key=api_key,
            honeypot_chain_id=56,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=PANCAKESWAP_V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
        )
