"""opBNB adapter — extends shared EvmAdapter."""

import os

from adapters.evm_base import EvmAdapter

KNOWN_LOCKERS = {
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

# PancakeSwap V2 factory on opBNB
PANCAKESWAP_V2_FACTORY = '0x02a84c1b3BBD7401a5f7fa98a384EBC70bB5749E'
WBNB_ADDRESS = '0x4200000000000000000000000000000000000006'
USDT_ADDRESS = '0x9e5AAC1Ba1a2e6aEd6b32689DFcF62A509Ca96f3'
FDUSD_ADDRESS = '0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb'

QUOTE_TOKENS = [
    ('WBNB', WBNB_ADDRESS),
    ('USDT', USDT_ADDRESS),
    ('FDUSD', FDUSD_ADDRESS),
]

WHITELISTED_ROUTERS = {
    "0x8cFe327CEc66d1C090Dd72bd0FF11d690C33a2Eb".lower(): "PancakeSwap V3 Router",
    "0x10ED43C718714eb63d5aA57B78B54704E256024E".lower(): "PancakeSwap V2 Router",
}


class OpBNBAdapter(EvmAdapter):
    """opBNB adapter — chain_id=204."""

    def __init__(self, rpc_url: str = None, opbnbscan_api_key: str = None):
        rpc = rpc_url or os.getenv('OPBNB_RPC_URL', 'https://opbnb-mainnet-rpc.bnbchain.org')
        api_key = opbnbscan_api_key or os.getenv('OPBNBSCAN_API_KEY', '')

        super().__init__(
            chain_id_value=204,
            chain_name_value="opBNB",
            rpc_url=rpc,
            etherscan_api_key=api_key,
            honeypot_chain_id=204,
            known_lockers=KNOWN_LOCKERS,
            quote_tokens=QUOTE_TOKENS,
            factory_address=PANCAKESWAP_V2_FACTORY,
            whitelisted_routers=WHITELISTED_ROUTERS,
        )
