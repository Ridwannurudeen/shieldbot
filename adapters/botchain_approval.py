"""Read-only BOT Chain RPC access for the explicit Telegram approval scan."""

import asyncio
import logging

from web3 import Web3
try:
    from web3.middleware import ExtraDataToPOAMiddleware as geth_poa_middleware
except ImportError:
    from web3.middleware import geth_poa_middleware

logger = logging.getLogger(__name__)

BOTCHAIN_RPC_URL = "https://rpc.botchain.ai"
ERC20_INFO_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function",
    },
]


class BotChainApprovalReader:
    """Fetch BOT Chain token metadata without registering a scan chain."""

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(BOTCHAIN_RPC_URL, request_kwargs={"timeout": 10}))
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    async def get_token_info(self, address: str) -> dict:
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=ERC20_INFO_ABI,
            )
            loop = asyncio.get_running_loop()
            reads = await asyncio.gather(
                *(
                    loop.run_in_executor(None, function.call)
                    for function in (
                        contract.functions.name(),
                        contract.functions.symbol(),
                        contract.functions.decimals(),
                        contract.functions.totalSupply(),
                    )
                ),
                return_exceptions=True,
            )
            for read in reads:
                if isinstance(read, BaseException):
                    raise read
            name, symbol, decimals, total_supply = reads
            return {
                "name": name,
                "symbol": symbol,
                "decimals": decimals,
                "total_supply": total_supply / (10 ** decimals),
            }
        except Exception as error:
            logger.error("[BOT Chain] Error getting token info: %s", type(error).__name__)
            return {}
