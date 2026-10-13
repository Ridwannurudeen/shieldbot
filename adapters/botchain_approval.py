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

    async def _call_with_retry(self, fn):
        import requests

        loop = asyncio.get_running_loop()
        for attempt in range(3):
            try:
                return await loop.run_in_executor(None, fn)
            except Exception as error:
                if isinstance(error, requests.exceptions.HTTPError):
                    response = error.response
                    is_retriable = response is not None and response.status_code in (429, 502, 503)
                else:
                    rpc_response = getattr(error, "rpc_response", None)
                    if isinstance(rpc_response, dict):
                        rpc_error = rpc_response.get("error")
                    else:
                        rpc_error = error.args[0] if isinstance(error, ValueError) and error.args else None
                    is_retriable = isinstance(rpc_error, dict) and rpc_error.get("code") == -32005
                if not is_retriable or attempt == 2:
                    raise
                delay = 1.0 * (2 ** attempt)
                logger.warning(
                    "[BOT Chain] RPC rate-limited (attempt %d/3), retrying in %ss: %s",
                    attempt + 1, delay, type(error).__name__,
                )
                await asyncio.sleep(delay)

    async def get_token_info(self, address: str) -> dict:
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=ERC20_INFO_ABI,
            )
            reads = await asyncio.gather(
                *(
                    self._call_with_retry(function.call)
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
