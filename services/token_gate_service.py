import asyncio
import logging
import time

from web3 import Web3

TOKEN_ADDRESS = "0x4904c02efa081cb7685346968bac854cdf4e7777"
MINIMUM_BALANCE_WEI = 10 ** 18
CACHE_TTL_SECONDS = 300

logger = logging.getLogger(__name__)


class TokenGateService:
    """Checks whether a wallet holds the minimum $SHIELDBOT token balance."""

    _abi = [
        {
            "constant": True,
            "inputs": [{"name": "account", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function",
        }
    ]

    def __init__(self, rpc_url: str):
        self.rpc_url = rpc_url
        self._cache: dict[str, tuple[bool, float]] = {}
        self._web3 = Web3(Web3.HTTPProvider(rpc_url))
        self._token = self._web3.eth.contract(
            address=Web3.to_checksum_address(TOKEN_ADDRESS),
            abi=self._abi,
        )

    async def has_shieldbot_token(self, address: str) -> bool:
        """Return True if the wallet holds at least 1 $SHIELDBOT token."""
        if not Web3.is_address(address):
            return False

        cache_key = address.lower()
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached and cached[1] > now:
            return cached[0]

        checksum_address = Web3.to_checksum_address(address)

        def _fetch_balance() -> int:
            return self._token.functions.balanceOf(checksum_address).call()

        try:
            balance = await asyncio.to_thread(_fetch_balance)
            has_minimum = balance >= MINIMUM_BALANCE_WEI
            self._cache[cache_key] = (has_minimum, now + CACHE_TTL_SECONDS)
            return has_minimum
        except Exception as exc:
            logger.warning("Token gate balance check failed for %s: %s", address, exc)
            return False
