"""
Web3 Client — thin router that delegates to chain-specific adapters.
Preserves the original interface for backward compatibility.
"""

import logging
from typing import Dict, Optional, Tuple, Union
from web3 import Web3

from adapters.bsc import BscAdapter

logger = logging.getLogger(__name__)


class UnsupportedChainError(ValueError):
    """Raised when a chain has no registered adapter."""


class Web3Client:
    """Web3 client routing to chain-specific adapters."""

    def __init__(self):
        # Primary adapter: BSC
        self._bsc_adapter = BscAdapter()

        # Adapter registry: chain_id -> adapter instance
        self._adapters: Dict[int, object] = {
            56: self._bsc_adapter,
        }

        # Legacy compat aliases
        self.bsc_web3 = self._bsc_adapter.w3

        # ERC20 ABI for token interface checks
        self.erc20_abi = [
            {"constant": True, "inputs": [], "name": "name",
             "outputs": [{"name": "", "type": "string"}], "type": "function"},
            {"constant": True, "inputs": [], "name": "symbol",
             "outputs": [{"name": "", "type": "string"}], "type": "function"},
            {"constant": True, "inputs": [], "name": "decimals",
             "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
            {"constant": True, "inputs": [], "name": "totalSupply",
             "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
            {"constant": True, "inputs": [], "name": "owner",
             "outputs": [{"name": "", "type": "address"}], "type": "function"},
        ]

        logger.info(f"Web3Client initialized (adapters: {list(self._adapters.keys())})")

    def register_adapter(self, adapter):
        """Register a chain adapter by its chain_id."""
        self._adapters[adapter.chain_id] = adapter
        logger.info(f"Registered adapter: {adapter.chain_name} (chain_id={adapter.chain_id})")

    def _get_adapter(self, chain_id: int):
        """Return the registered adapter, rejecting unsupported chains."""
        self.validate_chain_id(chain_id)
        return self._adapters[chain_id]

    def get_supported_chain_ids(self):
        """Return list of chain IDs with registered adapters."""
        return list(self._adapters.keys())

    def validate_chain_id(self, chain_id: int) -> int:
        """Reject chains without an adapter before accessing any provider."""
        if type(chain_id) is int and not 1 <= chain_id <= 10_000_000:
            raise UnsupportedChainError(
                "Unsupported chain ID: must be between 1 and 10000000."
            )
        if type(chain_id) is not int or chain_id not in self._adapters:
            supported = ", ".join(str(cid) for cid in self.get_supported_chain_ids())
            raise UnsupportedChainError(
                f"Unsupported chain ID {chain_id}. Supported chain IDs: {supported}"
            )
        return chain_id

    def get_web3(self, chain_id: int = 56):
        return self._get_adapter(chain_id).w3

    def is_valid_address(self, address: str) -> bool:
        return Web3.is_address(address)

    def to_checksum_address(self, address: str) -> str:
        return Web3.to_checksum_address(address)

    async def is_contract(self, address: str, chain_id: int = 56) -> bool:
        return await self._get_adapter(chain_id).is_contract(address)

    async def is_token_contract(self, address: str, chain_id: int = 56) -> bool:
        w3 = self.get_web3(chain_id)
        try:
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=self.erc20_abi,
            )
            contract.functions.symbol().call()
            return True
        except Exception:
            return False

    async def get_bytecode(self, address: str, chain_id: int = 56) -> Optional[str]:
        return await self._get_adapter(chain_id).get_bytecode(address)

    async def is_verified_contract(self, address: str, chain_id: int = 56) -> Union[bool, Tuple[bool, Optional[str]]]:
        return await self._get_adapter(chain_id).is_verified_contract(address)

    async def get_contract_creation_info(self, address: str, chain_id: int = 56) -> Optional[Dict]:
        return await self._get_adapter(chain_id).get_contract_creation_info(address)

    async def get_token_info(self, address: str, chain_id: int = 56) -> Dict:
        return await self._get_adapter(chain_id).get_token_info(address)

    async def can_transfer_token(self, address: str, chain_id: int = 56) -> bool:
        w3 = self.get_web3(chain_id)
        try:
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=self.erc20_abi,
            )
            contract.functions.decimals().call()
            return True
        except Exception:
            return False

    async def get_ownership_info(self, address: str, chain_id: int = 56) -> Dict:
        return await self._get_adapter(chain_id).get_ownership_info(address)

    async def get_liquidity_info(self, address: str, chain_id: int = 56) -> Dict:
        return await self._get_adapter(chain_id).get_liquidity_info(address)

    async def check_honeypot(self, address: str, chain_id: int = 56) -> Dict:
        return await self._get_adapter(chain_id).check_honeypot(address)

    async def get_tax_info(self, address: str, chain_id: int = 56) -> Dict:
        return await self._get_adapter(chain_id).get_tax_info(address)
