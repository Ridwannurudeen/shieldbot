"""
Web3 Client — thin router that delegates to chain-specific adapters.
Preserves the original interface for backward compatibility.
"""

import os
import logging
from typing import Dict, Optional, Tuple, Union
from web3 import Web3
try:
    from web3.middleware import ExtraDataToPOAMiddleware as geth_poa_middleware
except ImportError:
    from web3.middleware import geth_poa_middleware

from adapters.bsc import BscAdapter

logger = logging.getLogger(__name__)


class Web3Client:
    """Web3 client routing to chain-specific adapters."""

    def __init__(self):
        opbnb_rpc = os.getenv('OPBNB_RPC_URL', 'https://opbnb-mainnet-rpc.bnbchain.org')

        # Primary adapter: BSC
        self._bsc_adapter = BscAdapter()

        # Adapter registry: chain_id -> adapter instance
        self._adapters: Dict[int, object] = {
            56: self._bsc_adapter,
        }

        # opBNB still uses raw Web3 (no adapter yet — future PR)
        self.opbnb_web3 = Web3(Web3.HTTPProvider(opbnb_rpc))
        self.opbnb_web3.middleware_onion.inject(geth_poa_middleware, layer=0)

        # Legacy compat aliases
        self.bsc_web3 = self._bsc_adapter.w3

        # ERC20 ABI for opBNB fallback + is_token_contract
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
        """Return adapter for chain_id, or None for unsupported chains."""
        return self._adapters.get(chain_id)

    def get_supported_chain_ids(self):
        """Return list of chain IDs with registered adapters."""
        return list(self._adapters.keys())

    def get_web3(self, chain_id: int = 56):
        if chain_id == 204:
            return self.opbnb_web3
        adapter = self._get_adapter(chain_id)
        if adapter:
            return adapter.w3
        return self.bsc_web3

    def is_valid_address(self, address: str) -> bool:
        return Web3.is_address(address)

    def to_checksum_address(self, address: str) -> str:
        return Web3.to_checksum_address(address)

    async def is_contract(self, address: str, chain_id: int = 56) -> bool:
        adapter = self._get_adapter(chain_id)
        if adapter:
            return await adapter.is_contract(address)
        # opBNB fallback
        try:
            w3 = self.get_web3(chain_id)
            code = w3.eth.get_code(Web3.to_checksum_address(address))
            return len(code) > 0
        except Exception as e:
            logger.error(f"Error checking if contract: {e}")
            return False

    async def is_token_contract(self, address: str, chain_id: int = 56) -> bool:
        try:
            w3 = self.get_web3(chain_id)
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=self.erc20_abi,
            )
            contract.functions.symbol().call()
            return True
        except Exception:
            return False

    async def get_bytecode(self, address: str, chain_id: int = 56) -> Optional[str]:
        adapter = self._get_adapter(chain_id)
        if adapter:
            return await adapter.get_bytecode(address)
        try:
            w3 = self.get_web3(chain_id)
            code = w3.eth.get_code(Web3.to_checksum_address(address))
            return code.hex()
        except Exception as e:
            logger.error(f"Error getting bytecode: {e}")
            return None

    async def is_verified_contract(self, address: str, chain_id: int = 56) -> Union[bool, Tuple[bool, Optional[str]]]:
        adapter = self._get_adapter(chain_id)
        if adapter:
            return await adapter.is_verified_contract(address)
        return (False, None)

    async def get_contract_creation_info(self, address: str, chain_id: int = 56) -> Optional[Dict]:
        adapter = self._get_adapter(chain_id)
        if adapter:
            return await adapter.get_contract_creation_info(address)
        return None

    async def get_token_info(self, address: str, chain_id: int = 56) -> Dict:
        adapter = self._get_adapter(chain_id)
        if adapter:
            return await adapter.get_token_info(address)
        # opBNB fallback
        try:
            w3 = self.get_web3(chain_id)
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=self.erc20_abi,
            )
            name = contract.functions.name().call()
            symbol = contract.functions.symbol().call()
            decimals = contract.functions.decimals().call()
            total_supply = contract.functions.totalSupply().call()
            return {
                'name': name, 'symbol': symbol,
                'decimals': decimals, 'total_supply': total_supply / (10 ** decimals),
            }
        except Exception as e:
            logger.error(f"Error getting token info: {e}")
            return {}

    async def can_transfer_token(self, address: str, chain_id: int = 56) -> bool:
        try:
            w3 = self.get_web3(chain_id)
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=self.erc20_abi,
            )
            contract.functions.decimals().call()
            return True
        except Exception:
            return False

    async def get_ownership_info(self, address: str, chain_id: int = 56) -> Dict:
        adapter = self._get_adapter(chain_id)
        if adapter:
            return await adapter.get_ownership_info(address)
        try:
            w3 = self.get_web3(chain_id)
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=self.erc20_abi,
            )
            owner = contract.functions.owner().call()
            zero_address = '0x0000000000000000000000000000000000000000'
            is_renounced = owner.lower() == zero_address.lower()
            return {'owner': owner, 'is_renounced': is_renounced}
        except Exception as e:
            logger.error(f"Error getting ownership info: {e}")
            return {'owner': None, 'is_renounced': None}

    async def get_liquidity_info(self, address: str, chain_id: int = 56) -> Dict:
        adapter = self._get_adapter(chain_id)
        if adapter:
            return await adapter.get_liquidity_info(address)
        return {'is_locked': False, 'lock_percentage': 0}

    async def check_honeypot(self, address: str, chain_id: int = 56) -> Dict:
        adapter = self._get_adapter(chain_id)
        if adapter:
            return await adapter.check_honeypot(address)
        return {'is_honeypot': False, 'reason': 'No adapter for chain'}

    async def get_tax_info(self, address: str, chain_id: int = 56) -> Dict:
        adapter = self._get_adapter(chain_id)
        if adapter:
            return await adapter.get_tax_info(address)
        return {'buy_tax': 0, 'sell_tax': 0}
