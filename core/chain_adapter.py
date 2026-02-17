"""Abstract ChainAdapter interface for multi-chain support."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Union


class ChainAdapter(ABC):
    """Base class for chain-specific adapters."""

    @property
    @abstractmethod
    def chain_id(self) -> int:
        """Return the chain ID this adapter handles."""

    @property
    @abstractmethod
    def chain_name(self) -> str:
        """Human-readable chain name."""

    @abstractmethod
    async def is_contract(self, address: str) -> bool:
        """Check if address is a contract."""

    @abstractmethod
    async def get_bytecode(self, address: str) -> Optional[str]:
        """Get contract bytecode as hex string."""

    @abstractmethod
    async def is_verified_contract(self, address: str) -> Tuple[bool, Optional[str]]:
        """Check if contract is verified. Returns (is_verified, source_code_or_None)."""

    @abstractmethod
    async def get_contract_creation_info(self, address: str) -> Optional[Dict]:
        """Get creation tx hash, creator, creation_time, age_days."""

    @abstractmethod
    async def get_token_info(self, address: str) -> Dict:
        """Get token name, symbol, decimals, total_supply."""

    @abstractmethod
    async def get_ownership_info(self, address: str) -> Dict:
        """Get owner address and is_renounced flag."""

    @abstractmethod
    async def check_honeypot(self, address: str) -> Dict:
        """Check if token is a honeypot."""

    @abstractmethod
    async def get_tax_info(self, address: str) -> Dict:
        """Get buy/sell tax info."""

    @abstractmethod
    async def get_liquidity_info(self, address: str) -> Dict:
        """Get liquidity lock info."""

    @abstractmethod
    def get_whitelisted_routers(self) -> Dict[str, str]:
        """Return {lowercase_address: router_name} for this chain."""
