"""Premium tier management — token gating, tier resolution, and rate limits."""

import asyncio
import logging
import time
from typing import Dict, Optional

from web3 import Web3

logger = logging.getLogger(__name__)

TOKEN_ADDRESS = "0x4904c02efa081cb7685346968bac854cdf4e7777"
TOKEN_DECIMALS = 18

# Tier thresholds in token units
TIER_THRESHOLDS = {
    "agent": 200_000,   # 200K $SHIELDBOT → Agent tier
    "pro": 50_000,      # 50K $SHIELDBOT → Pro tier
}

# Rate limits per tier (requests per minute)
TIER_RATE_LIMITS = {
    "free": 30,
    "pro": 120,
    "agent": 500,
    "enterprise": 10000,
}

# Features per tier
TIER_FEATURES = {
    "free": {
        "scan", "chat", "threat_feed", "guardian_wallets_1",
    },
    "pro": {
        "scan", "chat", "threat_feed", "guardian_unlimited",
        "batch_revoke", "threat_graph", "mcp_access", "injection_scan",
    },
    "agent": {
        "scan", "chat", "threat_feed", "guardian_unlimited",
        "batch_revoke", "threat_graph", "mcp_access", "injection_scan",
        "agent_firewall", "policy_engine", "anomaly_detection",
        "priority_simulation", "sdk_access", "reputation_lookup",
    },
    "enterprise": {
        "all",
    },
}

CACHE_TTL = 3600  # 1 hour cache for balance checks


class TierService:
    """Resolves API key tier based on token holdings or subscription."""

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

    def __init__(self, rpc_url: str = ""):
        self._rpc_url = rpc_url
        self._web3: Optional[Web3] = None
        self._token = None
        self._balance_cache: Dict[str, tuple] = {}  # address -> (balance, expiry)
        self._enabled = False

        if rpc_url:
            try:
                self._web3 = Web3(Web3.HTTPProvider(rpc_url))
                self._token = self._web3.eth.contract(
                    address=Web3.to_checksum_address(TOKEN_ADDRESS),
                    abi=self._abi,
                )
                self._enabled = True
            except Exception as exc:
                logger.warning("TierService: web3 init failed: %s", exc)

    def is_enabled(self) -> bool:
        return self._enabled

    async def resolve_tier(self, key_info: Dict) -> str:
        """Resolve the effective tier for an API key.

        Priority:
        1. Enterprise (set in DB) → always enterprise
        2. Token holding check → pro or agent based on balance
        3. DB tier (from subscription) → whatever is stored
        4. Default → free
        """
        db_tier = key_info.get("tier", "free")

        # Enterprise is manually set and never overridden
        if db_tier == "enterprise":
            return "enterprise"

        # Check token holdings if we have an owner address
        owner = key_info.get("owner", "")
        if owner and self._enabled and Web3.is_address(owner):
            token_tier = await self._check_token_tier(owner)
            if token_tier:
                # Token holding tier trumps DB tier if higher
                tier_order = {"free": 0, "pro": 1, "agent": 2, "enterprise": 3}
                if tier_order.get(token_tier, 0) > tier_order.get(db_tier, 0):
                    return token_tier

        return db_tier

    def get_rate_limit(self, tier: str) -> int:
        """Get requests-per-minute limit for a tier."""
        return TIER_RATE_LIMITS.get(tier, TIER_RATE_LIMITS["free"])

    def has_feature(self, tier: str, feature: str) -> bool:
        """Check if a tier has access to a feature."""
        features = TIER_FEATURES.get(tier, TIER_FEATURES["free"])
        return "all" in features or feature in features

    async def get_token_balance(self, address: str) -> int:
        """Get $SHIELDBOT token balance for an address (in token units)."""
        if not self._enabled or not Web3.is_address(address):
            return 0

        cache_key = address.lower()
        now = time.monotonic()
        cached = self._balance_cache.get(cache_key)
        if cached and cached[1] > now:
            return cached[0]

        try:
            checksum = Web3.to_checksum_address(address)

            def _fetch():
                return self._token.functions.balanceOf(checksum).call()

            balance_wei = await asyncio.to_thread(_fetch)
            balance = balance_wei // (10 ** TOKEN_DECIMALS)
            self._balance_cache[cache_key] = (balance, now + CACHE_TTL)
            return balance
        except Exception as exc:
            logger.debug("Token balance check failed for %s: %s", address, exc)
            return 0

    async def _check_token_tier(self, address: str) -> Optional[str]:
        """Check what tier an address qualifies for based on token holdings."""
        balance = await self.get_token_balance(address)

        if balance >= TIER_THRESHOLDS["agent"]:
            return "agent"
        if balance >= TIER_THRESHOLDS["pro"]:
            return "pro"
        return None
