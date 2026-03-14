"""Agent tool layer — thin async wrappers around existing ShieldBot services.

Each method provides a single capability the AI agent can invoke.
No business logic lives here; all scoring, flagging, and analysis is
delegated to the underlying services in core/ and services/.
"""

import logging
import re
from typing import Dict, List, Optional

from core.analyzer import AnalysisContext

logger = logging.getLogger(__name__)

_ADDRESS_RE = re.compile(r'^0x[a-fA-F0-9]{40}$')


def _validate_address(addr: str) -> str:
    """Validate and normalize an Ethereum address."""
    if not _ADDRESS_RE.match(addr):
        raise ValueError(f"Invalid address: {addr}")
    return addr.lower()


class AgentTools:
    """Expose ShieldBot services as discrete, awaitable tool calls."""

    def __init__(self, container):
        self._container = container

    async def scan_contract(self, address: str, chain_id: int = 56) -> Dict:
        """Run all analyzers on a contract and return composite risk score."""
        address = _validate_address(address)
        ctx = AnalysisContext(address=address, chain_id=chain_id)
        results = await self._container.registry.run_all(ctx)
        return self._container.risk_engine.compute_from_results(results)

    async def check_deployer(self, address: str, chain_id: int = 56) -> Optional[Dict]:
        """Look up deployer risk summary for a contract address."""
        address = _validate_address(address)
        return await self._container.db.get_deployer_risk_summary(address, chain_id)

    async def check_honeypot(self, address: str) -> Dict:
        """Run honeypot simulation on a token address."""
        address = _validate_address(address)
        return await self._container.honeypot_service.fetch_honeypot_data(address)

    async def get_market_data(self, address: str) -> Dict:
        """Fetch DexScreener market data for a token address."""
        address = _validate_address(address)
        return await self._container.dex_service.fetch_token_market_data(address)

    async def query_campaign(self, address: str, chain_id: int = None) -> Dict:
        """Get deployer/funder campaign graph for an address."""
        return await self._container.db.get_campaign_graph(address, chain_id)

    async def get_funder_links(self, deployer: str, chain_id: int = None) -> Dict:
        """Get funder links for a deployer address via campaign graph."""
        return await self._container.db.get_campaign_graph(deployer, chain_id)

    async def get_agent_findings(
        self, limit: int = 10, finding_type: str = None
    ) -> List[Dict]:
        """Retrieve recent agent findings, optionally filtered by type."""
        return await self._container.db.get_agent_findings(limit, finding_type)

    async def auto_watch_deployer(
        self, address: str, reason: str, chain_id: int = 0
    ) -> None:
        """Add a deployer to the watch list."""
        address = _validate_address(address)
        await self._container.db.add_watched_deployer(address, chain_id, reason)

    async def get_cached_score(self, address: str, chain_id: int = 56) -> Optional[Dict]:
        """Return cached contract risk score if available."""
        return await self._container.db.get_contract_score(address, chain_id)
