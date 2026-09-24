"""Agent tool layer — thin async wrappers around existing ShieldBot services.

Each method provides a single capability the AI agent can invoke.
No business logic lives here; all scoring, flagging, and analysis is
delegated to the underlying services in core/ and services/.
"""

import logging
import re
from typing import Dict, List, Optional

from core.analyzer import AnalysisContext
from services.launch_discovery import CHAIN_ID as LAUNCH_CHAIN_ID
from services.robinhood_assets import with_impostor_check

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

    async def scan_contract(
        self, address: str, chain_id: int = 56, deadline: Optional[float] = None
    ) -> Dict:
        """Run all analyzers on a contract and return composite risk score.

        ``deadline`` replaces the interactive scan deadline; background scans pass
        core.registry.BACKGROUND_SCAN_DEADLINE_SECONDS. A Robinhood Chain (4663) result also
        carries its check against the official Robinhood tokens (services.robinhood_assets).
        """
        address = _validate_address(address)
        ctx = AnalysisContext(address=address, chain_id=chain_id)
        results = await self._container.registry.run_all(ctx, deadline=deadline)
        risk = self._container.risk_engine.compute_from_results(results)
        # The honeypot analyzer's data rides along so a published verdict can cite the simulation behind it.
        honeypot = next((result.data for result in results if result.name == "honeypot"), None)
        scan = {**risk, "honeypot_data": honeypot}
        if chain_id == LAUNCH_CHAIN_ID:
            scan = with_impostor_check(scan, await self._container.robinhood_assets.check_onchain(address))
        return scan

    async def check_deployer(self, address: str, chain_id: int = 56) -> Optional[Dict]:
        """Look up deployer risk summary for a contract address."""
        address = _validate_address(address)
        return await self._container.db.get_deployer_risk_summary(address, chain_id)

    async def check_honeypot(self, address: str, chain_id: int = 56) -> Dict:
        """Run honeypot simulation on a token address."""
        address = _validate_address(address)
        return await self._container.honeypot_service.fetch_honeypot_data(address, chain_id=chain_id)

    async def get_market_data(self, address: str, chain_id: int = 56) -> Dict:
        """Fetch DexScreener market data for a token address."""
        address = _validate_address(address)
        return await self._container.dex_service.fetch_token_market_data(address, chain_id=chain_id)

    async def query_campaign(self, address: str, chain_id: int = None) -> Dict:
        """Get deployer/funder campaign graph for an address."""
        address = _validate_address(address)
        return await self._container.db.get_campaign_graph(address, chain_id)

    async def get_funder_links(self, deployer: str, chain_id: int = None) -> Dict:
        """Get funder links for a deployer address via campaign graph."""
        deployer = _validate_address(deployer)
        return await self._container.db.get_campaign_graph(deployer, chain_id)

    async def get_agent_findings(
        self, limit: int = 10, finding_type: str = None
    ) -> List[Dict]:
        """Retrieve recent agent findings, optionally filtered by type."""
        limit = max(1, min(limit, 100))
        return await self._container.db.get_agent_findings(limit, finding_type)

    async def auto_watch_deployer(
        self, address: str, reason: str, chain_id: int = 0
    ) -> None:
        """Add a deployer to the watch list."""
        address = _validate_address(address)
        await self._container.db.add_watched_deployer(address, chain_id, reason)

    async def get_cached_score(self, address: str, chain_id: int = 56) -> Optional[Dict]:
        """Return cached contract risk score if available."""
        address = _validate_address(address)
        return await self._container.db.get_contract_score(address, chain_id)
