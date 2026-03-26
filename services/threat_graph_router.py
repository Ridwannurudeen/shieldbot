"""Threat Graph API router — endpoints for querying the cross-chain threat graph."""

import logging
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


def create_threat_graph_router(container) -> APIRouter:
    """Create the threat graph router with injected dependencies."""
    router = APIRouter(tags=["Threat Graph"])
    graph = container.threat_graph

    async def _require_api_key(request: Request) -> dict:
        raw_key = request.headers.get("X-API-Key", "")
        if not raw_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        key_info = await container.auth_manager.validate_key(raw_key)
        if not key_info:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return key_info

    @router.get("/check/{address}")
    async def check_address(
        address: str, chain_id: int = 56, max_depth: int = 3
    ):
        """Check if address is connected to known threat clusters (public)."""
        if max_depth < 1:
            max_depth = 1
        max_depth = min(max_depth, 5)
        result = await graph.check_address(address, chain_id, max_depth)
        return result

    @router.get("/cluster/{cluster_id}")
    async def get_cluster(cluster_id: str):
        """Get full cluster details (public)."""
        result = await graph.get_cluster(cluster_id)
        if not result or result.get("size", 0) == 0:
            raise HTTPException(status_code=404, detail="Cluster not found")
        return result

    @router.get("/stats")
    async def get_stats():
        """Graph statistics (public)."""
        return await graph.get_stats()

    @router.get("/search")
    async def search_graph(
        request: Request,
        min_connections: int = 5, min_flagged_ratio: float = 0.5
    ):
        """Find suspicious address patterns. Requires API key."""
        await _require_api_key(request)
        min_connections = max(1, min_connections)  # Enforce lower bound
        return await graph.search(min_connections, min_flagged_ratio)

    @router.post("/seed")
    async def seed_graph(request: Request, min_risk_score: int = 50, limit: int = 500):
        """Seed the threat graph from existing scored contracts. Requires admin secret."""
        admin_secret = request.headers.get("X-Admin-Secret", "")
        if not admin_secret:
            raise HTTPException(status_code=401, detail="Missing X-Admin-Secret header")
        expected = getattr(container.settings, "webhook_secret", "")
        if not expected or admin_secret != expected:
            raise HTTPException(status_code=403, detail="Invalid admin secret")

        # Get all scored contracts above threshold
        scored = await container.db.get_all_scored_contracts(
            min_risk_score=min_risk_score, limit=limit,
        )
        seeded = 0
        for contract in scored:
            try:
                await graph.enrich_from_scan(
                    address=contract["address"],
                    chain_id=contract["chain_id"],
                    scan_result=contract,
                )
                seeded += 1
            except Exception as exc:
                logger.warning("Seed enrichment failed for %s: %s", contract["address"], exc)

        # Rebuild clusters and refresh hot cache
        await graph.analyze_clusters()
        await graph.refresh_hot_cache()

        return {
            "seeded": seeded,
            "total_candidates": len(scored),
            "stats": await graph.get_stats(),
        }

    return router
