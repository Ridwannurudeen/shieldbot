"""Threat Graph API router — endpoints for querying the cross-chain threat graph."""

import logging
from fastapi import APIRouter, Request, HTTPException

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

    return router
