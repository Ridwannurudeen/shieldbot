"""Reputation API router — trust scoring endpoints for AI agents."""

import logging
from typing import List

from fastapi import APIRouter, Request, HTTPException

logger = logging.getLogger(__name__)


def create_reputation_router(container) -> APIRouter:
    """Create the reputation scoring router with injected dependencies."""
    router = APIRouter(tags=["Reputation"])
    reputation = container.reputation_service

    async def _require_api_key(request: Request) -> dict:
        raw_key = request.headers.get("X-API-Key", "")
        if not raw_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        key_info = await container.auth_manager.validate_key(raw_key)
        if not key_info:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return key_info

    @router.get("/leaderboard")
    async def leaderboard(limit: int = 50):
        """Top trusted agents by composite score (public)."""
        limit = max(1, min(limit, 100))
        return await reputation.get_leaderboard(limit)

    @router.post("/batch")
    async def batch_reputation(request: Request):
        """Bulk lookup (max 100 agents). Requires API key."""
        await _require_api_key(request)
        body = await request.json()
        agent_ids = body.get("agent_ids", [])[:100]
        if not agent_ids:
            raise HTTPException(status_code=400, detail="agent_ids required")
        return await reputation.batch_lookup(agent_ids)

    @router.get("/{agent_id}")
    async def get_reputation(agent_id: str):
        """Get composite trust score for an agent (public)."""
        result = await reputation.get_trust_score(agent_id)
        return result

    @router.get("/{agent_id}/history")
    async def get_reputation_history(agent_id: str, days: int = 30):
        """Score changes over time (public)."""
        days = max(1, min(days, 365))
        return await reputation.get_score_history(agent_id, days)

    @router.get("/{agent_id}/verified")
    async def check_verified(agent_id: str):
        """Check if agent qualifies for verified badge (public)."""
        return await reputation.check_verified_badge(agent_id)

    return router
