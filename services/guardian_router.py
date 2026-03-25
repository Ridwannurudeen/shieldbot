"""Guardian API router — wallet health monitoring endpoints."""

import re
import logging

from fastapi import APIRouter, Request, HTTPException

logger = logging.getLogger(__name__)

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def _validate_address(addr: str) -> str:
    """Validate Ethereum address format."""
    if not _ADDRESS_RE.match(addr):
        raise HTTPException(status_code=400, detail="Invalid wallet address format")
    return addr.lower()


def create_guardian_router(container) -> APIRouter:
    """Create the portfolio guardian router with injected dependencies."""
    router = APIRouter(tags=["Portfolio Guardian"])
    guardian = container.guardian_service

    async def _require_api_key(request: Request) -> dict:
        raw_key = request.headers.get("X-API-Key", "")
        if not raw_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        key_info = await container.auth_manager.validate_key(raw_key)
        if not key_info:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return key_info

    @router.get("/wallets")
    async def list_wallets(request: Request):
        """List monitored wallets for the authenticated user."""
        key_info = await _require_api_key(request)
        return await guardian.get_wallets(key_info.get("key_id", ""))

    @router.post("/wallets")
    async def register_wallet(request: Request):
        """Register a wallet for guardian monitoring."""
        key_info = await _require_api_key(request)
        body = await request.json()
        wallet_address = body.get("wallet_address", "")
        if not wallet_address:
            raise HTTPException(status_code=400, detail="wallet_address required")
        _validate_address(wallet_address)
        chain_id = body.get("chain_id", 56)
        is_agent = body.get("is_agent_wallet", False)
        result = await guardian.register_wallet(
            wallet_address, chain_id, owner_id=key_info.get("key_id", ""), is_agent=is_agent,
        )
        return result

    @router.get("/health/{wallet_address}")
    async def get_health(request: Request, wallet_address: str, chain_id: int = 56):
        """Get wallet health score with component breakdown."""
        await _require_api_key(request)
        _validate_address(wallet_address)
        return await guardian.get_health(wallet_address, chain_id)

    @router.get("/approvals/{wallet_address}")
    async def get_approvals(request: Request, wallet_address: str, chain_id: int = 56):
        """Get all token approvals, risk-ranked."""
        await _require_api_key(request)
        _validate_address(wallet_address)
        return await guardian.get_approvals(wallet_address.lower(), chain_id)

    @router.post("/revoke/build")
    async def build_revoke(request: Request):
        """Build unsigned batch revoke transactions."""
        await _require_api_key(request)
        body = await request.json()
        wallet = body.get("wallet_address", "")
        approvals = body.get("approvals", [])
        if not wallet:
            raise HTTPException(status_code=400, detail="wallet_address required")
        _validate_address(wallet)
        return await guardian.build_revoke_tx(wallet, approvals)

    @router.get("/alerts")
    async def get_alerts(request: Request, wallet_address: str = None, limit: int = 50):
        """Get recent guardian alerts."""
        await _require_api_key(request)
        if wallet_address:
            _validate_address(wallet_address)
        return await guardian.get_alerts(wallet_address, min(limit, 200))

    @router.put("/alerts/{alert_id}/acknowledge")
    async def acknowledge_alert(request: Request, alert_id: int):
        """Mark alert as acknowledged."""
        await _require_api_key(request)
        result = await guardian.acknowledge_alert(alert_id)
        if not result:
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"acknowledged": True}

    return router
