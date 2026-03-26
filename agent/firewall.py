"""Agent Transaction Firewall API — hot plane endpoints."""

import asyncio
import time
import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from agent.policy_engine import AgentPolicyEngine
from core.analyzer import AnalysisContext

logger = logging.getLogger(__name__)


def _fire_and_forget(coro, label: str = "background"):
    """Schedule a coroutine as a fire-and-forget task with exception logging."""
    task = asyncio.create_task(coro)
    def _done_cb(t):
        if t.cancelled():
            return
        exc = t.exception()
        if exc:
            logger.error("Fire-and-forget task '%s' failed: %s", label, exc, exc_info=exc)
    task.add_done_callback(_done_cb)
    return task


# --- Request/Response Models ---

class TransactionData(BaseModel):
    sender: str = Field(alias="from")
    to: str
    data: str = "0x"
    value: str = "0"
    chain_id: int = Field(default=56, alias="chain_id")

    model_config = ConfigDict(populate_by_name=True)


class AgentFirewallRequest(BaseModel):
    agent_id: str
    transaction: TransactionData
    context: Optional[Dict] = None


class AgentRegisterRequest(BaseModel):
    agent_id: str
    owner_address: str
    owner_telegram: Optional[str] = None
    owner_webhook: Optional[str] = None
    policy: Optional[Dict] = None


class AgentPolicyUpdateRequest(BaseModel):
    agent_id: str
    policy: Dict


# --- Router Factory ---

def create_agent_firewall_router(container) -> APIRouter:
    """Create the agent firewall router with injected dependencies."""
    router = APIRouter(tags=["Agent Firewall"])
    policy_engine = AgentPolicyEngine()

    async def _require_api_key(request: Request) -> Dict:
        """Validate API key from header."""
        raw_key = request.headers.get("X-API-Key", "")
        if not raw_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        key_info = await container.auth_manager.validate_key(raw_key)
        if not key_info:
            raise HTTPException(status_code=401, detail="Invalid API key")
        if not await container.auth_manager.check_rate_limit(key_info):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        return key_info

    async def _check_agent_authorization(key_info: Dict, agent_policy: Dict, agent_id: str):
        """Verify that the API key is authorized to act on the given agent."""
        registered_key = agent_policy.get("registered_by_key")
        if registered_key and registered_key != key_info.get("key_id"):
            raise HTTPException(
                status_code=403,
                detail=f"API key not authorized for agent {agent_id}",
            )

    @router.post("/firewall")
    async def agent_firewall(req: AgentFirewallRequest, request: Request):
        """Check a transaction against the agent's policy and risk scoring."""
        start_ms = time.time() * 1000
        key_info = await _require_api_key(request)

        # Load agent policy
        agent_policy = await container.db.get_agent_policy(req.agent_id)
        if not agent_policy:
            raise HTTPException(
                status_code=404,
                detail=f"Agent {req.agent_id} not registered. Call /api/agent/register first.",
            )

        await _check_agent_authorization(key_info, agent_policy, req.agent_id)

        tx = req.transaction
        to_addr = tx.to.lower()
        chain_id = tx.chain_id

        # 1. Check Redis verdict cache
        cached = await container.cache.get_verdict(to_addr, chain_id)
        if cached:
            # Still run policy check against cached score
            daily_spend = await container.db.get_agent_daily_spend(req.agent_id)
            tx_value_usd = _estimate_value_usd(tx.value)
            policy_result = policy_engine.evaluate(
                policy=agent_policy.get("policy", {}),
                risk_score=cached["score"],
                target_address=to_addr,
                tx_value_usd=tx_value_usd,
                daily_spend_usd=daily_spend,
            )
            verdict = policy_result.verdict
            latency = time.time() * 1000 - start_ms
            await container.db.record_agent_firewall_event(
                agent_id=req.agent_id, chain_id=chain_id,
                tx_to=to_addr, tx_value=tx.value,
                verdict=verdict, score=cached["score"],
                flags=cached.get("flags", []),
                policy_result=policy_result.checks,
                latency_ms=latency,
            )

            # Update reputation score after verdict
            if hasattr(container, "reputation_service"):
                _fire_and_forget(
                    container.reputation_service.update_from_verdict(
                        req.agent_id, verdict, cached["score"],
                    ),
                    label="reputation_update_cached",
                )

            # Track spending if allowed (Fix: cached path was missing this)
            if verdict == "ALLOW" and tx_value_usd > 0:
                await container.db.record_agent_spend(req.agent_id, tx_value_usd)

            return {
                "verdict": verdict,
                "score": cached["score"],
                "flags": cached.get("flags", []),
                "policy_check": {
                    "passed": policy_result.all_passed,
                    "checks": policy_result.checks,
                    "failed": policy_result.failed_checks,
                    "needs_owner_approval": policy_result.needs_owner_approval,
                },
                "cached": True,
                "latency_ms": round(latency, 1),
            }

        # 2. Check SQLite score cache
        db_cached = await container.db.get_contract_score(
            to_addr, chain_id, max_age_seconds=300,
        )

        simulation_result = None

        if db_cached:
            risk_score = db_cached["risk_score"]
            flags = db_cached.get("flags", [])
        else:
            # 3. Run analyzer pipeline + optional Tenderly simulation
            try:
                is_token = await container.web3_client.is_token_contract(
                    to_addr, chain_id,
                )
                ctx = AnalysisContext(
                    address=to_addr,
                    chain_id=chain_id,
                    from_address=tx.sender,
                    is_token=is_token,
                )

                if container.tenderly_simulator.is_enabled():
                    # Run analyzers + Tenderly in parallel
                    analyzer_task = container.registry.run_all(ctx)
                    sim_task = container.tenderly_simulator.simulate_transaction(
                        from_address=tx.sender,
                        to_address=to_addr,
                        data=tx.data,
                        value=tx.value,
                        chain_id=chain_id,
                    )
                    results, sim_raw = await asyncio.gather(
                        analyzer_task, sim_task, return_exceptions=True,
                    )
                    if isinstance(results, Exception):
                        raise results
                    if isinstance(sim_raw, Exception):
                        logger.warning("Tenderly simulation failed: %s", sim_raw)
                        sim_raw = None
                    simulation_result = sim_raw
                else:
                    results = await container.registry.run_all(ctx)

                risk_output = container.risk_engine.compute_from_results(
                    results, is_token,
                )
            except Exception as exc:
                logger.error(
                    "Analyzer pipeline failed for %s on chain %s: %s",
                    to_addr, chain_id, exc, exc_info=True,
                )
                raise HTTPException(
                    status_code=503,
                    detail="Analysis pipeline temporarily unavailable",
                )
            risk_score = risk_output.get("risk_score") or risk_output.get("rug_probability", 50)
            flags = risk_output.get("flags") or risk_output.get("critical_flags", [])

            # Tenderly risk augmentation
            if simulation_result:
                sim_flags = []
                if not simulation_result.get("success", True):
                    risk_score = max(risk_score, 70)
                    sim_flags.append("simulation_revert")
                asset_changes = simulation_result.get("asset_changes") or []
                has_outflow = any(
                    c.get("type") == "transfer" and c.get("from", "").lower() == tx.sender.lower()
                    for c in asset_changes
                )
                has_inflow = any(
                    c.get("type") == "transfer" and c.get("to", "").lower() == tx.sender.lower()
                    for c in asset_changes
                )
                if has_outflow and not has_inflow:
                    sim_flags.append("net_asset_outflow")
                warnings = simulation_result.get("warnings") or []
                if any("reentrancy" in str(w).lower() for w in warnings):
                    risk_score = max(risk_score, 80)
                    sim_flags.append("reentrancy_warning")
                flags = list(flags) + sim_flags

            # Cache in DB
            await container.db.upsert_contract_score(
                address=to_addr, chain_id=chain_id,
                risk_score=risk_score,
                risk_level=risk_output.get("risk_level", "UNKNOWN"),
                archetype=risk_output.get("risk_archetype"),
                category_scores=risk_output.get("category_scores"),
                flags=flags,
                confidence=risk_output.get("confidence") or risk_output.get("confidence_level"),
            )

            # Auto-enrich threat graph (fire-and-forget)
            if hasattr(container, "threat_graph"):
                _fire_and_forget(
                    container.threat_graph.enrich_from_scan(
                        to_addr, chain_id, risk_output,
                    ),
                    label="threat_graph_enrich",
                )

        # Cache in Redis for next hit
        await container.cache.set_verdict(to_addr, chain_id, {
            "score": risk_score, "flags": flags,
        })

        # 4. Policy check
        daily_spend = await container.db.get_agent_daily_spend(req.agent_id)
        tx_value_usd = _estimate_value_usd(tx.value)
        policy_result = policy_engine.evaluate(
            policy=agent_policy.get("policy", {}),
            risk_score=risk_score,
            target_address=to_addr,
            tx_value_usd=tx_value_usd,
            daily_spend_usd=daily_spend,
        )
        verdict = policy_result.verdict

        latency = time.time() * 1000 - start_ms

        # Record event
        await container.db.record_agent_firewall_event(
            agent_id=req.agent_id, chain_id=chain_id,
            tx_to=to_addr, tx_value=tx.value,
            verdict=verdict, score=risk_score, flags=flags,
            policy_result=policy_result.checks,
            latency_ms=latency,
        )

        # Update reputation score after verdict
        if hasattr(container, "reputation_service"):
            _fire_and_forget(
                container.reputation_service.update_from_verdict(
                    req.agent_id, verdict, risk_score,
                ),
                label="reputation_update",
            )

        # Track spending if allowed
        if verdict == "ALLOW" and tx_value_usd > 0:
            await container.db.record_agent_spend(req.agent_id, tx_value_usd)

        return {
            "verdict": verdict,
            "score": risk_score,
            "flags": flags,
            "policy_check": {
                "passed": policy_result.all_passed,
                "checks": policy_result.checks,
                "failed": policy_result.failed_checks,
                "needs_owner_approval": policy_result.needs_owner_approval,
            },
            "simulation": {
                "success": simulation_result.get("success"),
                "asset_deltas": simulation_result.get("asset_changes"),
                "warnings": simulation_result.get("warnings"),
                "gas_used": simulation_result.get("gas_used"),
            } if simulation_result else None,
            "cached": False,
            "latency_ms": round(latency, 1),
        }

    @router.post("/register")
    async def register_agent(req: AgentRegisterRequest, request: Request):
        """Register an agent with a firewall policy."""
        key_info = await _require_api_key(request)
        await container.db.upsert_agent_policy(
            agent_id=req.agent_id,
            owner_address=req.owner_address,
            owner_telegram=req.owner_telegram,
            owner_webhook=req.owner_webhook,
            tier=key_info.get("tier", "free"),
            policy=req.policy or {},
            registered_by_key=key_info.get("key_id"),
        )
        return {
            "agent_id": req.agent_id,
            "status": "registered",
            "tier": key_info.get("tier", "free"),
        }

    @router.put("/policy")
    async def update_policy(req: AgentPolicyUpdateRequest, request: Request):
        """Update an agent's firewall policy."""
        key_info = await _require_api_key(request)
        existing = await container.db.get_agent_policy(req.agent_id)
        if not existing:
            raise HTTPException(
                status_code=404,
                detail=f"Agent {req.agent_id} not registered",
            )
        await _check_agent_authorization(key_info, existing, req.agent_id)
        await container.db.upsert_agent_policy(
            agent_id=req.agent_id,
            owner_address=existing["owner_address"],
            tier=existing["tier"],
            policy=req.policy,
        )
        return {"agent_id": req.agent_id, "status": "updated"}

    @router.get("/policy")
    async def get_policy(agent_id: str, request: Request):
        """Get an agent's current policy."""
        key_info = await _require_api_key(request)
        policy = await container.db.get_agent_policy(agent_id)
        if not policy:
            raise HTTPException(
                status_code=404,
                detail=f"Agent {agent_id} not registered",
            )
        await _check_agent_authorization(key_info, policy, agent_id)
        return policy

    @router.get("/history")
    async def get_history(agent_id: str, request: Request, limit: int = 50):
        """Get an agent's firewall check history."""
        key_info = await _require_api_key(request)
        agent_policy = await container.db.get_agent_policy(agent_id)
        if not agent_policy:
            raise HTTPException(
                status_code=404,
                detail=f"Agent {agent_id} not registered",
            )
        await _check_agent_authorization(key_info, agent_policy, agent_id)
        limit = max(1, min(limit, 1000))
        return await container.db.get_agent_firewall_history(
            agent_id, limit=limit,
        )

    return router


def _estimate_value_usd(value_wei: str) -> float:
    """Rough BNB->USD estimate. Replace with oracle in production."""
    try:
        wei = int(value_wei) if value_wei else 0
        bnb = wei / 1e18
        return bnb * 600  # ~$600/BNB estimate -- replace with price feed
    except (ValueError, TypeError):
        return 0.0
