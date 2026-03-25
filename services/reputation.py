"""Composite trust scoring for AI agents using multiple data sources.

Combines ERC-8004 registry, BAP-578 agent NFT, ShieldBot firewall verdicts,
and SentinelNet cross-chain reputation into a single weighted trust score.
"""

import json
import time
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ReputationService:
    """Composite trust scoring for AI agents using multiple data sources."""

    # Score weights (must sum to 1.0)
    WEIGHTS = {
        "erc8004": 0.30,
        "bap578": 0.20,
        "shieldbot": 0.35,
        "sentinelnet": 0.15,
    }

    # Verified badge criteria
    VERIFIED_MIN_SCORE = 75
    VERIFIED_MIN_DAYS = 30
    VERIFIED_MAX_BLOCKS_7D = 0
    VERIFIED_MIN_COMPLIANCE = 0.95

    # Cache TTL in seconds (1 hour)
    CACHE_TTL = 3600

    def __init__(self, db, cache=None, web3_client=None):
        self._db = db
        self._cache = cache
        self._web3 = web3_client

    # ── Public API ───────────────────────────────────────────────────

    async def get_trust_score(self, agent_id: str) -> Dict:
        """Get composite trust score for an agent.

        Returns: {
            agent_id, composite_score, breakdown: {erc8004, bap578, shieldbot, sentinelnet},
            verified: bool, verdict_summary: {total, allowed, blocked, warned},
            last_updated
        }
        """
        # 1. Check cache (reputation_cache table, 1h TTL)
        cached = await self._db.get_reputation_cache(agent_id)
        if cached and (time.time() - cached.get("last_fetched", 0)) < self.CACHE_TTL:
            return cached

        # 2. Calculate ShieldBot component (from our own data)
        shieldbot_score = await self._calculate_shieldbot_score(agent_id)

        # 3. Calculate ERC-8004 component (on-chain read, stub if unavailable)
        erc8004_score = await self._fetch_erc8004_score(agent_id)

        # 4. Calculate BAP-578 component (on-chain read, stub if unavailable)
        bap578_score = await self._fetch_bap578_score(agent_id)

        # 5. SentinelNet bridge score (cross-chain, stub for now)
        sentinelnet_score = await self._fetch_sentinelnet_score(agent_id)

        # 6. Weighted composite
        composite = (
            erc8004_score * self.WEIGHTS["erc8004"]
            + bap578_score * self.WEIGHTS["bap578"]
            + shieldbot_score * self.WEIGHTS["shieldbot"]
            + sentinelnet_score * self.WEIGHTS["sentinelnet"]
        )

        # 7. Get verdict summary
        summary = await self._get_verdict_summary(agent_id)

        # 8. Check verified badge
        verified = await self._check_verified(agent_id, composite, summary)

        result = {
            "agent_id": agent_id,
            "composite_score": round(composite, 2),
            "breakdown": {
                "erc8004": round(erc8004_score, 2),
                "bap578": round(bap578_score, 2),
                "shieldbot": round(shieldbot_score, 2),
                "sentinelnet": round(sentinelnet_score, 2),
            },
            "verified": verified,
            "verdict_summary": summary,
            "last_updated": time.time(),
        }

        # 9. Cache result
        await self._db.upsert_reputation_cache(agent_id, result)

        return result

    async def get_score_history(self, agent_id: str, days: int = 30) -> List[Dict]:
        """Score changes over time based on firewall verdict history."""
        cutoff = time.time() - (days * 86400)
        history = await self._db.get_agent_firewall_history(agent_id, limit=1000)

        # Filter to the requested time window
        filtered = [h for h in history if h.get("created_at", 0) >= cutoff]

        # Group by day and compute daily scores
        daily = {}
        for h in filtered:
            ts = h.get("created_at", 0)
            day_key = int(ts // 86400) * 86400  # round to day boundary
            if day_key not in daily:
                daily[day_key] = {"total": 0, "allowed": 0, "blocked": 0, "warned": 0}
            daily[day_key]["total"] += 1
            verdict = h.get("verdict", "")
            if verdict == "ALLOW":
                daily[day_key]["allowed"] += 1
            elif verdict == "BLOCK":
                daily[day_key]["blocked"] += 1
            elif verdict == "WARN":
                daily[day_key]["warned"] += 1

        result = []
        for day_ts in sorted(daily.keys()):
            d = daily[day_ts]
            allow_ratio = d["allowed"] / d["total"] if d["total"] > 0 else 0.5
            block_ratio = d["blocked"] / d["total"] if d["total"] > 0 else 0
            score = max(0, min(100, allow_ratio * 100 - block_ratio * 50))
            result.append({
                "date": day_ts,
                "score": round(score, 2),
                "verdicts": d,
            })

        return result

    async def batch_lookup(self, agent_ids: List[str]) -> List[Dict]:
        """Bulk lookup (max 100)."""
        agent_ids = agent_ids[:100]
        results = []
        for agent_id in agent_ids:
            try:
                score = await self.get_trust_score(agent_id)
                results.append(score)
            except Exception as exc:
                logger.warning("Batch lookup failed for %s: %s", agent_id, exc)
                results.append({
                    "agent_id": agent_id,
                    "error": str(exc),
                })
        return results

    async def get_leaderboard(self, limit: int = 50) -> List[Dict]:
        """Top trusted agents."""
        limit = max(1, min(limit, 100))
        return await self._db.get_reputation_leaderboard(limit)

    async def check_verified_badge(self, agent_id: str) -> Dict:
        """Check if agent qualifies for verified badge."""
        score_data = await self.get_trust_score(agent_id)
        composite = score_data.get("composite_score", 0)
        summary = score_data.get("verdict_summary", {})

        # Get agent registration age
        policy = await self._db.get_agent_policy(agent_id)
        if policy:
            age_days = (time.time() - policy.get("created_at", time.time())) / 86400
        else:
            age_days = 0

        # Check recent blocks (7 days)
        cutoff_7d = time.time() - (7 * 86400)
        history = await self._db.get_agent_firewall_history(agent_id, limit=1000)
        blocks_7d = sum(
            1 for h in history
            if h.get("verdict") == "BLOCK" and h.get("created_at", 0) >= cutoff_7d
        )

        # Calculate compliance ratio
        total = summary.get("total", 0)
        blocked = summary.get("blocked", 0)
        compliance = (total - blocked) / total if total > 0 else 0.0

        meets_score = composite >= self.VERIFIED_MIN_SCORE
        meets_age = age_days >= self.VERIFIED_MIN_DAYS
        meets_blocks = blocks_7d <= self.VERIFIED_MAX_BLOCKS_7D
        meets_compliance = compliance >= self.VERIFIED_MIN_COMPLIANCE

        qualified = meets_score and meets_age and meets_blocks and meets_compliance

        return {
            "agent_id": agent_id,
            "qualified": qualified,
            "composite_score": composite,
            "checks": {
                "min_score": {"required": self.VERIFIED_MIN_SCORE, "actual": composite, "passed": meets_score},
                "min_age_days": {"required": self.VERIFIED_MIN_DAYS, "actual": round(age_days, 1), "passed": meets_age},
                "max_blocks_7d": {"required": self.VERIFIED_MAX_BLOCKS_7D, "actual": blocks_7d, "passed": meets_blocks},
                "min_compliance": {"required": self.VERIFIED_MIN_COMPLIANCE, "actual": round(compliance, 4), "passed": meets_compliance},
            },
        }

    async def update_from_verdict(self, agent_id: str, verdict: str, risk_score: float):
        """Update ShieldBot component score after a firewall verdict.

        This invalidates the cache so the next get_trust_score recalculates.
        """
        # Invalidate cache by setting last_fetched to 0
        try:
            await self._db.invalidate_reputation_cache(agent_id)
        except Exception as exc:
            logger.debug("Cache invalidation failed for %s: %s", agent_id, exc)

    # ── Private: ShieldBot Component Score ───────────────────────────

    async def _calculate_shieldbot_score(self, agent_id: str) -> float:
        """Calculate ShieldBot trust score (0-100) from verdict history."""
        history = await self._db.get_agent_firewall_history(agent_id, limit=100)

        if not history:
            return 50.0  # Neutral for new agents

        total = len(history)
        allowed = sum(1 for h in history if h.get("verdict") == "ALLOW")
        blocked = sum(1 for h in history if h.get("verdict") == "BLOCK")

        # Base score from allow ratio
        allow_ratio = allowed / total if total > 0 else 0.5
        base_score = allow_ratio * 100

        # Penalty for blocks (each block costs more as ratio increases)
        block_ratio = blocked / total if total > 0 else 0
        block_penalty = block_ratio * 50  # Max 50 point penalty

        # Bonus for consistent clean behavior (no blocks in last 20 txs)
        recent = history[:20]
        recent_blocks = sum(1 for h in recent if h.get("verdict") == "BLOCK")
        clean_bonus = 10 if recent_blocks == 0 and len(recent) >= 10 else 0

        score = max(0, min(100, base_score - block_penalty + clean_bonus))
        return score

    # ── Private: External Source Stubs ───────────────────────────────

    async def _fetch_erc8004_score(self, agent_id: str) -> float:
        """Fetch ERC-8004 registry score. Stub returns neutral."""
        # TODO: Read from ERC-8004 registry contract on BNB Chain
        cached = await self._db.get_reputation_cache_by_registry(agent_id, "erc8004")
        if cached:
            return cached.get("trust_score", 50.0)
        return 50.0

    async def _fetch_bap578_score(self, agent_id: str) -> float:
        """Fetch BAP-578 agent NFT score. Stub returns neutral."""
        cached = await self._db.get_reputation_cache_by_registry(agent_id, "bap578")
        if cached:
            return cached.get("trust_score", 50.0)
        return 50.0

    async def _fetch_sentinelnet_score(self, agent_id: str) -> float:
        """Fetch cross-chain reputation from SentinelNet. Stub returns neutral."""
        cached = await self._db.get_reputation_cache_by_registry(agent_id, "sentinelnet")
        if cached:
            return cached.get("trust_score", 50.0)
        return 50.0

    # ── Private: Verdict Summary ─────────────────────────────────────

    async def _get_verdict_summary(self, agent_id: str) -> Dict:
        """Aggregate verdict counts for an agent."""
        history = await self._db.get_agent_firewall_history(agent_id, limit=1000)
        total = len(history)
        allowed = sum(1 for h in history if h.get("verdict") == "ALLOW")
        blocked = sum(1 for h in history if h.get("verdict") == "BLOCK")
        warned = sum(1 for h in history if h.get("verdict") == "WARN")
        return {
            "total": total,
            "allowed": allowed,
            "blocked": blocked,
            "warned": warned,
        }

    async def _check_verified(self, agent_id: str, composite: float, summary: Dict) -> bool:
        """Check if agent meets verified badge criteria (quick check for get_trust_score)."""
        if composite < self.VERIFIED_MIN_SCORE:
            return False

        total = summary.get("total", 0)
        blocked = summary.get("blocked", 0)
        if total > 0:
            compliance = (total - blocked) / total
            if compliance < self.VERIFIED_MIN_COMPLIANCE:
                return False

        # Check recent blocks (7 days)
        cutoff_7d = time.time() - (7 * 86400)
        history = await self._db.get_agent_firewall_history(agent_id, limit=1000)
        blocks_7d = sum(
            1 for h in history
            if h.get("verdict") == "BLOCK" and h.get("created_at", 0) >= cutoff_7d
        )
        if blocks_7d > self.VERIFIED_MAX_BLOCKS_7D:
            return False

        # Check registration age
        policy = await self._db.get_agent_policy(agent_id)
        if policy:
            age_days = (time.time() - policy.get("created_at", time.time())) / 86400
            if age_days < self.VERIFIED_MIN_DAYS:
                return False
        else:
            return False

        return True
