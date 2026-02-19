"""Campaign Graph Radar v1 — cross-chain entity correlation for scam campaign detection.

Links deployers across chains, detects coordinated scam campaigns by clustering
contracts based on shared funders, deployers, code similarity, and temporal patterns.
"""

import asyncio
import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Minimum contracts from same deployer/funder to flag as campaign
CAMPAIGN_THRESHOLD = 3

# Bytecode similarity threshold (% of matching 4-byte selectors)
CODE_SIMILARITY_THRESHOLD = 0.7


class CampaignService:
    """Cross-chain campaign detection and entity correlation."""

    def __init__(self, web3_client, db):
        self._web3 = web3_client
        self._db = db

    async def get_entity_graph(self, address: str) -> Dict:
        """Build a complete entity graph for an address across all chains.

        Returns deployer/funder links, related contracts across chains,
        campaign indicators, and risk signals.
        """
        addr = address.lower()

        # Get base graph from existing DB infrastructure
        base_graph = await self._db.get_campaign_graph(addr)

        # Find cross-chain links for the deployer
        deployer = base_graph.get('deployer') or addr
        cross_chain = await self._find_cross_chain_contracts(deployer)

        # Find all contracts sharing the same funder
        funder = base_graph.get('funder')
        funder_cluster = []
        if funder:
            funder_cluster = await self._find_funder_cluster(funder)

        # Compute campaign indicators
        campaign = self._assess_campaign(
            base_graph, cross_chain, funder_cluster
        )

        return {
            **base_graph,
            'cross_chain_contracts': cross_chain,
            'funder_cluster': funder_cluster,
            'campaign': campaign,
        }

    async def _find_cross_chain_contracts(self, deployer: str) -> List[Dict]:
        """Find all contracts deployed by the same address across all chains."""
        deployer = deployer.lower()
        try:
            cursor = await self._db._db.execute("""
                SELECT contract_address, chain_id, deploy_tx_hash, indexed_at
                FROM deployers
                WHERE deployer_address = ?
                ORDER BY indexed_at DESC
            """, (deployer,))
            rows = await cursor.fetchall()
            contracts = []
            for row in rows:
                # Get risk score if available
                score_cursor = await self._db._db.execute("""
                    SELECT risk_score, risk_level, archetype
                    FROM contract_scores
                    WHERE address = ? AND chain_id = ?
                """, (row[0], row[1]))
                score_row = await score_cursor.fetchone()

                contracts.append({
                    'contract': row[0],
                    'chain_id': row[1],
                    'tx_hash': row[2],
                    'indexed_at': row[3],
                    'risk_score': score_row[0] if score_row else None,
                    'risk_level': score_row[1] if score_row else None,
                    'archetype': score_row[2] if score_row else None,
                })
            return contracts
        except Exception as e:
            logger.error(f"Cross-chain lookup error: {e}")
            return []

    async def _find_funder_cluster(self, funder: str) -> List[Dict]:
        """Find all deployers funded by the same address, and their contracts."""
        funder = funder.lower()
        try:
            # Find all deployers with this funder
            cursor = await self._db._db.execute("""
                SELECT fl.deployer_address, fl.chain_id, fl.funding_value_wei,
                       COUNT(d.contract_address) as contract_count
                FROM funder_links fl
                LEFT JOIN deployers d ON d.deployer_address = fl.deployer_address
                WHERE fl.funder_address = ?
                GROUP BY fl.deployer_address, fl.chain_id
                ORDER BY contract_count DESC
            """, (funder,))
            rows = await cursor.fetchall()

            cluster = []
            for row in rows:
                # Get risk scores of contracts from this deployer
                score_cursor = await self._db._db.execute("""
                    SELECT cs.risk_score, cs.risk_level
                    FROM contract_scores cs
                    JOIN deployers d ON cs.address = d.contract_address AND cs.chain_id = d.chain_id
                    WHERE d.deployer_address = ?
                """, (row[0],))
                scores = await score_cursor.fetchall()
                high_risk_count = sum(1 for s in scores if s[1] == 'HIGH')

                cluster.append({
                    'deployer': row[0],
                    'chain_id': row[1],
                    'funding_value_wei': str(row[2]),
                    'contract_count': row[3],
                    'high_risk_contracts': high_risk_count,
                })
            return cluster
        except Exception as e:
            logger.error(f"Funder cluster lookup error: {e}")
            return []

    def _assess_campaign(
        self,
        base_graph: Dict,
        cross_chain: List[Dict],
        funder_cluster: List[Dict],
    ) -> Dict:
        """Assess whether the entity is part of a coordinated scam campaign."""
        indicators = []
        risk_boost = 0
        is_campaign = False

        # Check 1: Same deployer, multiple chains
        chains_used = set()
        for c in cross_chain:
            chains_used.add(c['chain_id'])
        if len(chains_used) >= 2:
            indicators.append(
                f"Deployer active on {len(chains_used)} chains "
                f"({', '.join(str(c) for c in sorted(chains_used))})"
            )
            risk_boost += 10

        # Check 2: High volume deployer
        total_deployed = len(cross_chain)
        if total_deployed >= CAMPAIGN_THRESHOLD:
            indicators.append(
                f"Deployer has created {total_deployed} contracts"
            )
            risk_boost += 15
            is_campaign = True

        # Check 3: Many high-risk contracts from same deployer
        high_risk = [c for c in cross_chain if c.get('risk_level') == 'HIGH']
        if len(high_risk) >= 2:
            indicators.append(
                f"{len(high_risk)} of {total_deployed} contracts are HIGH risk"
            )
            risk_boost += 20
            is_campaign = True

        # Check 4: Funder funds multiple deployers (coordinated operation)
        if len(funder_cluster) >= 2:
            total_deployers = len(funder_cluster)
            total_from_funder = sum(f['contract_count'] for f in funder_cluster)
            indicators.append(
                f"Funder has bankrolled {total_deployers} deployers "
                f"({total_from_funder} total contracts)"
            )
            risk_boost += 15
            is_campaign = True

        # Check 5: Funder cluster has high-risk contracts
        cluster_high_risk = sum(f['high_risk_contracts'] for f in funder_cluster)
        if cluster_high_risk >= 3:
            indicators.append(
                f"Funder network has {cluster_high_risk} HIGH-risk contracts"
            )
            risk_boost += 20
            is_campaign = True

        severity = "NONE"
        if risk_boost >= 40:
            severity = "HIGH"
        elif risk_boost >= 20:
            severity = "MEDIUM"
        elif risk_boost > 0:
            severity = "LOW"

        return {
            'is_campaign': is_campaign,
            'severity': severity,
            'risk_boost': min(risk_boost, 50),
            'indicators': indicators,
            'chains_involved': sorted(chains_used),
            'total_contracts': total_deployed,
            'high_risk_contracts': len(high_risk),
        }

    async def get_top_campaigns(self, limit: int = 20) -> List[Dict]:
        """Get the most prolific deployers/funders (likely campaign operators)."""
        try:
            cursor = await self._db._db.execute("""
                SELECT d.deployer_address,
                       COUNT(DISTINCT d.contract_address) as contract_count,
                       COUNT(DISTINCT d.chain_id) as chain_count,
                       fl.funder_address
                FROM deployers d
                LEFT JOIN funder_links fl ON d.deployer_address = fl.deployer_address
                GROUP BY d.deployer_address
                HAVING contract_count >= ?
                ORDER BY contract_count DESC
                LIMIT ?
            """, (CAMPAIGN_THRESHOLD, limit))
            rows = await cursor.fetchall()

            campaigns = []
            for row in rows:
                # Get risk profile of their contracts
                score_cursor = await self._db._db.execute("""
                    SELECT cs.risk_level, COUNT(*) as cnt
                    FROM contract_scores cs
                    JOIN deployers d ON cs.address = d.contract_address AND cs.chain_id = d.chain_id
                    WHERE d.deployer_address = ?
                    GROUP BY cs.risk_level
                """, (row[0],))
                risk_profile = {r[0]: r[1] for r in await score_cursor.fetchall()}

                campaigns.append({
                    'deployer': row[0],
                    'contract_count': row[1],
                    'chain_count': row[2],
                    'funder': row[3],
                    'risk_profile': risk_profile,
                })
            return campaigns
        except Exception as e:
            logger.error(f"Top campaigns error: {e}")
            return []
