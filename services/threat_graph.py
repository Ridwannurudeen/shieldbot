"""Cross-chain threat intelligence graph with BFS/DFS traversal and cluster analysis."""

import json
import time
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class ThreatGraphService:
    """Cross-chain threat intelligence graph with BFS/DFS traversal."""

    def __init__(self, db):
        self._db = db
        self._hot_cache: Dict[str, Dict] = {}  # In-memory adjacency for top clusters
        self._cache_refreshed_at: float = 0

    async def add_edge(
        self,
        source: str,
        target: str,
        chain_id: int,
        relationship: str,
        evidence: Dict = None,
        confidence: float = 0.5,
    ):
        """Add or update an edge in the threat graph."""
        confidence = max(0.0, min(1.0, confidence))
        await self._db.add_threat_graph_edge(
            source=source.lower(),
            target=target.lower(),
            chain_id=chain_id,
            relationship=relationship,
            evidence=evidence,
            confidence=confidence,
        )

    async def check_address(
        self, address: str, chain_id: int = 56, max_depth: int = 3
    ) -> Dict:
        """BFS traversal from address. Returns connected nodes and cluster membership."""
        address = address.lower()
        max_depth = min(max_depth, 5)  # Cap to prevent DoS

        # Check hot cache first
        cache_key = f"{address}:{chain_id}"
        if cache_key in self._hot_cache:
            return self._hot_cache[cache_key]

        visited: Set[str] = set()
        queue: deque = deque([(address, 0)])  # (address, depth)
        edges_found: List[Dict] = []
        cluster_hits: List[Dict] = []

        while queue:
            current, depth = queue.popleft()
            if current in visited or depth > max_depth:
                continue
            visited.add(current)

            # Check cluster membership
            cluster = await self._db.get_cluster_for_address(current, chain_id)
            if cluster:
                cluster_hits.append(cluster)

            # Get outgoing and incoming edges within depth limit
            if depth < max_depth:
                out_edges = await self._db.get_edges_from(current, chain_id)
                for edge in out_edges:
                    edges_found.append(edge)
                    target = edge["target_address"].lower()
                    if target not in visited:
                        queue.append((target, depth + 1))

                in_edges = await self._db.get_edges_to(current, chain_id)
                for edge in in_edges:
                    edges_found.append(edge)
                    src = edge["source_address"].lower()
                    if src not in visited:
                        queue.append((src, depth + 1))

        result = {
            "address": address,
            "chain_id": chain_id,
            "connected_to_cluster": len(cluster_hits) > 0,
            "clusters": cluster_hits,
            "edges_found": len(edges_found),
            "nodes_visited": len(visited),
            "max_depth_reached": max_depth,
        }

        return result

    async def get_cluster(self, cluster_id: str) -> Dict:
        """Full cluster details: members, roles, stats."""
        members = await self._db.get_cluster_members(cluster_id)
        if not members:
            return {"cluster_id": cluster_id, "members": [], "size": 0}

        # Compute stats
        addresses = [m["address"] for m in members]
        roles = defaultdict(int)
        for m in members:
            roles[m.get("role", "member")] += 1

        return {
            "cluster_id": cluster_id,
            "members": members,
            "size": len(members),
            "roles": dict(roles),
        }

    async def get_stats(self) -> Dict:
        """Graph statistics: total edges, clusters, most active."""
        return await self._db.get_graph_stats()

    async def search(
        self, min_connections: int = 5, min_flagged_ratio: float = 0.5
    ) -> List[Dict]:
        """Find addresses matching criteria (high connectivity)."""
        stats = await self._db.get_graph_stats()
        total_edges = stats.get("total_edges", 0)

        # Get all edges grouped by source to find highly-connected nodes
        cursor = await self._db._db.execute(
            "SELECT source_address, COUNT(*) as cnt "
            "FROM threat_graph_edges "
            "GROUP BY source_address "
            "HAVING cnt >= ? "
            "ORDER BY cnt DESC "
            "LIMIT 50",
            (min_connections,),
        )
        rows = await cursor.fetchall()

        results = []
        for row in rows:
            addr = row[0]
            connection_count = row[1]

            # Check cluster membership
            cluster = await self._db.get_cluster_for_address(addr, 56)
            results.append({
                "address": addr,
                "connections": connection_count,
                "cluster": cluster,
            })

        return results

    async def enrich_from_scan(
        self, address: str, chain_id: int, scan_result: Dict
    ):
        """Auto-enrich graph from scan results (deployer edges, funder links)."""
        # Extract deployer relationship
        deployer = scan_result.get("deployer") or scan_result.get("contract_creator")
        if deployer:
            await self.add_edge(
                deployer, address, chain_id, "deployed",
                evidence={"from_scan": True},
                confidence=0.95,
            )

        # Extract funder relationship
        funder = scan_result.get("funded_by") or scan_result.get("deployer_funder")
        if funder and deployer:
            await self.add_edge(
                funder, deployer, chain_id, "funded",
                evidence={"from_scan": True},
                confidence=0.8,
            )

        # If scan found flags, mark relationships with higher confidence
        flags = scan_result.get("flags") or scan_result.get("critical_flags") or []
        if flags and deployer:
            risk_score = scan_result.get("risk_score") or scan_result.get(
                "rug_probability", 50
            )
            confidence = min(1.0, risk_score / 100)
            await self.add_edge(
                deployer, address, chain_id, "deployed",
                evidence={"flags": flags, "risk_score": risk_score},
                confidence=confidence,
            )

    async def analyze_clusters(self):
        """Find connected components using Union-Find, assign cluster IDs."""
        cursor = await self._db._db.execute(
            "SELECT source_address, target_address, chain_id FROM threat_graph_edges"
        )
        edges = await cursor.fetchall()

        if not edges:
            logger.info("Cluster analysis: no edges found")
            return

        # Union-Find
        parent: Dict[str, str] = {}

        def find(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent[x], parent[x])
                x = parent[x]
            return x

        def union(a: str, b: str):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        # Build components
        for src, tgt, _ in edges:
            union(src.lower(), tgt.lower())

        # Group by component
        all_addrs: Set[str] = set()
        for src, tgt, _ in edges:
            all_addrs.add(src.lower())
            all_addrs.add(tgt.lower())

        components: Dict[str, Set[str]] = defaultdict(set)
        for addr in all_addrs:
            root = find(addr)
            components[root].add(addr)

        # Only keep clusters with 3+ members
        cluster_count = 0
        for root, members in components.items():
            if len(members) < 3:
                continue
            cluster_id = f"C-{abs(hash(root)) % 100000}"
            for addr in members:
                await self._db.upsert_cluster_member(
                    cluster_id=cluster_id,
                    address=addr,
                    chain_id=56,
                    role="member",
                    confidence=0.5,
                )
            cluster_count += 1

        logger.info("Cluster analysis complete: %d clusters found", cluster_count)

    async def refresh_hot_cache(self):
        """Load top clusters into memory for fast traversal."""
        top = await self._db.get_top_clusters(limit=100)
        new_cache: Dict[str, Dict] = {}

        for cluster_info in top:
            cluster_id = cluster_info["cluster_id"]
            members = await self._db.get_cluster_members(cluster_id)
            for m in members:
                key = f"{m['address']}:{m['chain_id']}"
                new_cache[key] = {
                    "address": m["address"],
                    "chain_id": m["chain_id"],
                    "connected_to_cluster": True,
                    "clusters": [
                        {
                            "cluster_id": cluster_id,
                            "address": m["address"],
                            "chain_id": m["chain_id"],
                            "role": m.get("role", "member"),
                            "confidence": m.get("confidence", 0.5),
                        }
                    ],
                    "edges_found": 0,
                    "nodes_visited": 1,
                    "max_depth_reached": 0,
                    "from_cache": True,
                }

        self._hot_cache = new_cache
        self._cache_refreshed_at = time.time()
        logger.info(
            "Hot cache refreshed: %d addresses from %d clusters",
            len(new_cache),
            len(top),
        )
