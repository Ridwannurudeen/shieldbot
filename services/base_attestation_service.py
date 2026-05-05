"""Read recent ShieldBot attestations from EAS on Base via GraphQL.

Uses the public base.easscan.org indexer. No auth, no API key. Falls back to
empty list if the indexer is down or not reachable — the dashboard then shows
"No attestations yet" gracefully.
"""

import os
import json
import logging
from typing import Any, Dict, List, Optional

import aiohttp
from eth_abi import decode

logger = logging.getLogger(__name__)

EAS_GRAPHQL_BASE = "https://base.easscan.org/graphql"

# Risk level uint8 -> human label (mirrors the Solidity contract)
RISK_LABELS = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "SAFE", 4: "WARNING", 5: "DANGER"}

_QUERY = """
query ShieldBotAttestations($attester: String!, $take: Int!) {
  attestations(
    where: { attester: { equals: $attester }, revoked: { equals: false } }
    orderBy: { time: desc }
    take: $take
  ) {
    id
    attester
    recipient
    time
    txid
    data
    schemaId
  }
}
"""


def _decode_attestation_data(data_hex: str) -> Optional[Dict[str, Any]]:
    """Decode the EAS attestation `data` field per the ShieldBot schema."""
    if not data_hex or not data_hex.startswith("0x"):
        return None
    try:
        raw = bytes.fromhex(data_hex[2:])
        decoded = decode(
            ["address", "uint8", "string", "uint64", "bytes32", "string"],
            raw,
        )
        return {
            "scanned_address": decoded[0],
            "risk_level": int(decoded[1]),
            "risk_label": RISK_LABELS.get(int(decoded[1]), "UNKNOWN"),
            "scan_type": decoded[2],
            "source_chain_id": int(decoded[3]),
            "evidence_hash": "0x" + decoded[4].hex(),
            "evidence_uri": decoded[5],
        }
    except Exception as e:
        logger.debug(f"Attestation decode failed: {e}")
        return None


class BaseAttestationService:
    """Reads attestations posted by ShieldBotAttestor from EAS on Base."""

    def __init__(self, attestor_address: Optional[str] = None, graphql_url: Optional[str] = None):
        self.attestor_address = (attestor_address or os.getenv("BASE_ATTESTOR_ADDRESS", "")).lower()
        self.graphql_url = graphql_url or EAS_GRAPHQL_BASE

    def is_available(self) -> bool:
        return bool(self.attestor_address)

    async def get_recent(self, limit: int = 25) -> List[Dict[str, Any]]:
        """Return up to `limit` most recent attestations, newest first."""
        if not self.is_available():
            return []
        limit = max(1, min(limit, 100))
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.graphql_url,
                    json={
                        "query": _QUERY,
                        "variables": {"attester": self.attestor_address, "take": limit},
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.json()
        except Exception as e:
            logger.warning(f"EAS GraphQL fetch failed: {e}")
            return []

        if "errors" in body:
            logger.warning(f"EAS GraphQL errors: {body['errors']}")
            return []

        results: List[Dict[str, Any]] = []
        for att in body.get("data", {}).get("attestations", []):
            decoded = _decode_attestation_data(att.get("data", ""))
            if decoded is None:
                continue
            results.append({
                "uid": att.get("id"),
                "tx_hash": att.get("txid"),
                "recipient": att.get("recipient"),
                "timestamp": att.get("time"),
                **decoded,
            })
        return results

    async def get_summary(self) -> Dict[str, Any]:
        """Aggregate counts for dashboard tiles."""
        recent = await self.get_recent(limit=100)
        by_risk: Dict[str, int] = {}
        by_chain: Dict[int, int] = {}
        for a in recent:
            label = a["risk_label"]
            by_risk[label] = by_risk.get(label, 0) + 1
            chain = a["source_chain_id"]
            by_chain[chain] = by_chain.get(chain, 0) + 1
        return {
            "total_recent": len(recent),
            "by_risk": by_risk,
            "by_source_chain": by_chain,
            "attestor": self.attestor_address,
        }
