"""
BNB Greenfield Storage Service
Uploads forensic reports as immutable JSON objects when risk score >= 50.
Uses httpx for async HTTP and EIP-191 signing for authentication.
"""
import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Optional, Dict, Any

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct

logger = logging.getLogger(__name__)

GREENFIELD_REST_API = "https://gnfd-testnet-sp1.bnbchain.org"


def _generate_report_id(target_address: str, timestamp: int) -> str:
    """Generate deterministic report ID from address + timestamp."""
    raw = f"{target_address.lower()}-{timestamp}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class GreenfieldService:
    """Async BNB Greenfield storage client using REST API."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)
        self.bucket_name = os.getenv("GREENFIELD_BUCKET_NAME", "shieldbot-reports")
        private_key = os.getenv("GREENFIELD_PRIVATE_KEY", "")
        self.address = os.getenv("GREENFIELD_ADDRESS", "")

        if not private_key or private_key.startswith("your_"):
            logger.warning("GREENFIELD_PRIVATE_KEY not configured - Greenfield storage disabled")
            self.account = None
            self.enabled = False
        else:
            try:
                self.account = Account.from_key(private_key)
                self.enabled = True
                logger.info("Greenfield storage enabled")
            except Exception as e:
                logger.error(f"Invalid GREENFIELD_PRIVATE_KEY: {e}")
                self.account = None
                self.enabled = False

    async def close(self):
        await self.client.aclose()

    def is_enabled(self) -> bool:
        return self.enabled

    async def upload_report(
        self,
        target_address: str,
        risk_score: float,
        category_scores: Dict[str, float],
        full_analysis: Dict[str, Any],
        tx_hash: Optional[str] = None,
    ) -> Optional[str]:
        """
        Upload forensic report to Greenfield as JSON object.
        Returns public URL on success, None on failure.
        Retries once on transient failure.
        """
        if not self.enabled:
            return None

        for attempt in range(2):
            try:
                timestamp = int(time.time())
                report_id = _generate_report_id(target_address, timestamp)
                object_name = f"reports/{report_id}.json"

                report_data = {
                    "report_id": report_id,
                    "target_address": target_address.lower(),
                    "transaction_hash": tx_hash,
                    "risk_score": risk_score,
                    "category_scores": category_scores,
                    "analysis": full_analysis,
                    "timestamp": timestamp,
                }

                report_bytes = json.dumps(report_data, indent=2).encode("utf-8")
                url = await self._create_object(object_name, report_bytes)

                if url:
                    logger.info(f"Report uploaded to Greenfield: {url}")
                    return url

                logger.error(f"Failed to create Greenfield object for {report_id}")

            except Exception as e:
                logger.error(f"Greenfield upload attempt {attempt + 1} failed: {e}")

            if attempt == 0:
                await asyncio.sleep(2.0)

        return None

    async def _create_object(self, object_name: str, content: bytes) -> Optional[str]:
        """Create object on Greenfield using REST API with signed request."""
        try:
            # Step 1: Create object metadata
            url = f"{GREENFIELD_REST_API}/greenfield/storage/create_object"

            create_payload = {
                "bucket_name": self.bucket_name,
                "object_name": object_name,
                "payload_size": len(content),
                "visibility": "VISIBILITY_TYPE_PUBLIC_READ",
                "content_type": "application/json",
                "redundancy_type": "REDUNDANCY_EC_TYPE",
            }

            signature = self._sign_request(create_payload)

            headers = {
                "Authorization": f"GNFD1-ECDSA,Signature={signature}",
                "X-Gnfd-User-Address": self.address,
                "Content-Type": "application/json",
            }

            response = await self.client.post(url, json=create_payload, headers=headers)

            if response.status_code not in [200, 201]:
                logger.error(f"Greenfield create_object failed: {response.status_code} {response.text}")
                return None

            # Step 2: Upload object data
            upload_url = f"{GREENFIELD_REST_API}/greenfield/storage/put_object"

            upload_headers = {
                "Authorization": f"GNFD1-ECDSA,Signature={signature}",
                "X-Gnfd-User-Address": self.address,
                "Content-Type": "application/json",
            }

            upload_response = await self.client.put(
                upload_url,
                content=content,
                headers=upload_headers,
                params={"bucket_name": self.bucket_name, "object_name": object_name},
            )

            if upload_response.status_code not in [200, 201]:
                logger.error(f"Greenfield put_object failed: {upload_response.status_code}")
                return None

            return f"https://gnfd-testnet-sp1.bnbchain.org/view/{self.bucket_name}/{object_name}"

        except Exception as e:
            logger.error(f"Greenfield object creation failed: {e}")
            return None

    def _sign_request(self, payload: Dict) -> str:
        """Sign Greenfield API request using EIP-191 signature."""
        message_str = json.dumps(payload, sort_keys=True)
        message_hash = hashlib.sha256(message_str.encode()).digest()
        signable_message = encode_defunct(message_hash)
        signed_message = self.account.sign_message(signable_message)
        return signed_message.signature.hex()
