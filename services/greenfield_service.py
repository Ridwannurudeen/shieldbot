"""
BNB Greenfield Storage Service
Uploads forensic reports as immutable JSON objects when risk score >= 50.
Uses the official greenfield-python-sdk for on-chain object creation.
"""
import asyncio
import hashlib
import io
import json
import logging
import os
import time
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Public view URL base for Greenfield mainnet
GREENFIELD_VIEW_BASE = "https://greenfield-sp.bnbchain.org/view"


def _generate_report_id(target_address: str, timestamp: int) -> str:
    """Generate deterministic report ID from address + timestamp."""
    raw = f"{target_address.lower()}-{timestamp}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class GreenfieldService:
    """Async BNB Greenfield storage client using the official Python SDK."""

    def __init__(self):
        self.bucket_name = os.getenv("GREENFIELD_BUCKET_NAME", "shieldbot-reports")
        self._private_key = os.getenv("GREENFIELD_PRIVATE_KEY", "")
        self._client = None  # GreenfieldClient, initialized async
        self.enabled = False

        if not self._private_key or self._private_key.startswith("your_"):
            logger.warning("GREENFIELD_PRIVATE_KEY not configured - Greenfield storage disabled")
        else:
            # Mark as potentially enabled — full init happens in async_init
            self.enabled = True

    async def async_init(self):
        """Initialize the Greenfield SDK client. Must be called after construction."""
        if not self.enabled:
            return

        try:
            from greenfield_python_sdk.config import NetworkConfiguration
            from greenfield_python_sdk.key_manager import KeyManager
            from greenfield_python_sdk.greenfield_client import GreenfieldClient

            # Construct config directly to avoid pydantic-settings reading .env
            # (which causes extra_forbidden errors with our GREENFIELD_* vars)
            network_config = NetworkConfiguration(
                host="https://greenfield-chain.bnbchain.org",
                port=443,
                chain_id=1017,
            )
            key_manager = KeyManager(private_key=self._private_key)

            self._client = GreenfieldClient(
                network_configuration=network_config,
                key_manager=key_manager,
            )
            # Enter the async context to initialize blockchain + storage clients
            await self._client.__aenter__()
            await self._client.async_init()

            logger.info(f"Greenfield storage enabled (address: {key_manager.address})")
            self.enabled = True

        except Exception as e:
            logger.error(f"Greenfield SDK initialization failed: {e}")
            self._client = None
            self.enabled = False

    async def close(self):
        if self._client:
            try:
                await self._client.__aexit__(None, None, None)
            except Exception:
                pass
            self._client = None

    def is_enabled(self) -> bool:
        return self.enabled and self._client is not None

    async def upload_report(
        self,
        target_address: str,
        risk_score: float,
        category_scores: Dict[str, float],
        full_analysis: Dict[str, Any],
        tx_hash: Optional[str] = None,
    ) -> Optional[str]:
        """
        Upload forensic report to Greenfield as a public JSON object.
        Returns public URL on success, None on failure.
        Retries once on transient failure.
        """
        if not self.is_enabled():
            return None

        from greenfield_python_sdk.models.object import CreateObjectOptions, PutObjectOptions
        from greenfield_python_sdk.protos.greenfield.storage import VisibilityType

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

                report_json = json.dumps(report_data, indent=2)
                report_bytes = report_json.encode("utf-8")
                reader = io.BytesIO(report_bytes)

                # Step 1: Create the object on-chain (gets SP approval, broadcasts tx)
                create_opts = CreateObjectOptions(
                    visibility=VisibilityType.VISIBILITY_TYPE_PUBLIC_READ,
                    content_type="application/json",
                )
                await self._client.object.create_object(
                    bucket_name=self.bucket_name,
                    object_name=object_name,
                    reader=reader,
                    opts=create_opts,
                )

                # Wait for chain confirmation
                await asyncio.sleep(3)

                # Step 2: Upload the actual data to the storage provider
                reader.seek(0)
                put_opts = PutObjectOptions()
                await self._client.object.put_object(
                    bucket_name=self.bucket_name,
                    object_name=object_name,
                    object_size=len(report_bytes),
                    reader=reader,
                    opts=put_opts,
                )

                public_url = f"{GREENFIELD_VIEW_BASE}/{self.bucket_name}/{object_name}"
                logger.info(f"Report uploaded to Greenfield: {public_url}")
                return public_url

            except Exception as e:
                logger.error(f"Greenfield upload attempt {attempt + 1} failed: {e}")

            if attempt == 0:
                await asyncio.sleep(2.0)

        return None
