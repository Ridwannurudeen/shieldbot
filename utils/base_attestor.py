"""ShieldBot → Base attestor bridge.

Posts threat-scan attestations to the ShieldBotAttestor contract on Base mainnet,
which forwards them to the Ethereum Attestation Service (EAS) — the same primitive
Coinbase Verifications uses on Base.

Fire-and-forget: failures logged but never propagate to the bot response path.
"""

import os
import json
import asyncio
import logging
from typing import Optional, Dict
from web3 import Web3

logger = logging.getLogger(__name__)

# ABI: only what we call from Python.
ATTESTOR_ABI = [
    {
        "type": "function",
        "name": "attest",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "scannedAddress", "type": "address"},
            {"name": "riskLevel", "type": "uint8"},
            {"name": "scanType", "type": "string"},
            {"name": "sourceChainId", "type": "uint64"},
            {"name": "evidenceHash", "type": "bytes32"},
            {"name": "evidenceURI", "type": "string"},
        ],
        "outputs": [{"name": "uid", "type": "bytes32"}],
    },
    {
        "type": "function",
        "name": "totalAttestations",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "attestationCount",
        "stateMutability": "view",
        "inputs": [{"name": "", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
]

RISK_LEVEL_MAP = {
    "low": 0, "medium": 1, "high": 2, "safe": 3, "warning": 4, "danger": 5,
}


class BaseAttestor:
    """Posts ShieldBot threat attestations to EAS via the ShieldBotAttestor contract on Base."""

    def __init__(
        self,
        contract_address: Optional[str] = None,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
    ):
        self.contract_address = contract_address or os.getenv("BASE_ATTESTOR_ADDRESS", "")
        self.private_key = private_key or os.getenv("BASE_VERIFIER_PRIVATE_KEY", "")
        rpc = rpc_url or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")

        self.web3 = Web3(Web3.HTTPProvider(rpc))

        if not self.contract_address or not self.private_key:
            logger.warning("BaseAttestor disabled — set BASE_ATTESTOR_ADDRESS and BASE_VERIFIER_PRIVATE_KEY to enable")
            self.contract = None
            self.account = None
        else:
            self.account = self.web3.eth.account.from_key(self.private_key)
            self.contract = self.web3.eth.contract(
                address=Web3.to_checksum_address(self.contract_address),
                abi=ATTESTOR_ABI,
            )
            logger.info(f"BaseAttestor initialized: verifier={self.account.address} contract={self.contract_address}")

    def is_available(self) -> bool:
        return self.contract is not None and self.account is not None

    async def attest(
        self,
        scanned_address: str,
        risk_level: str,
        scan_type: str,
        source_chain_id: int = 56,
        evidence: Optional[Dict] = None,
        evidence_uri: str = "",
    ) -> Optional[str]:
        """Post a single attestation. Returns the EAS attestation UID on success.

        Args:
            scanned_address: target of the scan (the address being attested about)
            risk_level: low/medium/high/safe/warning/danger
            scan_type: e.g. "contract", "token", "approval", "deployer"
            source_chain_id: chain where the scanned address lives (56=BSC, 8453=Base, ...)
            evidence: optional dict serialized to JSON for the evidence hash
            evidence_uri: optional ipfs:// or https:// link to the off-chain detailed report
        """
        if not self.is_available():
            return None

        try:
            checksum = Web3.to_checksum_address(scanned_address)
            risk_uint8 = RISK_LEVEL_MAP.get(risk_level.lower(), 1)

            if evidence is not None:
                evidence_bytes = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
                evidence_hash = Web3.keccak(evidence_bytes)
            else:
                evidence_hash = b"\x00" * 32

            nonce = self.web3.eth.get_transaction_count(self.account.address)
            gas_price = self.web3.eth.gas_price

            tx = self.contract.functions.attest(
                checksum, risk_uint8, scan_type, source_chain_id, evidence_hash, evidence_uri
            ).build_transaction({
                "from": self.account.address,
                "nonce": nonce,
                "gas": 350_000,
                "gasPrice": gas_price,
                "chainId": 8453,
            })

            signed = self.web3.eth.account.sign_transaction(tx, self.private_key)
            raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
            tx_hash = self.web3.eth.send_raw_transaction(raw)
            tx_hash_hex = tx_hash.hex()
            logger.info(f"Base attestation posted: tx={tx_hash_hex} addr={scanned_address} risk={risk_level} chain={source_chain_id}")
            return tx_hash_hex
        except Exception as e:
            logger.error(f"Base attestation failed: {e}")
            return None

    async def attest_fire_and_forget(self, *args, **kwargs) -> None:
        """Schedule an attestation as a background task; return immediately."""
        if not self.is_available():
            return None
        asyncio.create_task(self._safe_attest(*args, **kwargs))
        return None

    async def _safe_attest(self, *args, **kwargs):
        try:
            await asyncio.wait_for(self.attest(*args, **kwargs), timeout=20.0)
        except asyncio.TimeoutError:
            logger.warning("Base attestation timed out")
        except Exception as e:
            logger.error(f"Background Base attestation failed: {e}")
