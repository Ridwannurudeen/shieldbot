"""
On-Chain Scan Recorder
Records security scan results to the ShieldBotVerifier contract on BSC.
Fire-and-forget pattern: non-blocking, failures don't affect bot response.
"""

import os
import logging
import asyncio
from typing import Optional
from web3 import Web3

try:
    from web3.middleware import ExtraDataToPOAMiddleware
    POA_MIDDLEWARE = ExtraDataToPOAMiddleware
except ImportError:
    from web3.middleware import geth_poa_middleware
    POA_MIDDLEWARE = geth_poa_middleware

logger = logging.getLogger(__name__)

# ShieldBotVerifier contract on BSC Mainnet
CONTRACT_ADDRESS = '0x867aE7449af56BB56a4978c758d7E88066E1f795'

# Minimal ABI for recordScan and getLatestScan
VERIFIER_ABI = [
    {
        "inputs": [
            {"name": "_scannedAddress", "type": "address"},
            {"name": "_riskLevel", "type": "uint8"},
            {"name": "_scanType", "type": "string"}
        ],
        "name": "recordScan",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"name": "_address", "type": "address"}],
        "name": "getLatestScan",
        "outputs": [
            {"name": "scannedAddress", "type": "address"},
            {"name": "riskLevel", "type": "uint8"},
            {"name": "timestamp", "type": "uint256"},
            {"name": "scanType", "type": "string"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"name": "_address", "type": "address"}],
        "name": "hasBeenScanned",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"name": "", "type": "address"}],
        "name": "scanCount",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "totalScans",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]

# Risk level mapping: string -> uint8 (matches Solidity enum)
RISK_LEVEL_MAP = {
    'low': 0,
    'medium': 1,
    'high': 2,
    'safe': 3,
    'warning': 4,
    'danger': 5,
}


class OnchainRecorder:
    """Records scan results on-chain via ShieldBotVerifier contract."""

    def __init__(self):
        self.private_key = os.getenv('BOT_WALLET_PRIVATE_KEY')
        bsc_rpc = os.getenv('BSC_RPC_URL', 'https://bsc-dataseed1.binance.org/')

        self.web3 = Web3(Web3.HTTPProvider(bsc_rpc))
        # BSC is a POA chain, need this middleware
        self.web3.middleware_onion.inject(POA_MIDDLEWARE, layer=0)

        if not self.private_key:
            logger.warning("BOT_WALLET_PRIVATE_KEY not set - on-chain recording disabled")
            self.contract = None
            self.account = None
        else:
            self.account = self.web3.eth.account.from_key(self.private_key)
            self.contract = self.web3.eth.contract(
                address=Web3.to_checksum_address(CONTRACT_ADDRESS),
                abi=VERIFIER_ABI
            )
            logger.info(f"OnchainRecorder initialized: wallet={self.account.address}")

    def is_available(self) -> bool:
        """Check if on-chain recording is configured."""
        return self.contract is not None and self.account is not None

    async def record_scan(self, address: str, risk_level: str, scan_type: str) -> Optional[str]:
        """
        Record a scan result on-chain. Returns tx hash on success, None on failure.
        This is fire-and-forget — errors are logged but don't propagate.

        Args:
            address: The scanned contract/token address
            risk_level: Risk level string (low/medium/high/safe/warning/danger)
            scan_type: "contract" or "token"

        Returns:
            Transaction hash string if successful, None otherwise
        """
        if not self.is_available():
            logger.debug("On-chain recording not available (no private key)")
            return None

        try:
            checksum_address = Web3.to_checksum_address(address)
            risk_uint8 = RISK_LEVEL_MAP.get(risk_level.lower(), 1)  # default to MEDIUM

            # Build transaction
            nonce = self.web3.eth.get_transaction_count(self.account.address)
            gas_price = self.web3.eth.gas_price

            tx = self.contract.functions.recordScan(
                checksum_address,
                risk_uint8,
                scan_type
            ).build_transaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': 250000,
                'gasPrice': gas_price,
                'chainId': 56,
            })

            # Sign and send (web3 6.x uses rawTransaction, 7.x uses raw_transaction)
            signed_tx = self.web3.eth.account.sign_transaction(tx, self.private_key)
            raw = getattr(signed_tx, 'raw_transaction', None) or signed_tx.rawTransaction
            tx_hash = self.web3.eth.send_raw_transaction(raw)
            tx_hash_hex = tx_hash.hex()

            logger.info(f"On-chain scan recorded: {tx_hash_hex} for {address} ({risk_level})")
            return tx_hash_hex

        except Exception as e:
            logger.error(f"On-chain recording failed: {e}")
            return None

    async def record_scan_fire_and_forget(self, address: str, risk_level: str, scan_type: str) -> Optional[str]:
        """
        Non-blocking wrapper around record_scan.
        Schedules the recording as a background task.
        Returns immediately with None (tx hash not available until task completes).
        """
        if not self.is_available():
            return None

        try:
            # Run in background - don't await
            loop = asyncio.get_event_loop()
            result = await self.record_scan(address, risk_level, scan_type)
            return result
        except Exception as e:
            logger.error(f"Fire-and-forget recording failed: {e}")
            return None

    async def get_latest_scan(self, address: str) -> Optional[dict]:
        """
        Query the on-chain contract for the latest scan of an address.
        This is a view function (zero gas).

        Returns:
            dict with scannedAddress, riskLevel, timestamp, scanType, or None
        """
        if not self.contract:
            # Can still query without private key - just need the contract
            bsc_rpc = os.getenv('BSC_RPC_URL', 'https://bsc-dataseed1.binance.org/')
            web3 = Web3(Web3.HTTPProvider(bsc_rpc))
            contract = web3.eth.contract(
                address=Web3.to_checksum_address(CONTRACT_ADDRESS),
                abi=VERIFIER_ABI
            )
        else:
            contract = self.contract

        try:
            checksum_address = Web3.to_checksum_address(address)

            # Check if address has been scanned
            has_scan = contract.functions.hasBeenScanned(checksum_address).call()
            if not has_scan:
                return None

            result = contract.functions.getLatestScan(checksum_address).call()
            scanned_addr, risk_level, timestamp, scan_type = result

            risk_names = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'SAFE', 4: 'WARNING', 5: 'DANGER'}

            return {
                'address': scanned_addr,
                'risk_level': risk_names.get(risk_level, 'UNKNOWN'),
                'risk_level_raw': risk_level,
                'timestamp': timestamp,
                'scan_type': scan_type,
                'scan_count': contract.functions.scanCount(checksum_address).call()
            }

        except Exception as e:
            logger.error(f"Error querying on-chain scan: {e}")
            return None

    async def get_stats(self) -> Optional[dict]:
        """Get total scan statistics from the contract."""
        try:
            if not self.contract:
                bsc_rpc = os.getenv('BSC_RPC_URL', 'https://bsc-dataseed1.binance.org/')
                web3 = Web3(Web3.HTTPProvider(bsc_rpc))
                contract = web3.eth.contract(
                    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
                    abi=VERIFIER_ABI
                )
            else:
                contract = self.contract

            total = contract.functions.totalScans().call()
            return {'total_scans': total}
        except Exception as e:
            logger.error(f"Error getting on-chain stats: {e}")
            return None
