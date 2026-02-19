"""Rescue Mode — Tier 1 (alerts with explanations) and Tier 2 (pre-built revoke transactions).

Scans a wallet's active token approvals, identifies risky ones, and generates
ready-to-sign revocation transactions for one-click cleanup.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import aiohttp
from web3 import Web3

logger = logging.getLogger(__name__)

# ERC-20 Approval event topic
APPROVAL_TOPIC = Web3.keccak(text="Approval(address,address,uint256)").hex()

# ApprovalForAll event topic (ERC-721/1155)
APPROVAL_FOR_ALL_TOPIC = Web3.keccak(text="ApprovalForAll(address,address,bool)").hex()

UNLIMITED_THRESHOLD = 2**128

# Known safe spenders (major DEX routers) — approvals to these are lower risk
KNOWN_SAFE_SPENDERS = {
    "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap V2",
    "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": "PancakeSwap V3",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
    "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": "SushiSwap",
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch V6",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
}


@dataclass
class ApprovalInfo:
    """Information about a single token approval."""
    token_address: str
    token_name: str
    token_symbol: str
    spender: str
    spender_label: str
    allowance: str  # Human-readable ("unlimited" or amount)
    allowance_raw: int
    risk_level: str  # HIGH, MEDIUM, LOW
    risk_reason: str
    chain_id: int
    revoke_tx: Optional[Dict[str, Any]] = None


@dataclass
class RescueAlert:
    """Tier 1 alert with explanation and recommended actions."""
    alert_type: str
    severity: str
    title: str
    description: str
    what_it_means: str
    what_you_can_do: List[str]
    affected_token: Optional[str] = None
    affected_spender: Optional[str] = None
    chain_id: int = 56


class RescueService:
    """Rescue Mode service — scans approvals and generates revoke transactions."""

    def __init__(self, web3_client, db=None):
        self._web3_client = web3_client
        self._db = db
        self._etherscan_url = "https://api.etherscan.io/v2/api"

    async def scan_approvals(
        self, wallet_address: str, chain_id: int = 56, etherscan_api_key: str = ""
    ) -> Dict[str, Any]:
        """Scan a wallet's active token approvals and assess risk.

        Returns a dict with:
        - approvals: list of ApprovalInfo
        - alerts: list of RescueAlert (Tier 1)
        - revoke_txs: list of pre-built revoke transactions (Tier 2)
        - summary: risk summary
        """
        wallet = wallet_address.lower()
        approvals = await self._fetch_approvals(wallet, chain_id, etherscan_api_key)

        alerts = []
        revoke_txs = []
        high_risk_count = 0
        medium_risk_count = 0

        for approval in approvals:
            # Generate Tier 1 alert
            alert = self._generate_alert(approval)
            if alert:
                alerts.append(alert)

            # Generate Tier 2 revoke transaction
            if approval.risk_level in ("HIGH", "MEDIUM"):
                revoke_tx = self._build_revoke_tx(
                    wallet, approval.token_address, approval.spender, chain_id
                )
                approval.revoke_tx = revoke_tx
                revoke_txs.append({
                    'token': approval.token_address,
                    'token_symbol': approval.token_symbol,
                    'spender': approval.spender,
                    'spender_label': approval.spender_label,
                    'risk_level': approval.risk_level,
                    'transaction': revoke_tx,
                })

            if approval.risk_level == "HIGH":
                high_risk_count += 1
            elif approval.risk_level == "MEDIUM":
                medium_risk_count += 1

        return {
            'wallet': wallet,
            'chain_id': chain_id,
            'total_approvals': len(approvals),
            'high_risk': high_risk_count,
            'medium_risk': medium_risk_count,
            'approvals': [self._approval_to_dict(a) for a in approvals],
            'alerts': [self._alert_to_dict(a) for a in alerts],
            'revoke_txs': revoke_txs,
            'scanned_at': time.time(),
        }

    async def _fetch_approvals(
        self, wallet: str, chain_id: int, api_key: str
    ) -> List[ApprovalInfo]:
        """Fetch token approval events from Etherscan v2 API."""
        approvals = []
        try:
            async with aiohttp.ClientSession() as session:
                # Fetch ERC-20 approval events where wallet is the owner
                params = {
                    'chainid': chain_id,
                    'module': 'logs',
                    'action': 'getLogs',
                    'fromBlock': 0,
                    'toBlock': 'latest',
                    'topic0': APPROVAL_TOPIC,
                    'topic1': '0x' + wallet.replace('0x', '').zfill(64),
                    'apikey': api_key,
                    'page': 1,
                    'offset': 200,
                }
                async with session.get(
                    self._etherscan_url, params=params,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return approvals
                    data = await resp.json()

                if data.get('status') != '1' or not data.get('result'):
                    return approvals

                # Process approval logs — keep latest per (token, spender)
                latest_approvals: Dict[tuple, Dict] = {}
                for log in data['result']:
                    try:
                        token = log['address'].lower()
                        topics = log.get('topics', [])
                        if len(topics) < 3:
                            continue
                        spender = '0x' + topics[2][-40:]
                        amount_hex = log.get('data', '0x0')
                        amount = int(amount_hex, 16) if amount_hex and amount_hex != '0x' else 0
                        block = int(log.get('blockNumber', '0x0'), 16)

                        key = (token, spender.lower())
                        existing = latest_approvals.get(key)
                        if not existing or block > existing['block']:
                            latest_approvals[key] = {
                                'token': token,
                                'spender': spender.lower(),
                                'amount': amount,
                                'block': block,
                            }
                    except (ValueError, IndexError, KeyError):
                        continue

                # Filter out zero approvals (already revoked)
                active = {k: v for k, v in latest_approvals.items() if v['amount'] > 0}

                # Enrich with token info and risk assessment
                for (token, spender), info in active.items():
                    token_info = await self._web3_client.get_token_info(token, chain_id)
                    name = token_info.get('name', 'Unknown')
                    symbol = token_info.get('symbol', '???')

                    spender_label = KNOWN_SAFE_SPENDERS.get(spender, 'Unknown Contract')
                    risk_level, risk_reason = self._assess_approval_risk(
                        spender, info['amount'], spender_label
                    )

                    if info['amount'] >= UNLIMITED_THRESHOLD:
                        allowance_str = "Unlimited"
                    else:
                        decimals = token_info.get('decimals', 18)
                        allowance_str = f"{info['amount'] / (10 ** decimals):,.2f}"

                    approvals.append(ApprovalInfo(
                        token_address=token,
                        token_name=name,
                        token_symbol=symbol,
                        spender=spender,
                        spender_label=spender_label,
                        allowance=allowance_str,
                        allowance_raw=info['amount'],
                        risk_level=risk_level,
                        risk_reason=risk_reason,
                        chain_id=chain_id,
                    ))

        except Exception as e:
            logger.error(f"Error fetching approvals: {e}")

        # Sort by risk level (HIGH first)
        risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        approvals.sort(key=lambda a: risk_order.get(a.risk_level, 3))
        return approvals

    def _assess_approval_risk(
        self, spender: str, amount: int, spender_label: str
    ) -> tuple:
        """Assess risk level for a token approval."""
        is_known_safe = spender.lower() in KNOWN_SAFE_SPENDERS

        if amount >= UNLIMITED_THRESHOLD:
            if is_known_safe:
                return "MEDIUM", f"Unlimited approval to {spender_label} — safe but excessive"
            return "HIGH", "Unlimited approval to unknown contract"

        if amount >= HIGH_APPROVAL:
            if is_known_safe:
                return "LOW", f"Large approval to {spender_label}"
            return "MEDIUM", "Large approval to unknown contract"

        if is_known_safe:
            return "LOW", f"Normal approval to {spender_label}"
        return "LOW", "Normal approval amount"

    def _generate_alert(self, approval: ApprovalInfo) -> Optional[RescueAlert]:
        """Generate a Tier 1 alert for a risky approval."""
        if approval.risk_level == "LOW":
            return None

        if approval.risk_level == "HIGH":
            return RescueAlert(
                alert_type="dangerous_approval",
                severity="HIGH",
                title=f"Dangerous Approval: {approval.token_symbol}",
                description=(
                    f"Your wallet has an unlimited approval for {approval.token_symbol} "
                    f"({approval.token_name}) granted to an unknown contract "
                    f"({approval.spender[:10]}...)."
                ),
                what_it_means=(
                    "This contract can spend ALL of your "
                    f"{approval.token_symbol} tokens at any time without "
                    "further permission. If the contract is malicious or gets "
                    "compromised, your tokens could be drained instantly."
                ),
                what_you_can_do=[
                    f"Revoke this approval immediately using the revoke button below",
                    f"Check the contract {approval.spender} on the block explorer",
                    "If you don't recognize this approval, it may be from a phishing site",
                ],
                affected_token=approval.token_address,
                affected_spender=approval.spender,
                chain_id=approval.chain_id,
            )

        return RescueAlert(
            alert_type="excessive_approval",
            severity="MEDIUM",
            title=f"Excessive Approval: {approval.token_symbol}",
            description=(
                f"Your wallet has a large approval for {approval.token_symbol} "
                f"granted to {approval.spender_label} ({approval.spender[:10]}...)."
            ),
            what_it_means=(
                f"While {approval.spender_label} is a known protocol, unlimited "
                "approvals carry risk if the protocol gets exploited. Consider "
                "revoking and re-approving with exact amounts when needed."
            ),
            what_you_can_do=[
                "Revoke this approval and re-approve with exact amounts when trading",
                "Monitor the protocol for any security incidents",
            ],
            affected_token=approval.token_address,
            affected_spender=approval.spender,
            chain_id=approval.chain_id,
        )

    def _build_revoke_tx(
        self, wallet: str, token: str, spender: str, chain_id: int
    ) -> Dict[str, Any]:
        """Build a pre-signed revoke transaction (approve to 0)."""
        # ERC-20 approve(spender, 0) calldata
        approve_selector = "0x095ea7b3"
        spender_padded = spender.replace("0x", "").lower().zfill(64)
        amount_padded = "0" * 64

        return {
            'from': Web3.to_checksum_address(wallet),
            'to': Web3.to_checksum_address(token),
            'data': f"{approve_selector}{spender_padded}{amount_padded}",
            'value': '0x0',
            'chainId': hex(chain_id),
        }

    @staticmethod
    def _approval_to_dict(a: ApprovalInfo) -> Dict:
        return {
            'token_address': a.token_address,
            'token_name': a.token_name,
            'token_symbol': a.token_symbol,
            'spender': a.spender,
            'spender_label': a.spender_label,
            'allowance': a.allowance,
            'risk_level': a.risk_level,
            'risk_reason': a.risk_reason,
            'chain_id': a.chain_id,
            'has_revoke_tx': a.revoke_tx is not None,
        }

    @staticmethod
    def _alert_to_dict(a: RescueAlert) -> Dict:
        return {
            'alert_type': a.alert_type,
            'severity': a.severity,
            'title': a.title,
            'description': a.description,
            'what_it_means': a.what_it_means,
            'what_you_can_do': a.what_you_can_do,
            'affected_token': a.affected_token,
            'affected_spender': a.affected_spender,
            'chain_id': a.chain_id,
        }
