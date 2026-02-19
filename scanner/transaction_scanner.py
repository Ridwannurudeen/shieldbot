"""
Pre-Transaction Scanner
Analyzes contracts for security risks before interaction
Integrates risk_scorer for numeric scoring and AI analysis
"""

import logging
from typing import Dict, List, Optional
from utils.scam_db import ScamDatabase
from utils.chain_info import get_chain_name
from utils.risk_scorer import (
    findings_from_scan_result, calculate_risk_score,
    blend_scores, compute_confidence
)

logger = logging.getLogger(__name__)

# Expanded suspicious bytecode signatures (~18 patterns)
SUSPICIOUS_SIGNATURES = {
    # Critical - backdoor / destructive
    '7a9e5410': {'warning': 'Potential backdoor function detected', 'severity': 'critical'},
    '1694505e': {'warning': 'Self-destruct function present', 'severity': 'critical'},
    '83197ef0': {'warning': 'Delegated call to arbitrary address possible', 'severity': 'critical'},
    'a9059cbb': {'warning': 'Transfer function (standard)', 'severity': 'info'},
    # Critical - mint / supply manipulation
    '40c10f19': {'warning': 'Mint function detected - owner can inflate supply', 'severity': 'critical'},
    'a0712d68': {'warning': 'Mint function (alt signature)', 'severity': 'critical'},
    # High - ownership / control
    '8456cb59': {'warning': 'Pause function - owner can freeze trading', 'severity': 'critical'},
    '3f4ba83a': {'warning': 'Unpause function present', 'severity': 'info'},
    'f2fde38b': {'warning': 'Ownership transfer function', 'severity': 'info'},
    '715018a6': {'warning': 'Renounce ownership function', 'severity': 'info'},
    # High - blacklist / whitelist
    '44337ea1': {'warning': 'Blacklist function - owner can block addresses', 'severity': 'critical'},
    'fe575a87': {'warning': 'Remove from blacklist function', 'severity': 'info'},
    'e47d6060': {'warning': 'Add to whitelist function', 'severity': 'info'},
    # Medium - burn / proxy
    '42966c68': {'warning': 'Burn function detected', 'severity': 'info'},
    '79cc6790': {'warning': 'BurnFrom function', 'severity': 'info'},
    '3659cfe6': {'warning': 'Proxy upgrade function - contract can be changed', 'severity': 'critical'},
    '4f1ef286': {'warning': 'Proxy upgradeAndCall - contract logic can change', 'severity': 'critical'},
    '5c60da1b': {'warning': 'Implementation slot (proxy pattern)', 'severity': 'info'},
}

# Source code patterns for honeypot / dangerous contracts
SOURCE_CODE_PATTERNS = [
    {"pattern": "onlyOwner", "severity": "medium", "message": "Owner-only functions present"},
    {"pattern": "blacklist", "severity": "high", "message": "Blacklist mechanism detected"},
    {"pattern": "addBlacklist", "severity": "high", "message": "Can add addresses to blacklist"},
    {"pattern": "removeBlacklist", "severity": "info", "message": "Can remove from blacklist"},
    {"pattern": "_isBlacklisted", "severity": "high", "message": "Blacklist state variable found"},
    {"pattern": "excludeFrom", "severity": "medium", "message": "Address exclusion mechanism"},
    {"pattern": "includeIn", "severity": "info", "message": "Address inclusion mechanism"},
    {"pattern": "setMaxTx", "severity": "high", "message": "Owner can set max transaction amount"},
    {"pattern": "setMaxWallet", "severity": "high", "message": "Owner can set max wallet size"},
    {"pattern": "setFee", "severity": "high", "message": "Owner can change fees"},
    {"pattern": "setTax", "severity": "high", "message": "Owner can change tax rates"},
    {"pattern": "selfdestruct", "severity": "critical", "message": "Self-destruct in source code"},
    {"pattern": "delegatecall", "severity": "high", "message": "Delegatecall in source code"},
    {"pattern": "renounceOwnership", "severity": "info", "message": "Can renounce ownership (positive)"},
]


class TransactionScanner:
    """Scans contracts for security risks with numeric scoring"""

    def __init__(self, web3_client, ai_analyzer=None):
        self.web3 = web3_client
        self.scam_db = ScamDatabase()
        self.ai_analyzer = ai_analyzer

    async def scan_address(self, address: str, chain_id: int = 56) -> Dict:
        """
        Scan a contract address for security risks.

        Returns:
            dict: Scan results with risk_score, confidence, risk_level, checks, warnings
        """
        logger.info(f"Scanning address: {address} (chain_id={chain_id})")

        if not self.web3.is_valid_address(address):
            raise ValueError("Invalid address format")

        address = self.web3.to_checksum_address(address)

        # Track which data sources responded
        data_sources = {}

        result = {
            'address': address,
            'is_verified': False,
            'is_contract': False,
            'risk_level': 'unknown',
            'risk_score': 0,
            'confidence': 0,
            'checks': {},
            'warnings': [],
            'scam_matches': [],
            'scan_type': 'contract',
            'chain_id': chain_id,
            'network': get_chain_name(chain_id),
        }

        # Check if it's a contract
        result['is_contract'] = await self.web3.is_contract(address, chain_id=chain_id)

        if not result['is_contract']:
            result['risk_level'] = 'low'
            result['risk_score'] = 5
            result['confidence'] = 95
            result['warnings'].append("This is an EOA (externally owned account), not a contract")
            return result

        # Run all security checks (BscScan API only covers BSC; bytecode uses chain_id)
        data_sources['bscscan'] = await self._check_verification(address, result, chain_id=chain_id)
        data_sources['scam_db'] = await self._check_scam_database(address, result, chain_id=chain_id)
        data_sources['contract_age'] = await self._check_contract_age(address, result, chain_id=chain_id)
        data_sources['bytecode'] = await self._check_similar_scams(address, result, chain_id)

        # Source code analysis if verified
        source_code = result.get('source_code')
        data_sources['source_code'] = False
        if source_code:
            self._analyze_source_code(source_code, result)
            data_sources['source_code'] = True

        # Calculate heuristic risk level (legacy)
        result['risk_level'] = self._calculate_risk_level(result)

        # Compute numeric risk score via risk_scorer
        findings = findings_from_scan_result(result)
        heuristic_score, _, _ = calculate_risk_score(findings)

        # Compute AI risk score if available
        ai_result = None
        if self.ai_analyzer and self.ai_analyzer.is_available():
            try:
                ai_result = await self.ai_analyzer.compute_ai_risk_score(address, result)
            except Exception as e:
                logger.error(f"AI risk scoring failed: {e}")

        # Only mark AI as successful if we got a valid dict with risk_score
        ai_score = None
        if isinstance(ai_result, dict) and 'risk_score' in ai_result:
            ai_score = ai_result['risk_score']
            data_sources['ai'] = True
        else:
            data_sources['ai'] = False

        # Blend scores (heuristic + AI when available)
        result['risk_score'] = blend_scores(heuristic_score, ai_score)
        result['confidence'] = compute_confidence(data_sources)

        # Generate unified forensic report (replaces separate AI calls)
        if self.ai_analyzer and self.ai_analyzer.is_available():
            try:
                report = await self.ai_analyzer.generate_forensic_report(
                    address, result, 'contract'
                )
                if report:
                    result['forensic_report'] = report
            except Exception as e:
                logger.error(f"Forensic report generation failed: {e}")

        # Override risk_level from blended score for consistency
        if result['risk_score'] >= 71:
            result['risk_level'] = 'high'
        elif result['risk_score'] >= 31:
            result['risk_level'] = 'medium'
        else:
            result['risk_level'] = 'low'

        return result

    async def _check_verification(self, address: str, result: Dict, chain_id: int = 56) -> bool:
        """Check if contract is verified on BscScan. Returns True if check succeeded."""
        try:
            verification = await self.web3.is_verified_contract(address, chain_id=chain_id)

            if isinstance(verification, tuple):
                is_verified, source_code = verification
            else:
                is_verified = verification
                source_code = None

            result['is_verified'] = is_verified
            result['checks']['verified_source'] = is_verified

            if source_code:
                result['source_code'] = source_code

            if not is_verified:
                result['warnings'].append("Contract source code is not verified")

            return True
        except Exception as e:
            logger.error(f"Error checking verification: {e}")
            result['checks']['verified_source'] = False
            return False

    async def _check_scam_database(self, address: str, result: Dict, chain_id: int = 56) -> bool:
        """Check against known scam databases. Returns True if check succeeded."""
        try:
            matches = await self.scam_db.check_address(address, chain_id=chain_id)

            if matches:
                result['scam_matches'] = matches
                result['warnings'].append(f"Found {len(matches)} scam database match(es)")
                result['checks']['scam_database_clean'] = False
            else:
                result['checks']['scam_database_clean'] = True

            return True
        except Exception as e:
            logger.error(f"Error checking scam database: {e}")
            result['checks']['scam_database_clean'] = None
            return False

    async def _check_contract_age(self, address: str, result: Dict, chain_id: int = 56) -> bool:
        """Check contract creation time. Returns True if check succeeded."""
        try:
            creation_info = await self.web3.get_contract_creation_info(address, chain_id=chain_id)

            if creation_info:
                age_days = creation_info.get('age_days', 0)
                result['contract_age_days'] = age_days

                if age_days < 7:
                    result['warnings'].append(f"Contract is only {age_days} days old")
                    result['checks']['not_too_new'] = False
                else:
                    result['checks']['not_too_new'] = True
                return True

            return False
        except Exception as e:
            logger.error(f"Error checking contract age: {e}")
            result['checks']['not_too_new'] = None
            return False

    async def _check_similar_scams(self, address: str, result: Dict, chain_id: int = 56) -> bool:
        """Check for suspicious bytecode patterns. Returns True if check succeeded."""
        try:
            bytecode = await self.web3.get_bytecode(address, chain_id=chain_id)

            if bytecode:
                patterns = self._detect_suspicious_patterns(bytecode)

                if patterns:
                    result['warnings'].extend(patterns)
                    result['checks']['no_suspicious_patterns'] = False
                else:
                    result['checks']['no_suspicious_patterns'] = True
                return True

            return False
        except Exception as e:
            logger.error(f"Error checking similar scams: {e}")
            result['checks']['no_suspicious_patterns'] = None
            return False

    def _detect_suspicious_patterns(self, bytecode: str) -> List[str]:
        """Detect suspicious patterns in contract bytecode (expanded to ~18 signatures)"""
        warnings = []

        for sig, info in SUSPICIOUS_SIGNATURES.items():
            if info['severity'] in ('critical', 'high') and sig in bytecode:
                warnings.append(f"{info['warning']}")

        return warnings

    def _analyze_source_code(self, source_code: str, result: Dict):
        """Run local pattern matching on verified source code."""
        detected = []
        source_lower = source_code.lower()

        for item in SOURCE_CODE_PATTERNS:
            if item['pattern'].lower() in source_lower:
                detected.append(item)

        if detected:
            critical_or_high = [d for d in detected if d['severity'] in ('critical', 'high')]
            if critical_or_high:
                result['warnings'].append(
                    f"Source code: {len(critical_or_high)} dangerous pattern(s) found: "
                    + ", ".join(d['pattern'] for d in critical_or_high[:4])
                )
            result['source_code_patterns'] = detected

    def _calculate_risk_level(self, result: Dict) -> str:
        """Calculate overall risk level based on checks (legacy heuristic)"""
        checks = result['checks']

        if result['scam_matches']:
            return 'high'

        if checks.get('verified_source') is False and checks.get('not_too_new') is False:
            return 'high'

        if checks.get('verified_source') is False or checks.get('no_suspicious_patterns') is False:
            return 'medium'

        if all([
            checks.get('verified_source'),
            checks.get('scam_database_clean'),
            checks.get('no_suspicious_patterns')
        ]):
            return 'low'

        return 'medium'
