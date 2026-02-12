"""
Pre-Transaction Scanner
Analyzes contracts for security risks before interaction
"""

import logging
from typing import Dict, List, Optional
from utils.scam_db import ScamDatabase

logger = logging.getLogger(__name__)


class TransactionScanner:
    """Scans contracts for security risks"""
    
    def __init__(self, web3_client, ai_analyzer=None):
        self.web3 = web3_client
        self.scam_db = ScamDatabase()
        self.ai_analyzer = ai_analyzer
    
    async def scan_address(self, address: str) -> Dict:
        """
        Scan a contract address for security risks
        
        Returns:
            dict: Scan results with risk level, checks, and warnings
        """
        logger.info(f"Scanning address: {address}")
        
        # Validate address
        if not self.web3.is_valid_address(address):
            raise ValueError("Invalid address format")
        
        # Normalize address
        address = self.web3.to_checksum_address(address)
        
        # Initialize result
        result = {
            'address': address,
            'is_verified': False,
            'is_contract': False,
            'risk_level': 'unknown',
            'checks': {},
            'warnings': [],
            'scam_matches': []
        }
        
        # Check if it's a contract
        result['is_contract'] = await self.web3.is_contract(address)
        
        if not result['is_contract']:
            result['risk_level'] = 'low'
            result['warnings'].append("This is an EOA (externally owned account), not a contract")
            return result
        
        # Run all security checks
        await self._check_verification(address, result)
        await self._check_scam_database(address, result)
        await self._check_contract_age(address, result)
        await self._check_similar_scams(address, result)
        
        # Calculate overall risk level
        result['risk_level'] = self._calculate_risk_level(result)
        
        # Add AI-powered analysis if available
        if self.ai_analyzer and self.ai_analyzer.is_available():
            try:
                bytecode = await self.web3.get_bytecode(address)
                ai_analysis = await self.ai_analyzer.analyze_contract_bytecode(
                    address, bytecode, result
                )
                if ai_analysis:
                    result['ai_analysis'] = ai_analysis
                    logger.info("AI analysis added to scan result")
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
        
        return result
    
    async def _check_verification(self, address: str, result: Dict):
        """Check if contract is verified on BscScan"""
        try:
            is_verified = await self.web3.is_verified_contract(address)
            result['is_verified'] = is_verified
            result['checks']['verified_source'] = is_verified
            
            if not is_verified:
                result['warnings'].append("⚠️ Contract source code is not verified")
        except Exception as e:
            logger.error(f"Error checking verification: {e}")
            result['checks']['verified_source'] = False
    
    async def _check_scam_database(self, address: str, result: Dict):
        """Check against known scam databases"""
        try:
            matches = await self.scam_db.check_address(address)
            
            if matches:
                result['scam_matches'] = matches
                result['warnings'].append(f"🔴 Found {len(matches)} scam database match(es)")
                result['checks']['scam_database_clean'] = False
            else:
                result['checks']['scam_database_clean'] = True
        except Exception as e:
            logger.error(f"Error checking scam database: {e}")
            result['checks']['scam_database_clean'] = None
    
    async def _check_contract_age(self, address: str, result: Dict):
        """Check contract creation time"""
        try:
            creation_info = await self.web3.get_contract_creation_info(address)
            
            if creation_info:
                age_days = creation_info.get('age_days', 0)
                result['contract_age_days'] = age_days
                
                # Warn if contract is very new (< 7 days)
                if age_days < 7:
                    result['warnings'].append(f"⚠️ Contract is only {age_days} days old")
                    result['checks']['not_too_new'] = False
                else:
                    result['checks']['not_too_new'] = True
        except Exception as e:
            logger.error(f"Error checking contract age: {e}")
            result['checks']['not_too_new'] = None
    
    async def _check_similar_scams(self, address: str, result: Dict):
        """Check for similar scam patterns"""
        try:
            # Get contract bytecode
            bytecode = await self.web3.get_bytecode(address)
            
            if bytecode:
                # Check for common scam patterns in bytecode
                patterns = self._detect_suspicious_patterns(bytecode)
                
                if patterns:
                    result['warnings'].extend(patterns)
                    result['checks']['no_suspicious_patterns'] = False
                else:
                    result['checks']['no_suspicious_patterns'] = True
        except Exception as e:
            logger.error(f"Error checking similar scams: {e}")
            result['checks']['no_suspicious_patterns'] = None
    
    def _detect_suspicious_patterns(self, bytecode: str) -> List[str]:
        """Detect suspicious patterns in contract bytecode"""
        warnings = []
        
        # List of suspicious function signatures (keccak256 hashes)
        suspicious_sigs = {
            '0x7a9e5410': 'Potential backdoor function detected',
            '0x1694505e': 'Self-destruct function present',
            '0x83197ef0': 'Delegated call to arbitrary address possible'
        }
        
        for sig, warning in suspicious_sigs.items():
            if sig.replace('0x', '') in bytecode:
                warnings.append(f"⚠️ {warning}")
        
        return warnings
    
    def _calculate_risk_level(self, result: Dict) -> str:
        """Calculate overall risk level based on checks"""
        checks = result['checks']
        
        # High risk conditions
        if result['scam_matches']:
            return 'high'
        
        if checks.get('verified_source') is False and checks.get('not_too_new') is False:
            return 'high'
        
        # Medium risk conditions
        if checks.get('verified_source') is False or checks.get('no_suspicious_patterns') is False:
            return 'medium'
        
        # Low risk
        if all([
            checks.get('verified_source'),
            checks.get('scam_database_clean'),
            checks.get('no_suspicious_patterns')
        ]):
            return 'low'
        
        return 'medium'
