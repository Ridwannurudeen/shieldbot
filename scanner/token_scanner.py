"""
Token Safety Scanner
Checks tokens for honeypots, trading restrictions, and safety issues
Integrates risk_scorer for numeric scoring and AI analysis
"""

import logging
from typing import Dict, List, Optional
from adapters.robinhood import SIMULATION_PROVIDER
from utils.chain_info import get_chain_name
from utils.web3_client import UnsupportedChainError
from utils.risk_scorer import (
    findings_from_scan_result, calculate_risk_score,
    blend_scores, compute_confidence
)

logger = logging.getLogger(__name__)

# Source code patterns ported from scanner/token.py for honeypot detection
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


class TokenScanner:
    """Scans tokens for safety and honeypot detection with numeric scoring"""

    def __init__(self, web3_client, ai_analyzer=None):
        self.web3 = web3_client
        self.ai_analyzer = ai_analyzer

    async def check_token(self, address: str, chain_id: int = 56) -> Dict:
        """
        Check token safety with numeric risk scoring.

        Returns:
            dict: Safety results with risk_score, confidence, safety_level, checks, risks
        """
        logger.info(f"Checking token: {address} (chain_id={chain_id})")

        if not self.web3.is_valid_address(address):
            raise ValueError("Invalid address format")

        address = self.web3.to_checksum_address(address)

        data_sources = {}

        result = {
            'address': address,
            'name': None,
            'symbol': None,
            'decimals': None,
            'total_supply': None,
            'is_honeypot': None,
            'safety_level': 'unknown',
            'risk_score': 0,
            'confidence': 0,
            'checks': {},
            'risks': [],
            'buy_tax': None,
            'sell_tax': None,
            'scan_type': 'token',
            'chain_id': chain_id,
            'network': get_chain_name(chain_id),
        }

        # Get token info
        await self._get_token_info(address, result, chain_id)

        # Get contract verification and age info (BscScan — BSC only)
        data_sources['bscscan'] = await self._get_contract_metadata(address, result, chain_id=chain_id)

        # Run safety checks
        await self._check_trading_functions(address, result, chain_id)
        await self._check_ownership(address, result, chain_id)
        data_sources['honeypot_api'] = await self._check_liquidity(address, result, chain_id)
        await self._check_honeypot(address, result, chain_id)
        data_sources['honeypot_api'] = await self._check_taxes(address, result, chain_id) or data_sources.get('honeypot_api', False)

        # Source code analysis if verified
        source_code = result.get('source_code')
        data_sources['source_code'] = False
        if source_code:
            self._analyze_source_code(source_code, result)
            data_sources['source_code'] = True

        # Resolve conflicts
        self._resolve_conflicts(result)

        result['coverage'] = {
            field: result.get(field) is not None
            for field in ('is_verified', 'contract_age_days', 'is_honeypot', 'buy_tax', 'sell_tax')
        }
        result['coverage'].update({
            field: result['checks'].get(field) is not None
            for field in ('can_buy', 'can_sell', 'ownership_renounced', 'liquidity_locked')
        })
        result['coverage_reasons'] = {
            field: f'{field} unknown: provider data unavailable'
            for field, covered in result['coverage'].items() if not covered
        }
        result['status'] = 'unknown' if result['coverage_reasons'] else 'ok'

        # Calculate safety level (legacy)
        result['safety_level'] = self._calculate_safety_level(result)

        # Compute numeric risk score
        findings = findings_from_scan_result(result)
        heuristic_score, _, _ = calculate_risk_score(findings)

        # Compute AI risk score if available
        ai_result = None
        if self.ai_analyzer and self.ai_analyzer.is_available():
            try:
                ai_result = await self.ai_analyzer.compute_ai_risk_score(address, result)
            except UnsupportedChainError:
                raise
            except Exception as e:
                logger.error("AI risk scoring failed: %s", type(e).__name__)

        # Only mark AI as successful if we got a valid dict with risk_score
        ai_score = None
        if isinstance(ai_result, dict) and 'risk_score' in ai_result:
            ai_score = ai_result['risk_score']
            data_sources['ai'] = True
        else:
            data_sources['ai'] = False

        # Blend scores (heuristic + AI when available)
        result['risk_score'] = blend_scores(heuristic_score, ai_score)

        # Set data source tracking
        data_sources['bytecode'] = True
        data_sources['scam_db'] = False
        data_sources['contract_age'] = result.get('contract_age_days') is not None
        result['confidence'] = compute_confidence(data_sources)

        # Generate unified forensic report (replaces separate AI calls)
        if self.ai_analyzer and self.ai_analyzer.is_available():
            try:
                report = await self.ai_analyzer.generate_forensic_report(
                    address, result, 'token'
                )
                if report:
                    result['forensic_report'] = report
            except UnsupportedChainError:
                raise
            except Exception as e:
                logger.error("Forensic report generation failed: %s", type(e).__name__)

        return result

    async def _get_token_info(self, address: str, result: Dict, chain_id: int = 56):
        """Get basic token information"""
        try:
            token_info = await self.web3.get_token_info(address, chain_id=chain_id)
            result['name'] = token_info.get('name')
            result['symbol'] = token_info.get('symbol')
            result['decimals'] = token_info.get('decimals')
            result['total_supply'] = token_info.get('total_supply')
        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Error getting token info: %s", type(e).__name__)

    async def _get_contract_metadata(self, address: str, result: Dict, chain_id: int = 56) -> bool:
        """Get contract verification and age info for cross-validation. Returns True if succeeded."""
        try:
            verification = await self.web3.is_verified_contract(address, chain_id=chain_id)

            if isinstance(verification, tuple):
                is_verified, source_code = verification
            else:
                is_verified = verification
                source_code = None

            result['is_verified'] = is_verified
            if source_code:
                result['source_code'] = source_code

            creation_info = await self.web3.get_contract_creation_info(address, chain_id=chain_id)
            result['contract_age_days'] = creation_info.get('age_days') if creation_info else None

            return is_verified is not None and result['contract_age_days'] is not None
        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Error getting contract metadata: %s", type(e).__name__)
            result['is_verified'] = None
            result['contract_age_days'] = None
            return False

    async def _check_trading_functions(self, address: str, result: Dict, chain_id: int = 56):
        """Check if token can be bought and sold"""
        try:
            can_transfer = await self.web3.can_transfer_token(address, chain_id=chain_id)
            result['checks']['can_buy'] = can_transfer
            result['checks']['can_sell'] = can_transfer

            if not can_transfer:
                result['risks'].append("Token transfers may be restricted or disabled")
        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Error checking trading functions: %s", type(e).__name__)
            result['checks']['can_buy'] = None
            result['checks']['can_sell'] = None

    def _resolve_conflicts(self, result: Dict):
        """Resolve conflicts between different checks"""
        if result.get('is_honeypot'):
            result['checks']['can_sell'] = False
            if "Token transfers may be restricted" not in str(result.get('risks', [])):
                result['risks'].append("Honeypot detected - You cannot sell this token after buying")

    async def _check_ownership(self, address: str, result: Dict, chain_id: int = 56):
        """Check contract ownership status"""
        try:
            ownership_info = await self.web3.get_ownership_info(address, chain_id=chain_id)
            is_renounced = ownership_info.get('is_renounced')
            owner = ownership_info.get('owner')

            result['checks']['ownership_renounced'] = is_renounced
            result['owner'] = owner

            if not is_renounced and owner:
                result['risks'].append(f"Contract has active owner: {owner[:10]}...")
        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Error checking ownership: %s", type(e).__name__)
            result['checks']['ownership_renounced'] = None

    async def _check_liquidity(self, address: str, result: Dict, chain_id: int = 56) -> bool:
        """Check liquidity lock status. Returns True if check succeeded."""
        try:
            liquidity_info = await self.web3.get_liquidity_info(address, chain_id=chain_id)

            is_locked = liquidity_info.get('is_locked', False)
            lock_percentage = liquidity_info.get('lock_percentage', 0)

            result['checks']['liquidity_locked'] = is_locked
            result['liquidity_lock_percentage'] = lock_percentage

            if not is_locked:
                result['risks'].append("Liquidity is not locked - risk of rug pull")
            elif lock_percentage < 80:
                result['risks'].append(f"Only {lock_percentage}% of liquidity is locked")

            return True
        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Error checking liquidity: %s", type(e).__name__)
            result['checks']['liquidity_locked'] = None
            return False

    async def _check_honeypot(self, address: str, result: Dict, chain_id: int = 56):
        """Check if token is a honeypot with cross-validation"""
        if chain_id != 56 and self.web3.supports_honeypot_simulation(chain_id) is not True:
            result['is_honeypot'] = None
            result['checks']['can_sell'] = None
            result['honeypot_status'] = 'unknown'
            result['honeypot_reason'] = 'Legacy honeypot check unavailable for this chain'
            result['risks'].append('Honeypot and sellability unknown: legacy check unavailable for this chain')
            return
        try:
            honeypot_result = await self.web3.check_honeypot(address, chain_id=chain_id)
            is_honeypot = honeypot_result.get('is_honeypot')
            result['honeypot_status'] = honeypot_result.get('status', 'ok' if is_honeypot is not None else 'unknown')
            result['honeypot_reason'] = honeypot_result.get('reason')
            if result['honeypot_status'] == 'unknown':
                result['checks']['can_sell'] = None
            if is_honeypot is None:
                result['is_honeypot'] = None
                result['checks']['can_sell'] = None
                reason = honeypot_result.get('reason') or 'provider data unavailable'
                result['risks'].append(f'Honeypot and sellability unknown: {reason}')
                return

            if is_honeypot:
                is_verified = result.get('is_verified', False)
                contract_age_days = result.get('contract_age_days', 0)
                providers = honeypot_result.get('field_providers') or {}
                # A third-party flag can be a false positive; our own simulation executed the sell.
                simulated = providers.get('is_honeypot') == SIMULATION_PROVIDER

                if not simulated and is_verified and contract_age_days is not None and contract_age_days > 30:
                    logger.info(f"Honeypot API flagged {address} but contract is verified and {contract_age_days} days old - likely false positive")
                    result['is_honeypot'] = False
                    result['risks'].append("High sell restrictions detected, but contract appears legitimate (verified + established)")
                else:
                    result['is_honeypot'] = True
                    result['risks'].append("HONEYPOT DETECTED - Cannot sell after buying")
                    honeypot_reason = honeypot_result.get('reason', 'Unknown')
                    result['risks'].append(f"Reason: {honeypot_reason}")
            else:
                result['is_honeypot'] = False

        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Error checking honeypot: %s", type(e).__name__)
            result['is_honeypot'] = None
            result['checks']['can_sell'] = None
            result['honeypot_status'] = 'unknown'
            result['honeypot_reason'] = 'Honeypot provider failed'
            result['risks'].append('Honeypot and sellability unknown: provider failed')

    async def _check_taxes(self, address: str, result: Dict, chain_id: int = 56) -> bool:
        """Check buy and sell taxes. Returns True if check succeeded."""
        if chain_id != 56 and self.web3.supports_honeypot_simulation(chain_id) is not True:
            result['buy_tax'] = None
            result['sell_tax'] = None
            result['tax_status'] = 'unknown'
            result['tax_reason'] = 'Legacy tax check unavailable for this chain'
            result['risks'].append('Buy/sell taxes unknown: legacy check unavailable for this chain')
            return False
        result['buy_tax'] = None
        result['sell_tax'] = None
        try:
            tax_info = await self.web3.get_tax_info(address, chain_id=chain_id)

            buy_tax = tax_info.get('buy_tax')
            sell_tax = tax_info.get('sell_tax')

            result['buy_tax'] = buy_tax
            result['sell_tax'] = sell_tax

            if buy_tax is not None and buy_tax > 10:
                result['risks'].append(f"High buy tax: {buy_tax}%")
            if sell_tax is not None and sell_tax > 10:
                result['risks'].append(f"High sell tax: {sell_tax}%")
            if sell_tax is not None and sell_tax > 50:
                result['risks'].append("Extremely high sell tax - possible honeypot")

            if buy_tax is None or sell_tax is None:
                result['tax_status'] = 'unknown'
                result['tax_reason'] = tax_info.get('reason') or 'Tax provider data incomplete'
                result['risks'].append(f"Buy/sell taxes unknown: {result['tax_reason']}")
                return False
            result['tax_status'] = 'ok'
            result['tax_reason'] = None
            return True
        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Error checking taxes: %s", type(e).__name__)
            result['tax_status'] = 'unknown'
            result['tax_reason'] = 'Tax provider failed'
            result['risks'].append('Buy/sell taxes unknown: provider failed')
            return False

    def _analyze_source_code(self, source_code: str, result: Dict):
        """Run local pattern matching on verified source code (ported from scanner/token.py)."""
        detected = []
        source_lower = source_code.lower()

        for item in SOURCE_CODE_PATTERNS:
            if item['pattern'].lower() in source_lower:
                detected.append(item)

        if detected:
            critical_or_high = [d for d in detected if d['severity'] in ('critical', 'high')]
            if critical_or_high:
                result['risks'].append(
                    f"Source code: {len(critical_or_high)} dangerous pattern(s): "
                    + ", ".join(d['pattern'] for d in critical_or_high[:4])
                )

            # Check for renounce
            if not any(d['pattern'] == 'renounceOwnership' for d in detected):
                if any(d['pattern'] == 'onlyOwner' for d in detected):
                    result['risks'].append("No ownership renounce function - owner has permanent control")

            result['source_code_patterns'] = detected

    def _calculate_safety_level(self, result: Dict) -> str:
        """Calculate overall safety level"""
        checks = result['checks']

        if result['is_honeypot']:
            return 'danger'
        if checks.get('can_sell') is False:
            return 'danger'
        if result.get('status') == 'unknown':
            return 'unknown'
        if result.get('is_honeypot') is None or checks.get('can_sell') is None:
            return 'unknown'
        sell_tax = result.get('sell_tax')
        buy_tax = result.get('buy_tax')
        if sell_tax is not None and sell_tax > 50:
            return 'danger'

        warning_count = 0
        if checks.get('ownership_renounced') is False:
            warning_count += 1
        if not checks.get('liquidity_locked'):
            warning_count += 1
        if (buy_tax is not None and buy_tax > 10) or (sell_tax is not None and sell_tax > 10):
            warning_count += 1

        if warning_count >= 2:
            return 'warning'

        if buy_tax is None or sell_tax is None:
            return 'unknown'

        if all([
            checks.get('can_buy'),
            checks.get('can_sell'),
            not result['is_honeypot'],
            result.get('sell_tax', 0) <= 10
        ]):
            return 'safe'

        return 'warning'
