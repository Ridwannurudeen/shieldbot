"""
Token Safety Scanner
Checks tokens for honeypots, trading restrictions, and safety issues
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class TokenScanner:
    """Scans tokens for safety and honeypot detection"""
    
    def __init__(self, web3_client, ai_analyzer=None):
        self.web3 = web3_client
        self.ai_analyzer = ai_analyzer
    
    async def check_token(self, address: str) -> Dict:
        """
        Check token safety
        
        Returns:
            dict: Safety results with honeypot detection, checks, and risks
        """
        logger.info(f"Checking token: {address}")
        
        # Validate address
        if not self.web3.is_valid_address(address):
            raise ValueError("Invalid address format")
        
        # Normalize address
        address = self.web3.to_checksum_address(address)
        
        # Initialize result
        result = {
            'address': address,
            'name': None,
            'symbol': None,
            'decimals': None,
            'total_supply': None,
            'is_honeypot': False,
            'safety_level': 'unknown',
            'checks': {},
            'risks': [],
            'buy_tax': None,
            'sell_tax': None
        }
        
        # Get token info
        await self._get_token_info(address, result)
        
        # Run safety checks
        await self._check_trading_functions(address, result)
        await self._check_ownership(address, result)
        await self._check_liquidity(address, result)
        await self._check_honeypot(address, result)
        await self._check_taxes(address, result)
        
        # Calculate overall safety level
        result['safety_level'] = self._calculate_safety_level(result)
        
        # Add AI-powered analysis if available
        if self.ai_analyzer and self.ai_analyzer.is_available():
            try:
                token_info = {
                    'name': result.get('name'),
                    'symbol': result.get('symbol'),
                    'decimals': result.get('decimals')
                }
                ai_analysis = await self.ai_analyzer.analyze_token_safety(
                    address, token_info, result
                )
                if ai_analysis:
                    result['ai_analysis'] = ai_analysis
                    logger.info("AI token analysis added to result")
            except Exception as e:
                logger.error(f"AI token analysis failed: {e}")
        
        return result
    
    async def _get_token_info(self, address: str, result: Dict):
        """Get basic token information"""
        try:
            token_info = await self.web3.get_token_info(address)
            
            result['name'] = token_info.get('name')
            result['symbol'] = token_info.get('symbol')
            result['decimals'] = token_info.get('decimals')
            result['total_supply'] = token_info.get('total_supply')
        except Exception as e:
            logger.error(f"Error getting token info: {e}")
    
    async def _check_trading_functions(self, address: str, result: Dict):
        """Check if token can be bought and sold"""
        try:
            # Check if transfer function exists and works
            can_transfer = await self.web3.can_transfer_token(address)
            result['checks']['can_buy'] = can_transfer
            result['checks']['can_sell'] = can_transfer
            
            if not can_transfer:
                result['risks'].append("🔴 Token transfers may be restricted or disabled")
        except Exception as e:
            logger.error(f"Error checking trading functions: {e}")
            result['checks']['can_buy'] = None
            result['checks']['can_sell'] = None
    
    async def _check_ownership(self, address: str, result: Dict):
        """Check contract ownership status"""
        try:
            ownership_info = await self.web3.get_ownership_info(address)
            
            is_renounced = ownership_info.get('is_renounced', False)
            owner = ownership_info.get('owner')
            
            result['checks']['ownership_renounced'] = is_renounced
            result['owner'] = owner
            
            if not is_renounced and owner:
                result['risks'].append(f"⚠️ Contract has active owner: {owner[:10]}...")
            
        except Exception as e:
            logger.error(f"Error checking ownership: {e}")
            result['checks']['ownership_renounced'] = None
    
    async def _check_liquidity(self, address: str, result: Dict):
        """Check liquidity lock status"""
        try:
            liquidity_info = await self.web3.get_liquidity_info(address)
            
            is_locked = liquidity_info.get('is_locked', False)
            lock_percentage = liquidity_info.get('lock_percentage', 0)
            
            result['checks']['liquidity_locked'] = is_locked
            result['liquidity_lock_percentage'] = lock_percentage
            
            if not is_locked:
                result['risks'].append("⚠️ Liquidity is not locked - risk of rug pull")
            elif lock_percentage < 80:
                result['risks'].append(f"⚠️ Only {lock_percentage}% of liquidity is locked")
        
        except Exception as e:
            logger.error(f"Error checking liquidity: {e}")
            result['checks']['liquidity_locked'] = None
    
    async def _check_honeypot(self, address: str, result: Dict):
        """Check if token is a honeypot"""
        try:
            # Use external honeypot API or simulation
            honeypot_result = await self.web3.check_honeypot(address)
            
            is_honeypot = honeypot_result.get('is_honeypot', False)
            result['is_honeypot'] = is_honeypot
            
            if is_honeypot:
                result['risks'].append("🔴 HONEYPOT DETECTED - Cannot sell after buying")
                honeypot_reason = honeypot_result.get('reason', 'Unknown')
                result['risks'].append(f"Reason: {honeypot_reason}")
        
        except Exception as e:
            logger.error(f"Error checking honeypot: {e}")
    
    async def _check_taxes(self, address: str, result: Dict):
        """Check buy and sell taxes"""
        try:
            tax_info = await self.web3.get_tax_info(address)
            
            buy_tax = tax_info.get('buy_tax', 0)
            sell_tax = tax_info.get('sell_tax', 0)
            
            result['buy_tax'] = buy_tax
            result['sell_tax'] = sell_tax
            
            # Warn about high taxes
            if buy_tax > 10:
                result['risks'].append(f"⚠️ High buy tax: {buy_tax}%")
            
            if sell_tax > 10:
                result['risks'].append(f"⚠️ High sell tax: {sell_tax}%")
            
            if sell_tax > 50:
                result['risks'].append("🔴 Extremely high sell tax - possible honeypot")
        
        except Exception as e:
            logger.error(f"Error checking taxes: {e}")
    
    def _calculate_safety_level(self, result: Dict) -> str:
        """Calculate overall safety level"""
        checks = result['checks']
        
        # Danger conditions
        if result['is_honeypot']:
            return 'danger'
        
        if not checks.get('can_sell'):
            return 'danger'
        
        if result.get('sell_tax', 0) > 50:
            return 'danger'
        
        # Warning conditions
        warning_count = 0
        
        if not checks.get('ownership_renounced'):
            warning_count += 1
        
        if not checks.get('liquidity_locked'):
            warning_count += 1
        
        if result.get('buy_tax', 0) > 10 or result.get('sell_tax', 0) > 10:
            warning_count += 1
        
        if warning_count >= 2:
            return 'warning'
        
        # Safe conditions
        if all([
            checks.get('can_buy'),
            checks.get('can_sell'),
            not result['is_honeypot'],
            result.get('sell_tax', 0) <= 10
        ]):
            return 'safe'
        
        return 'warning'
