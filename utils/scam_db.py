"""
Scam Database Checker
Checks addresses against known scam databases and blocklists
"""

import logging
import aiohttp
from typing import List, Dict

logger = logging.getLogger(__name__)


class ScamDatabase:
    """Check addresses against scam databases"""
    
    def __init__(self):
        # Public scam databases
        self.chainabuse_api = "https://www.chainabuse.com/api/address/"
        self.scamsniffer_api = "https://api.scamsniffer.io/v1/address/"
        
        # Local blacklist (can be expanded)
        self.known_scams = set([
            # Add known scam addresses here
        ])
    
    async def check_address(self, address: str) -> List[Dict]:
        """
        Check address against multiple scam databases
        
        Returns:
            list: List of matches with type and reason
        """
        matches = []
        
        # Check local blacklist
        if address.lower() in self.known_scams:
            matches.append({
                'type': 'Local Blacklist',
                'reason': 'Known scam address',
                'source': 'ShieldBot'
            })
        
        # Check ChainAbuse
        chainabuse_results = await self._check_chainabuse(address)
        if chainabuse_results:
            matches.extend(chainabuse_results)
        
        # Check ScamSniffer
        scamsniffer_results = await self._check_scamsniffer(address)
        if scamsniffer_results:
            matches.extend(scamsniffer_results)
        
        return matches
    
    async def _check_chainabuse(self, address: str) -> List[Dict]:
        """Check ChainAbuse database"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.chainabuse_api}{address}"
                
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        if data and len(data) > 0:
                            return [{
                                'type': 'ChainAbuse',
                                'reason': data[0].get('description', 'Reported scam'),
                                'source': 'chainabuse.com'
                            }]
            
            return []
        except Exception as e:
            logger.error(f"Error checking ChainAbuse: {e}")
            return []
    
    async def _check_scamsniffer(self, address: str) -> List[Dict]:
        """Check ScamSniffer database"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.scamsniffer_api}{address}"
                
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        if data.get('is_scam'):
                            return [{
                                'type': 'ScamSniffer',
                                'reason': data.get('reason', 'Flagged as scam'),
                                'source': 'scamsniffer.io'
                            }]
            
            return []
        except Exception as e:
            logger.error(f"Error checking ScamSniffer: {e}")
            return []
    
    def add_to_blacklist(self, address: str):
        """Add address to local blacklist"""
        self.known_scams.add(address.lower())
        logger.info(f"Added {address} to blacklist")
    
    def remove_from_blacklist(self, address: str):
        """Remove address from local blacklist"""
        self.known_scams.discard(address.lower())
        logger.info(f"Removed {address} from blacklist")
