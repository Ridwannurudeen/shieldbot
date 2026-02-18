"""
Scam Database Checker
Checks addresses against known scam databases and blocklists
"""

import re
import logging
import aiohttp
from typing import List, Dict

logger = logging.getLogger(__name__)

_ETH_ADDR_RE = re.compile(r'^0x[0-9a-fA-F]{40}$')


class ScamDatabase:
    """Check addresses against scam databases"""

    def __init__(self):
        # Public scam databases
        self.chainabuse_api = "https://www.chainabuse.com/api/address/"
        self.goplus_api = "https://api.gopluslabs.io/api/v1/token_security/"

        # Local blacklist (can be expanded)
        self.known_scams = set([
            # Add known scam addresses here
        ])

    async def check_address(self, address: str, chain_id: int = 56) -> List[Dict]:
        """
        Check address against multiple scam databases

        Returns:
            list: List of matches with type and reason
        """
        if not _ETH_ADDR_RE.match(address):
            logger.warning(f"Invalid address format passed to check_address: {address[:20]}")
            return []

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

        # Check GoPlus Security
        goplus_results = await self._check_goplus(address, chain_id)
        if goplus_results:
            matches.extend(goplus_results)

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
    
    async def _check_goplus(self, address: str, chain_id: int = 56) -> List[Dict]:
        """Check GoPlus Security API for token risk indicators."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.goplus_api}{chain_id}?contract_addresses={address.lower()}"

                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = data.get('result', {}).get(address.lower(), {})
                        if not result:
                            return []

                        flags = []
                        if result.get('is_blacklisted') == '1':
                            flags.append('Blacklisted token')
                        if result.get('is_honeypot') == '1':
                            flags.append('Honeypot (GoPlus)')
                        if result.get('is_open_source') == '0':
                            flags.append('Not open source')
                        if result.get('cannot_sell_all') == '1':
                            flags.append('Cannot sell all tokens')
                        if result.get('owner_change_balance') == '1':
                            flags.append('Owner can change balance')

                        if flags:
                            return [{
                                'type': 'GoPlus Security',
                                'reason': '; '.join(flags),
                                'source': 'gopluslabs.io',
                            }]

            return []
        except Exception as e:
            logger.error(f"Error checking GoPlus: {e}")
            return []
    
    def add_to_blacklist(self, address: str):
        """Add address to local blacklist"""
        self.known_scams.add(address.lower())
        logger.info(f"Added {address} to blacklist")
    
    def remove_from_blacklist(self, address: str):
        """Remove address from local blacklist"""
        self.known_scams.discard(address.lower())
        logger.info(f"Removed {address} from blacklist")
