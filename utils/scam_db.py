"""
Scam Database Checker
Checks addresses against known scam databases and blocklists
"""

import asyncio
import re
import time
import logging
import aiohttp
from typing import List, Dict
from cachetools import TTLCache

logger = logging.getLogger(__name__)

_ETH_ADDR_RE = re.compile(r'^0x[0-9a-fA-F]{40}$')

_GOPLUS_CACHE = TTLCache(maxsize=1024, ttl=30)
_GOPLUS_INFLIGHT = {}

# Addresses that must never be blacklisted (routers, WBNB, stables, etc.)
_PROTECTED_ADDRESSES: set[str] = set()

# Minimum independent reporters before an address is actually blacklisted
_REPORT_THRESHOLD = 3

# Max reports a single user can submit per day
_USER_REPORT_LIMIT = 5
_USER_REPORT_WINDOW = 86400  # 24 hours


def load_protected_addresses():
    """Import whitelisted routers / known-good addresses at startup."""
    try:
        from adapters.bsc import WHITELISTED_ROUTERS, WBNB_ADDRESS, BUSD_ADDRESS, USDT_ADDRESS
        for addr in WHITELISTED_ROUTERS:
            _PROTECTED_ADDRESSES.add(addr.lower())
        for addr in (WBNB_ADDRESS, BUSD_ADDRESS, USDT_ADDRESS):
            _PROTECTED_ADDRESSES.add(addr.lower())
    except ImportError:
        pass


# Run once on module load
load_protected_addresses()


class ScamDatabase:
    """Check addresses against scam databases"""

    def __init__(self):
        # Public scam databases
        self.chainabuse_api = "https://www.chainabuse.com/api/address/"

        # Shared session (created lazily, reused across requests)
        self._session: aiohttp.ClientSession = None

        # Local blacklist (can be expanded)
        self.known_scams = set([
            # Add known scam addresses here
        ])

        # Pending reports: address -> set of (reporter_id, timestamp)
        self._pending_reports: dict[str, set[tuple[str, float]]] = {}

        # Per-user rate limiting: reporter_id -> list of timestamps
        self._user_report_times: dict[str, list[float]] = {}

    async def _get_session(self) -> aiohttp.ClientSession:
        """Return a shared aiohttp session, creating it if needed."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self):
        """Close the shared session."""
        if self._session and not self._session.closed:
            await self._session.close()

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
            session = await self._get_session()
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

    @staticmethod
    async def fetch_token_security(address: str, chain_id: int = 56) -> dict:
        """Share GoPlus token data across concurrent scan components."""
        if not _ETH_ADDR_RE.fullmatch(address):
            return {'status': 'unknown', 'reason': 'Invalid token address', 'data': {}}
        key = (chain_id, address.lower())
        if key in _GOPLUS_CACHE:
            return _GOPLUS_CACHE[key]
        flight_key = (asyncio.get_running_loop(), key)
        if flight_key not in _GOPLUS_INFLIGHT:
            _GOPLUS_INFLIGHT[flight_key] = asyncio.create_task(
                ScamDatabase._fetch_token_security(key, flight_key)
            )
        return await asyncio.shield(_GOPLUS_INFLIGHT[flight_key])

    @staticmethod
    async def _fetch_token_security(key: tuple, flight_key: tuple) -> dict:
        chain_id, address = key
        result = {'status': 'unknown', 'reason': 'GoPlus unavailable', 'data': {}}
        try:
            url = f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={address}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status != 200:
                        result['reason'] = f'GoPlus HTTP {resp.status}'
                    else:
                        payload = await resp.json()
                        tokens = payload.get('result') if isinstance(payload, dict) else None
                        token = tokens.get(address) if isinstance(tokens, dict) else None
                        if not isinstance(payload, dict) or payload.get('code') != 1:
                            result['reason'] = 'GoPlus returned an unsuccessful response'
                        elif not isinstance(token, dict) or not token:
                            result['reason'] = 'GoPlus has no data for this token on this chain'
                        else:
                            result = {'status': 'ok', 'reason': None, 'data': token}
        except Exception as e:
            logger.error("Error fetching GoPlus token security: %s", e)
            result['reason'] = f'GoPlus request failed ({type(e).__name__})'
        finally:
            _GOPLUS_INFLIGHT.pop(flight_key, None)
        _GOPLUS_CACHE[key] = result
        return result

    async def _check_goplus(self, address: str, chain_id: int = 56) -> List[Dict]:
        """Check GoPlus Security API for token risk indicators."""
        response = await self.fetch_token_security(address, chain_id)
        result = response['data']
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
    
    def report_address(self, address: str, reporter_id: str) -> dict:
        """Community report with rate-limiting, whitelist protection, and multi-report threshold.

        Returns:
            {"accepted": bool, "reason": str, "blacklisted": bool, "reports": int, "needed": int}
        """
        addr = address.lower()
        now = time.time()

        # 1. Protect whitelisted addresses
        if addr in _PROTECTED_ADDRESSES:
            logger.warning("Rejected report for protected address %s from %s", address, reporter_id)
            return {
                "accepted": False,
                "reason": "This address is a known legitimate contract and cannot be reported.",
                "blacklisted": False, "reports": 0, "needed": _REPORT_THRESHOLD,
            }

        # 2. Per-user rate limiting
        uid = str(reporter_id)
        times = self._user_report_times.get(uid, [])
        times = [t for t in times if now - t < _USER_REPORT_WINDOW]
        if len(times) >= _USER_REPORT_LIMIT:
            return {
                "accepted": False,
                "reason": f"Rate limit reached — max {_USER_REPORT_LIMIT} reports per 24 h.",
                "blacklisted": False, "reports": 0, "needed": _REPORT_THRESHOLD,
            }
        times.append(now)
        self._user_report_times[uid] = times

        # 3. Already blacklisted
        if addr in self.known_scams:
            return {
                "accepted": True, "reason": "Already blacklisted.",
                "blacklisted": True, "reports": _REPORT_THRESHOLD, "needed": _REPORT_THRESHOLD,
            }

        # 4. Add to pending reports (deduplicate by reporter)
        pending = self._pending_reports.setdefault(addr, set())
        # Remove any prior report from this user
        pending = {(rid, ts) for rid, ts in pending if rid != uid}
        pending.add((uid, now))
        self._pending_reports[addr] = pending

        unique_reporters = len({rid for rid, _ in pending})

        # 5. Threshold check
        if unique_reporters >= _REPORT_THRESHOLD:
            self.add_to_blacklist(address)
            self._pending_reports.pop(addr, None)
            logger.info("Address %s blacklisted after %d independent reports", address, unique_reporters)
            return {
                "accepted": True, "reason": "Threshold met — address blacklisted.",
                "blacklisted": True, "reports": unique_reporters, "needed": _REPORT_THRESHOLD,
            }

        logger.info("Report accepted for %s (%d/%d) from %s", address, unique_reporters, _REPORT_THRESHOLD, uid)
        return {
            "accepted": True,
            "reason": f"Report recorded ({unique_reporters}/{_REPORT_THRESHOLD} needed to blacklist).",
            "blacklisted": False, "reports": unique_reporters, "needed": _REPORT_THRESHOLD,
        }

    def add_to_blacklist(self, address: str):
        """Add address to local blacklist (skips protected addresses)."""
        addr = address.lower()
        if addr in _PROTECTED_ADDRESSES:
            logger.warning("Refused to blacklist protected address %s", address)
            return
        self.known_scams.add(addr)
        logger.info(f"Added {address} to blacklist")

    def remove_from_blacklist(self, address: str):
        """Remove address from local blacklist"""
        self.known_scams.discard(address.lower())
        logger.info(f"Removed {address} from blacklist")
