"""
Scam Database Checker
Checks addresses against known scam databases and blocklists
"""

import asyncio
import re
import time
import logging
from typing import Optional

import aiohttp
from cachetools import TLRUCache, TTLCache

from core.circuit_breaker import provider_breakers
from core.unknown_ledger import unknown_ledger

logger = logging.getLogger(__name__)

_ETH_ADDR_RE = re.compile(r'^0x[0-9a-fA-F]{40}$')

_GOPLUS_CACHE = TTLCache(maxsize=1024, ttl=30)
_GOPLUS_INFLIGHT = {}
_GOPLUS_NO_DATA = 'GoPlus has no data for this token on this chain'


def _address_security_ttu(key, result, now):
    # An address's labels change slowly; a failed lookup is retried after 30 seconds.
    return now + (600 if result['status'] == 'ok' else 30)


_GOPLUS_ADDRESS_CACHE = TLRUCache(maxsize=1024, ttu=_address_security_ttu)
_GOPLUS_ADDRESS_INFLIGHT = {}

# Response codes that ask for the same request again; their meaning is not
# documented anywhere we can read offline, so the reason stays neutral.
_GOPLUS_RETRY_CODES = (2, 4029)
_GOPLUS_ATTEMPTS = 3
_GOPLUS_BACKOFF = 0.5

# Addresses that must never be blacklisted (routers, WBNB, stables, etc.)
_PROTECTED_ADDRESSES: set[str] = set()

# Minimum independent reporters before an address is actually blacklisted
_REPORT_THRESHOLD = 3

# Max reports a single user can submit per day
_USER_REPORT_LIMIT = 5
_USER_REPORT_WINDOW = 86400  # 24 hours

# A community entry lapses after 30 days unless an admin confirms it
COMMUNITY_BLACKLIST_TTL = 30 * 86400

# How often a process that runs no hunter sweep (the bot, and the API when the sweep runs in
# workers.py) rereads the persisted blacklist: as often as the sweep prunes and reloads it.
BLACKLIST_RELOAD_SECONDS = 1800


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


class ScamMatches(list):
    """Scam database matches plus the providers that failed to answer.

    A list, so callers that expect the historical return value keep working.
    Matches with a non-empty ``failed_providers`` are incomplete, never clean.
    """

    def __init__(self, matches=(), failed_providers=(), observed_at=0, goplus_record=None):
        super().__init__(matches)
        self.failed_providers = tuple(failed_providers)
        self.observed_at = observed_at
        # GoPlus's token record, empty when it gave none: the contract service reads facts from it
        # that are not scam findings.
        self.goplus_record = goplus_record or {}


class ScamDatabase:
    """Check addresses against scam databases"""

    def __init__(self):
        # The local blacklist, persisted in the database's scam_blacklist table:
        # (chain_id, address) -> {'source', 'reports', 'expires_at'}, chain_id None for every chain.
        self.known_scams: dict[tuple[Optional[int], str], dict] = {}
        # The Database; the service container sets it. Only blacklist writes and loads use it.
        self.db = None

        # Pending reports: (chain_id, address) -> set of (reporter_id, timestamp)
        self._pending_reports: dict[tuple[int, str], set[tuple[str, float]]] = {}

        # Per-user rate limiting: reporter_id -> list of timestamps
        self._user_report_times: dict[str, list[float]] = {}

    async def check_address(self, address: str, chain_id: int = 56) -> ScamMatches:
        """
        Check address against multiple scam databases

        Returns:
            ScamMatches: matches with type and reason; ``failed_providers`` names
            each provider that did not answer, with a class-only reason
        """
        if not _ETH_ADDR_RE.match(address):
            logger.warning(f"Invalid address format passed to check_address: {address[:20]}")
            return ScamMatches(failed_providers=('Invalid address format',))

        observed_at = time.time()
        matches = []
        failed_providers = []

        # Check local blacklist
        blacklist_match = self._blacklist_match(address.lower(), chain_id)
        if blacklist_match:
            matches.append(blacklist_match)

        # Check GoPlus Security
        goplus_results = await self._check_goplus(address, chain_id)
        matches.extend(goplus_results)
        failed_providers.extend(goplus_results.failed_providers)

        return ScamMatches(
            matches, failed_providers, min(observed_at, goplus_results.observed_at), goplus_results.goplus_record
        )
    
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
        observed_at = time.time()
        result = {'status': 'unknown', 'reason': 'GoPlus unavailable', 'data': {}}
        try:
            provider_breakers.check('goplus_token', chain_id)
            url = f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={address}"
            async with aiohttp.ClientSession() as session:
                # Rate limits are retried with bounded backoff; only a failure that
                # survives every attempt is cached as unknown.
                for attempt in range(_GOPLUS_ATTEMPTS):
                    if attempt:
                        await asyncio.sleep(_GOPLUS_BACKOFF * (2 ** (attempt - 1)))
                    retriable = False
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                        if resp.status != 200:
                            result = {'status': 'unknown', 'reason': f'GoPlus HTTP {resp.status}', 'data': {}}
                            retriable = resp.status == 429
                        else:
                            payload = await resp.json()
                            code = payload.get('code') if isinstance(payload, dict) else None
                            tokens = payload.get('result') if isinstance(payload, dict) else None
                            token = tokens.get(address) if isinstance(tokens, dict) else None
                            if code in _GOPLUS_RETRY_CODES:
                                result = {'status': 'unknown', 'reason': f'GoPlus returned code {code}', 'data': {}}
                                retriable = True
                            elif code != 1:
                                result = {'status': 'unknown', 'reason': 'GoPlus returned an unsuccessful response', 'data': {}}
                            elif not isinstance(token, dict) or not token:
                                result = {'status': 'unknown', 'reason': _GOPLUS_NO_DATA, 'data': {}}
                            else:
                                result = {'status': 'ok', 'reason': None, 'data': token}
                    if not retriable:
                        break
            provider_breakers.record_status('goplus_token', chain_id, resp.status)
        except Exception as e:
            provider_breakers.record_error('goplus_token', chain_id, e)
            logger.error("Error fetching GoPlus token security: %s", type(e).__name__)
            result['reason'] = f'GoPlus request failed ({type(e).__name__})'
        finally:
            _GOPLUS_INFLIGHT.pop(flight_key, None)
        result['observed_at'] = observed_at
        unknown_ledger.record('goplus_token', chain_id, (
            'answered' if result['status'] == 'ok'
            else 'unknown' if result['reason'] == _GOPLUS_NO_DATA else 'failed'
        ))
        _GOPLUS_CACHE[key] = result
        return result

    @staticmethod
    async def fetch_address_security(address: str) -> dict:
        """GoPlus malicious-address labels, shared across concurrent scans.

        GoPlus accepts a chain but returns the same labels for every chain, so none is sent.
        """
        if not _ETH_ADDR_RE.fullmatch(address):
            return {'status': 'unknown', 'reason': 'Invalid address', 'data': {}}
        key = address.lower()
        cached = _GOPLUS_ADDRESS_CACHE.get(key)
        if cached is not None:
            return cached
        flight_key = (asyncio.get_running_loop(), key)
        if flight_key not in _GOPLUS_ADDRESS_INFLIGHT:
            _GOPLUS_ADDRESS_INFLIGHT[flight_key] = asyncio.create_task(
                ScamDatabase._fetch_address_security(key, flight_key)
            )
        return await asyncio.shield(_GOPLUS_ADDRESS_INFLIGHT[flight_key])

    @staticmethod
    async def _fetch_address_security(address: str, flight_key: tuple) -> dict:
        observed_at = time.time()
        result = {'status': 'unknown', 'reason': 'GoPlus unavailable', 'data': {}}
        try:
            # The request names no chain, so one breaker covers every chain's lookups.
            provider_breakers.check('goplus_address')
            url = f"https://api.gopluslabs.io/api/v1/address_security/{address}"
            async with aiohttp.ClientSession() as session:
                for attempt in range(_GOPLUS_ATTEMPTS):
                    if attempt:
                        await asyncio.sleep(_GOPLUS_BACKOFF * (2 ** (attempt - 1)))
                    retriable = False
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                        if resp.status != 200:
                            result = {'status': 'unknown', 'reason': f'GoPlus HTTP {resp.status}', 'data': {}}
                            retriable = resp.status == 429
                        else:
                            payload = await resp.json()
                            code = payload.get('code') if isinstance(payload, dict) else None
                            record = payload.get('result') if isinstance(payload, dict) else None
                            if code in _GOPLUS_RETRY_CODES:
                                result = {'status': 'unknown', 'reason': f'GoPlus returned code {code}', 'data': {}}
                                retriable = True
                            elif code != 1:
                                result = {'status': 'unknown', 'reason': 'GoPlus returned an unsuccessful response', 'data': {}}
                            elif not isinstance(record, dict) or not record:
                                result = {'status': 'unknown', 'reason': 'GoPlus returned no address record', 'data': {}}
                            else:
                                result = {'status': 'ok', 'reason': None, 'data': record}
                    if not retriable:
                        break
            provider_breakers.record_status('goplus_address', None, resp.status)
        except Exception as e:
            provider_breakers.record_error('goplus_address', None, e)
            logger.error("Error fetching GoPlus address security: %s", type(e).__name__)
            result['reason'] = f'GoPlus request failed ({type(e).__name__})'
        finally:
            _GOPLUS_ADDRESS_INFLIGHT.pop(flight_key, None)
        result['observed_at'] = observed_at
        unknown_ledger.record('goplus_address', None, (
            'answered' if result['status'] == 'ok'
            else 'unknown' if result['reason'] == 'GoPlus returned no address record' else 'failed'
        ))
        _GOPLUS_ADDRESS_CACHE[address] = result
        return result

    async def _check_goplus(self, address: str, chain_id: int = 56) -> ScamMatches:
        """Check GoPlus Security API for token risk indicators.

        A successful response without a record for the address is an answer, not a failure.
        """
        response = await self.fetch_token_security(address, chain_id)
        if response['status'] != 'ok' and response['reason'] != _GOPLUS_NO_DATA:
            return ScamMatches(failed_providers=(response['reason'],), observed_at=response.get('observed_at', 0))
        result = response['data']
        # GoPlus labels the token itself a scam: block. The optional keys are absent unless set, and
        # the record is the answer, so an absent key means not flagged. fake_token is an object.
        block_flags = []
        if result.get('is_airdrop_scam') == '1':
            block_flags.append('Airdrop scam token')
        fake_token = result.get('fake_token')
        if isinstance(fake_token, dict) and str(fake_token.get('value')) == '1':
            block_flags.append('Counterfeit of a mainstream token')
        # A restriction that makes the token dangerous to hold: the 70 floor. Not scam findings:
        # is_blacklisted means the contract has a blacklist function (USDT on Ethereum has one),
        # an owner power the contract service passes to structural scoring; not open source is the
        # explorer's unverified finding, which structural scoring already counts;
        # honeypot_with_same_creator describes the deployer, and GoPlus sets it on Binance-Peg
        # Dogecoin.
        flags = list(block_flags)
        if result.get('is_honeypot') == '1':
            flags.append('Honeypot (GoPlus)')
        if result.get('cannot_sell_all') == '1':
            flags.append('Cannot sell all tokens')
        if result.get('owner_change_balance') == '1':
            flags.append('Owner can change balance')
        if flags:
            return ScamMatches([{
                'type': 'GoPlus Security',
                'reason': '; '.join(flags),
                'source': 'gopluslabs.io',
                'severity': 'block' if block_flags else 'high',
            }], observed_at=response.get('observed_at', 0), goplus_record=result)
        return ScamMatches(observed_at=response.get('observed_at', 0), goplus_record=result)
    
    def _active_entry(self, key: tuple) -> Optional[dict]:
        entry = self.known_scams.get(key)
        if entry and (entry['expires_at'] is None or entry['expires_at'] > time.time()):
            return entry
        return None

    def local_match(self, address: str, chain_id: int) -> Optional[dict]:
        """The local blacklist's scam match for an address on a chain, or None: the part of
        check_address that asks no provider, so a caller can read it before GoPlus answers."""
        return self._blacklist_match(address.lower(), chain_id)

    def _blacklist_match(self, address: str, chain_id: int) -> Optional[dict]:
        """The local blacklist's scam match for an address on a chain, or None.

        An admin entry is a full, block-severity match. A community entry is a medium-severity match
        named by its report count: three users' reports are a signal anyone can manufacture, never
        evidence for a block. An admin entry outranks a community one; an expired entry and a
        protected address never match.
        """
        if address in _PROTECTED_ADDRESSES:
            return None
        entries = [
            entry for entry in (self._active_entry((chain_id, address)), self._active_entry((None, address)))
            if entry
        ]
        if not entries:
            return None
        entry = min(entries, key=lambda entry: entry['source'] != 'admin')
        if entry['source'] == 'admin':
            return {
                'type': 'Local Blacklist',
                'reason': 'Confirmed scam address',
                'source': 'ShieldBot',
                'severity': 'block',
            }
        return {
            'type': 'community_reports',
            'reason': f"Reported by {entry['reports']} users",
            'source': 'ShieldBot',
            'severity': 'medium',
            'reports': entry['reports'],
        }

    async def load_blacklist(self):
        """Replace the in-memory blacklist with the unexpired entries in the database."""
        rows = await self.db.get_active_blacklist(time.time())
        self.known_scams = {
            (row['chain_id'], row['address']): {
                'source': row['source'], 'reports': row['reports'], 'expires_at': row['expires_at'],
            }
            for row in rows if row['address'] not in _PROTECTED_ADDRESSES
        }

    async def prune_blacklist(self):
        """Delete expired entries, then reload, which also picks up entries another process wrote
        (the Telegram bot's reports)."""
        await self.db.prune_scam_blacklist(time.time())
        await self.load_blacklist()

    async def report_address(self, address: str, reporter_id: str, chain_id: int) -> dict:
        """Community report with rate-limiting, whitelist protection, and multi-report threshold.

        Reports count per chain, and the entry they make lists the address on that chain only.

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

        # 3. Already blacklisted, on this chain or on every chain; an admin entry answers first
        entries = [entry for entry in (self._active_entry((chain_id, addr)), self._active_entry((None, addr))) if entry]
        if entries:
            entry = min(entries, key=lambda entry: entry['source'] != 'admin')
            return {
                "accepted": True, "reason": "Already blacklisted.",
                "blacklisted": True, "reports": entry['reports'], "needed": _REPORT_THRESHOLD,
                "confirmed": entry['source'] == 'admin', "already_listed": True,
            }

        # 4. Add to pending reports (deduplicate by reporter). A report older than an entry's lifetime
        # no longer counts.
        key = (chain_id, addr)
        pending = {
            (rid, ts) for rid, ts in self._pending_reports.get(key, set())
            if rid != uid and now - ts < COMMUNITY_BLACKLIST_TTL
        }
        pending.add((uid, now))
        self._pending_reports[key] = pending

        unique_reporters = len({rid for rid, _ in pending})

        # 5. Threshold check
        if unique_reporters >= _REPORT_THRESHOLD:
            await self.add_to_blacklist(address, unique_reporters, chain_id)
            self._pending_reports.pop(key, None)
            logger.info("Address %s blacklisted after %d independent reports", address, unique_reporters)
            return {
                "accepted": True, "reason": "Threshold met — address blacklisted.",
                "blacklisted": True, "reports": unique_reporters, "needed": _REPORT_THRESHOLD,
                "confirmed": False, "already_listed": False,
            }

        logger.info("Report accepted for %s (%d/%d) from %s", address, unique_reporters, _REPORT_THRESHOLD, uid)
        return {
            "accepted": True,
            "reason": f"Report recorded ({unique_reporters}/{_REPORT_THRESHOLD} needed to blacklist).",
            "blacklisted": False, "reports": unique_reporters, "needed": _REPORT_THRESHOLD,
        }

    async def add_to_blacklist(self, address: str, reports: int, chain_id: Optional[int]):
        """Add a community entry (skips protected addresses). It expires after COMMUNITY_BLACKLIST_TTL
        unless an admin confirms it, and never replaces an admin entry."""
        addr = address.lower()
        if addr in _PROTECTED_ADDRESSES:
            logger.warning("Refused to blacklist protected address %s", address)
            return
        await self.db.add_community_blacklist(addr, chain_id, reports, time.time() + COMMUNITY_BLACKLIST_TTL)
        await self.load_blacklist()
        logger.info(f"Added {address} to blacklist")

    async def confirm_scam(self, address: str, chain_id: Optional[int], reason: Optional[str]) -> bool:
        """Admin confirmation: a full scam match that never expires. False for a protected address."""
        addr = address.lower()
        if addr in _PROTECTED_ADDRESSES:
            logger.warning("Refused to blacklist protected address %s", address)
            return False
        await self.db.confirm_blacklist(addr, chain_id, reason)
        await self.load_blacklist()
        logger.info(f"Confirmed {address} as a scam")
        return True

    async def remove_from_blacklist(self, address: str, chain_id: Optional[int]) -> bool:
        """Remove the entry for an address on a chain (None: the every-chain entry). True if one existed."""
        removed = await self.db.remove_blacklist(address, chain_id)
        await self.load_blacklist()
        if removed:
            logger.info(f"Removed {address} from blacklist")
        return removed
