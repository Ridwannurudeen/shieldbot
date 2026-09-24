"""Facts about a transaction counterparty (an approval or permit spender).

One RPC call tells a wallet from a contract (an EIP-7702 delegated wallet has code, but only the
delegation designator), the explorer gives verification and age, and GoPlus gives
malicious-address labels. Each fact is None when its provider did not answer, and coverage says
which facts are known, so a rule never reads an unknown as clean.
"""

import asyncio
import copy
import time
from typing import Optional

from cachetools import TLRUCache

# Canonical Uniswap Permit2, deployed at the same address on every EVM chain.
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
# EIP-7702: a delegated account's code is 0xef0100 followed by the 20-byte delegate address.
DELEGATION_PREFIX = "ef0100"
DELEGATION_HEX_LENGTH = 46

# GoPlus address_security labels that mark a drainer or theft address. Airdrop spam (gas_abuse)
# and interface quirks are left out: each label here justifies refusing an approval.
THEFT_LABELS = (
    "phishing_activities",
    "stealing_attack",
    "blacklist_doubt",
    "honeypot_related_address",
    "fake_token",
    "cybercrime",
    "money_laundering",
    "financial_crime",
    "blackmail_activities",
    "sanctioned",
    "malicious_mining_activities",
    "mixer",
    "darkweb_transactions",
)

# Complete facts hold for five minutes, which covers a drainer campaign's repeat requests. Facts
# with a gap are looked up again after 30 seconds, so one provider blip does not leave a spender
# Unknown for five minutes.
COMPLETE_FACTS_TTL = 300
INCOMPLETE_FACTS_TTL = 30


def _facts_ttu(key, facts, now):
    return now + (COMPLETE_FACTS_TTL if all(facts["coverage"].values()) else INCOMPLETE_FACTS_TTL)


_FACTS_CACHE = TLRUCache(maxsize=1024, ttu=_facts_ttu)
_FACTS_INFLIGHT = {}

# Each provider answers within this or counts as unknown, so a slow explorer or RPC leaves one
# fact Unknown instead of running the intent analyzer past the registry's 25-second deadline.
PROVIDER_TIMEOUT = 8


async def within_timeout(awaitable, unknown):
    """The lookup's answer, or `unknown` after PROVIDER_TIMEOUT. Only the caller stops waiting: the
    lookup runs on to its own provider timeout, so it still records its outcome in the Unknown
    ledger once (and fills its cache for the next scan)."""
    try:
        return await asyncio.wait_for(asyncio.shield(awaitable), PROVIDER_TIMEOUT)
    except asyncio.TimeoutError:
        return unknown


def code_kind(code: Optional[str]) -> tuple:
    """(is_contract, delegated) from an eth_getCode answer; (None, None) when the code is unknown.

    web3 6 returns the hex with 0x and web3 7 without. An EIP-7702 delegated account has code, but
    only the delegation designator: it is a wallet.
    """
    if code is None:
        return None, None
    code_hex = code.lower().removeprefix("0x")
    return len(code_hex) > 0, code_hex.startswith(DELEGATION_PREFIX) and len(code_hex) == DELEGATION_HEX_LENGTH


def unknown_facts(address: str) -> dict:
    """Facts for a counterparty nobody could look up."""
    return {
        "address": address.lower(),
        "allowlisted": None,
        "is_contract": None,
        "delegated": None,
        "is_verified": None,
        "age_days": None,
        "labels": None,
        "label_source": "",
        "coverage": {"code": False, "verification": False, "age": False, "labels": False},
        "reason": "Spender facts unknown: no counterparty lookup available",
        "observed_at": time.time(),
    }


def _allowlisted_name(web3_client, address: str, chain_id: int) -> Optional[str]:
    """The scanned chain adapter's router name, or Permit2, which no adapter lists."""
    lower = address.lower()
    routers = web3_client._get_adapter(chain_id).get_whitelisted_routers() if web3_client else {}
    return routers.get(lower) or ("Permit2" if lower == PERMIT2 else None)


def approval_grant(decoded: dict) -> Optional[tuple]:
    """(spender, unlimited) when decoded calldata grants a positive allowance, else None.

    Revokes (amount 0, setApprovalForAll(operator, false), a DAI permit with allowed false) grant
    nothing. Permit2's own calldata selectors decode no spender, so they are not judged here.
    """
    params = decoded.get("params") or {}
    selector = decoded.get("selector")
    if selector in ("095ea7b3", "39509351"):  # approve, increaseAllowance(spender, amount)
        amount = params.get("param_1")
        granted, spender = isinstance(amount, int) and amount > 0, params.get("param_0")
        unlimited = bool(decoded.get("is_unlimited_approval"))
    elif selector == "a22cb465":  # setApprovalForAll(operator, approved)
        granted, spender, unlimited = params.get("param_1") is True, params.get("param_0"), True
    elif selector == "d505accf":  # EIP-2612 permit(owner, spender, value, deadline, ...)
        value = params.get("param_2")
        granted, spender = isinstance(value, int) and value > 0, params.get("param_1")
        unlimited = bool(decoded.get("is_unlimited_approval"))
    elif selector == "8fcbaf0c":  # DAI permit(holder, spender, nonce, expiry, allowed): all or nothing
        granted, spender, unlimited = params.get("param_4") is True, params.get("param_1"), True
    else:
        return None
    return (spender, unlimited) if granted and spender else None


def judge_spender(facts: dict, unlimited: bool) -> tuple:
    """Hard floor for granting a non-allowlisted spender a token allowance.

    Returns (floor or None, the floor's flag or None, unknown). A rule fires only on facts that
    are known; unknown is True when a fact the verdict depends on is not, so the caller reports
    the verdict as incomplete instead of clean. Legitimate protocols verify their contracts, so
    an unverified spender is refused outright for an unlimited grant; a wallet or a labelled
    address never needs an allowance.
    """
    labels, age, verified = facts["labels"], facts["age_days"], facts["is_verified"]
    unknown = labels is None or facts["is_contract"] is None
    if labels:
        source = f" ({facts['label_source']})" if facts["label_source"] else ""
        return 100, f"Spender flagged by GoPlus: {', '.join(labels)}{source}", unknown
    if facts["is_contract"] is False:
        return 100, "Approval to a wallet address, not a contract (drainer pattern)", unknown
    if facts["delegated"]:
        return 100, "Approval to an EIP-7702 delegated wallet, not a protocol contract", unknown
    # With the code unknown the rules below still fire on what the explorer said; the address
    # could be a wallet (100), so their floors are a lower bound and the verdict stays unknown.
    if verified is None:
        return None, None, True
    if verified is False:
        if age is not None and age < 7:
            return 85, f"Spender contract is unverified and {age} days old", unknown
        # A limited grant to an unverified contract of unknown age might be one under 7 days (85).
        floor = 85 if unlimited else 60
        return floor, "Spender contract is unverified", unknown or (not unlimited and age is None)
    if not unlimited:
        return None, None, unknown
    if age is None:
        return None, None, True
    if age < 7:
        return 60, f"Spender contract is {age} days old", unknown
    return None, None, unknown


class CounterpartyService:
    """Looks up counterparty facts, cached for five minutes per chain and address."""

    def __init__(self, web3_client, scam_db):
        self._web3 = web3_client
        self._scam_db = scam_db

    def allowlisted_name(self, address: str, chain_id: int) -> Optional[str]:
        return _allowlisted_name(self._web3, address, chain_id)

    async def fetch(self, address: str, chain_id: int) -> dict:
        lower = address.lower()
        observed_at = time.time()
        allowlisted = self.allowlisted_name(lower, chain_id)
        if allowlisted:
            return {
                **unknown_facts(lower),
                "allowlisted": allowlisted,
                "coverage": {"code": True, "verification": True, "age": True, "labels": True},
                "reason": None,
                "observed_at": observed_at,
            }
        key = (chain_id, lower)
        cached = _FACTS_CACHE.get(key)
        if cached is not None:
            return copy.deepcopy(cached)
        # Concurrent scans of one spender share a single lookup.
        flight_key = (asyncio.get_running_loop(), key)
        if flight_key not in _FACTS_INFLIGHT:
            _FACTS_INFLIGHT[flight_key] = asyncio.create_task(self._lookup(address, chain_id, key, flight_key))
        # Each caller gets its own copy: a caller that edits its facts must not edit the cache's.
        return copy.deepcopy(await asyncio.shield(_FACTS_INFLIGHT[flight_key]))

    async def _lookup(self, address: str, chain_id: int, key: tuple, flight_key: tuple) -> dict:
        try:
            return await self._facts(address, chain_id, key)
        finally:
            _FACTS_INFLIGHT.pop(flight_key, None)

    async def _facts(self, address: str, chain_id: int, key: tuple) -> dict:
        lower = address.lower()
        observed_at = time.time()
        timed_out = {"status": "unknown", "reason": "GoPlus timed out", "data": {}}
        code, verification, creation, security = await asyncio.gather(
            within_timeout(self._web3.get_bytecode(address, chain_id=chain_id), None),
            within_timeout(self._web3.is_verified_contract(address, chain_id=chain_id), (None, None)),
            within_timeout(self._web3.get_contract_creation_info(address, chain_id=chain_id), None),
            within_timeout(self._scam_db.fetch_address_security(address), timed_out),
        )
        is_contract, delegated = code_kind(code)
        # A wallet has no source to verify and no creation to date.
        wallet = is_contract is False or delegated is True
        is_verified = None if wallet else verification[0]
        age_days = None if wallet or not creation else creation.get("age_days")

        labels = None
        label_source = ""
        if security["status"] == "ok":
            record = security["data"]
            labels = [label for label in THEFT_LABELS if record.get(label) == "1"]
            created = str(record.get("number_of_malicious_contracts_created", "0"))
            if created.isdigit() and int(created) > 0:
                labels.append("number_of_malicious_contracts_created")
            label_source = record.get("data_source") or ""

        coverage = {
            "code": is_contract is not None,
            "verification": wallet or is_verified is not None,
            "age": wallet or age_days is not None,
            "labels": labels is not None,
        }
        missing = {
            "code": "code (RPC)",
            "verification": "verification (explorer)",
            "age": "age (explorer)",
            "labels": f"labels ({security['reason']})",
        }
        unknown = [missing[fact] for fact, known in coverage.items() if not known]
        facts = {
            "address": lower,
            "allowlisted": None,
            "is_contract": is_contract,
            "delegated": delegated,
            "is_verified": is_verified,
            "age_days": age_days,
            "labels": labels,
            "label_source": label_source,
            "coverage": coverage,
            "reason": "Spender facts unknown: " + ", ".join(unknown) if unknown else None,
            "observed_at": observed_at,
        }
        _FACTS_CACHE[key] = facts
        return facts


class UnavailableCounterparty:
    """Stands in where no lookup is wired (bare analyzers, the container-less API): every fact is
    unknown. The allowlist still holds: the chain adapter's routers when a web3 client is given,
    and Permit2."""

    def __init__(self, web3_client=None):
        self._web3 = web3_client

    def allowlisted_name(self, address: str, chain_id: int) -> Optional[str]:
        return _allowlisted_name(self._web3, address, chain_id)

    async def fetch(self, address: str, chain_id: int) -> dict:
        return unknown_facts(address)
