"""Facts about a transaction counterparty (an approval or permit spender).

One RPC call tells a wallet from a contract (an EIP-7702 delegated wallet has code, but only the
delegation designator), the explorer gives verification and age, and GoPlus gives
malicious-address labels. Each fact is None when its provider did not answer, and coverage says
which facts are known, so a rule never reads an unknown as clean.
"""

import asyncio
import time
from typing import Optional

from cachetools import TTLCache

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

_FACTS_CACHE = TTLCache(maxsize=1024, ttl=300)


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


class CounterpartyService:
    """Looks up counterparty facts, cached for five minutes per chain and address."""

    def __init__(self, web3_client, scam_db):
        self._web3 = web3_client
        self._scam_db = scam_db

    def allowlisted_name(self, address: str, chain_id: int) -> Optional[str]:
        """The chain adapter's router name, or Permit2, which no adapter lists."""
        lower = address.lower()
        routers = self._web3._get_adapter(chain_id).get_whitelisted_routers()
        return routers.get(lower) or ("Permit2" if lower == PERMIT2 else None)

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
        if key in _FACTS_CACHE:
            return _FACTS_CACHE[key]

        code, verification, creation, security = await asyncio.gather(
            self._web3.get_bytecode(address, chain_id=chain_id),
            self._web3.is_verified_contract(address, chain_id=chain_id),
            self._web3.get_contract_creation_info(address, chain_id=chain_id),
            self._scam_db.fetch_address_security(address),
        )
        # web3 6 returns the code hex with 0x, web3 7 without.
        code_hex = None if code is None else code.lower().removeprefix("0x")
        is_contract = None if code_hex is None else len(code_hex) > 0
        delegated = (
            None
            if code_hex is None
            else (code_hex.startswith(DELEGATION_PREFIX) and len(code_hex) == DELEGATION_HEX_LENGTH)
        )
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
