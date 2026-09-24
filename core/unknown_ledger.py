"""The Unknown ledger: how often each data provider answered, per chain.

One count per request ShieldBot sends to a provider; an answer reused from one of ShieldBot's
short-lived provider caches is not counted again. Each request ends in one outcome:
  answered  the provider returned the data asked for
  unknown   the provider replied that it has none for this subject: a 404, no record, no trading
            pairs, no phishing verdict, or a sell simulation that ran but could not decide
  failed    no usable reply: a network error or timeout, any other error status, a refusal, or a
            body that could not be read

Providers: honeypot.is and eth_simulateV1 (sell simulation), goplus_token, goplus_phishing (asked
about a URL, so it has no chain), etherscan, blockscout and sourcify (verification and contract
creation), dexscreener, and rpc (the chain's RPC; a revert is the node answering).

Counts live in memory: they restart from zero with the process, and counting_since says when the
current count began. Each process keeps its own, so the API's ledger covers the API's scans, the
hunter and the launch watch, and not the Telegram bot.
"""

import time
from collections import defaultdict
from typing import Dict, Optional

OUTCOMES = ("answered", "unknown", "failed")


class UnknownLedger:
    def __init__(self):
        self.counting_since = time.time()
        self._counts: Dict[tuple, Dict[str, int]] = defaultdict(lambda: dict.fromkeys(OUTCOMES, 0))
        self._last: Dict[tuple, Dict] = {}

    def record(self, provider: str, chain_id: Optional[int], outcome: str):
        """Count one request's outcome; chain_id is None for a provider asked about no chain."""
        key = (chain_id, provider)
        self._counts[key][outcome] += 1
        self._last[key] = {"last_outcome": outcome, "last_at": time.time()}

    def for_chain(self, chain_id: Optional[int]) -> Dict[str, Dict]:
        """Each provider's counts on one chain, with its latest outcome and when it came."""
        return {
            provider: {**counts, **self._last[(key_chain, provider)]}
            for (key_chain, provider), counts in self._counts.items()
            if key_chain == chain_id
        }

    def summary(self) -> Dict:
        """Counts per provider summed over chains, and per chain summed over providers."""
        by_provider: Dict[str, Dict[str, int]] = defaultdict(lambda: dict.fromkeys(OUTCOMES, 0))
        by_chain: Dict[int, Dict[str, int]] = defaultdict(lambda: dict.fromkeys(OUTCOMES, 0))
        for (chain_id, provider), counts in self._counts.items():
            for outcome, count in counts.items():
                by_provider[provider][outcome] += count
                if chain_id is not None:
                    by_chain[chain_id][outcome] += count
        return {
            "counting_since": self.counting_since,
            "by_provider": dict(by_provider),
            "by_chain": dict(by_chain),
        }


unknown_ledger = UnknownLedger()
