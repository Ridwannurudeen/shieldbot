"""Benchmark dataset loading and data classes.

Two formats load into the same entries:
  v1 (eval/data/benchmark_v1.json): a label, "malicious" or "safe", and a category; no sources.
  v2 (FORMAT_V2, eval/data/benchmark_v2.json): one class from CLASSES per entry, the date its label was
     confirmed, and for every malicious label at least one source, none of them a provider ShieldBot
     scores with, each with its URL and the date it was retrieved. eval/README.md describes the format.
An entry marked stale (its label no longer holds) is left out when a dataset is loaded.
"""

import json
import re
from dataclasses import dataclass, field
from typing import List, Optional

FORMAT_V2 = "shieldbot-benchmark/2"
CLASSES = (
    "honeypot",
    "rug_pull",
    "drainer_contract",
    "approval_drainer_spender",
    "address_poisoning",
    "impostor_token",
    "fake_claim",
    "safe",
)
# Providers whose answers feed ShieldBot's score. A label taken from one of them would grade ShieldBot
# against its own inputs, so no malicious v2 label may cite them.
SCORING_PROVIDERS = frozenset({
    "goplus", "honeypot.is", "tokensniffer", "dexscreener", "ethos", "tenderly", "etherscan",
    "blockscout", "shieldbot",
})
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")


@dataclass
class BenchmarkEntry:
    """A labeled address for evaluation."""
    address: str
    chain_id: int
    label: str  # "malicious" or "safe"
    category: Optional[str] = None  # v1: e.g. "honeypot", "legitimate"; v2: the entry's class
    description: Optional[str] = None
    sources: List[dict] = field(default_factory=list)  # v2: where the label comes from
    labeled: Optional[str] = None  # v2: the date the label was confirmed, YYYY-MM-DD
    counterpart: Optional[str] = None  # v2 address_poisoning: the address the entry imitates


def load_dataset(path: str) -> List[BenchmarkEntry]:
    """Load the entries of a v1 or v2 benchmark file, leaving out stale ones.

    Raises ValueError, naming the entry, when a v2 file breaks the format's rules.
    """
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if data.get('format') == FORMAT_V2:
        return _load_v2(data)

    entries = []
    for item in data.get('entries', []):
        if item.get('stale'):
            continue
        entries.append(BenchmarkEntry(
            address=item['address'],
            chain_id=item.get('chain_id', 56),
            label=item['label'],
            category=item.get('category'),
            description=item.get('description'),
        ))
    return entries


def _load_v2(data: dict) -> List[BenchmarkEntry]:
    entries = []
    seen = set()
    for index, item in enumerate(data.get('entries', [])):
        where = f"entry {index} ({item.get('address')})"
        if item.get('class') not in CLASSES:
            raise ValueError(f"{where}: class must be one of {', '.join(CLASSES)}")
        if not isinstance(item.get('address'), str) or not _ADDRESS.fullmatch(item['address']):
            raise ValueError(f"{where}: address is not a 20-byte hex address")
        if type(item.get('chain_id')) is not int:
            raise ValueError(f"{where}: chain_id must be an integer")
        if not _is_date(item.get('labeled')):
            raise ValueError(f"{where}: labeled must be a YYYY-MM-DD date")
        key = (item['chain_id'], item['address'].lower())
        if key in seen:
            raise ValueError(f"{where}: listed twice on chain {item['chain_id']}")
        seen.add(key)
        sources = item.get('sources', [])
        if not isinstance(sources, list):
            raise ValueError(f"{where}: sources must be a list")
        for source in sources:
            if not (
                isinstance(source, dict)
                and isinstance(source.get('provider'), str)
                and isinstance(source.get('url'), str) and source['url'].startswith('https://')
                and _is_date(source.get('retrieved'))
                and isinstance(source.get('evidence'), str) and source['evidence']
            ):
                raise ValueError(f"{where}: every source needs a provider, an https url, a retrieved date and evidence")
        malicious = item['class'] != 'safe'
        if malicious and not sources:
            raise ValueError(f"{where}: a malicious label needs at least one source")
        if malicious and any(source['provider'].lower() in SCORING_PROVIDERS for source in sources):
            raise ValueError(f"{where}: a malicious label cannot cite a provider ShieldBot scores with")
        counterpart = item.get('counterpart')
        if item['class'] == 'address_poisoning' and not (
            isinstance(counterpart, str) and _ADDRESS.fullmatch(counterpart)
        ):
            raise ValueError(f"{where}: an address_poisoning entry needs the counterpart address it imitates")
        stale = item.get('stale')
        if stale is not None and not (
            isinstance(stale, dict) and _is_date(stale.get('date')) and isinstance(stale.get('reason'), str)
        ):
            raise ValueError(f"{where}: stale must give a date and a reason")
        if stale:
            continue
        entries.append(BenchmarkEntry(
            address=item['address'],
            chain_id=item['chain_id'],
            label='malicious' if malicious else 'safe',
            category=item['class'],
            description=item.get('description'),
            sources=sources,
            labeled=item['labeled'],
            counterpart=counterpart,
        ))
    return entries


def _is_date(value) -> bool:
    return isinstance(value, str) and _DATE.fullmatch(value) is not None
