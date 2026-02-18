"""Benchmark dataset loading and data classes."""

import json
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class BenchmarkEntry:
    """A labeled address for evaluation."""
    address: str
    chain_id: int
    label: str  # "malicious" or "safe"
    category: Optional[str] = None  # e.g. "honeypot", "rug_pull", "legitimate"
    description: Optional[str] = None


def load_dataset(path: str) -> List[BenchmarkEntry]:
    """Load benchmark entries from a JSON file."""
    with open(path, 'r') as f:
        data = json.load(f)

    entries = []
    for item in data.get('entries', []):
        entries.append(BenchmarkEntry(
            address=item['address'],
            chain_id=item.get('chain_id', 56),
            label=item['label'],
            category=item.get('category'),
            description=item.get('description'),
        ))
    return entries
