"""Shared request accounting for the census provider probes."""

import asyncio
import json
import re
import time
from datetime import datetime, timezone

import aiohttp

from .storage import data_directory, load_data


IMPORTANT_FIELDS = (
    "is_honeypot",
    "buy_tax",
    "sell_tax",
    "cannot_sell_all",
    "transfer_pausable",
    "is_open_source",
)
WETH = "0x0bd7d308f8e1639fab988df18a8011f41eacad73"


async def sample_tokens(data_dir, limit):
    if limit < 1:
        raise ValueError("limit must be positive")
    data = await load_data(data_directory(data_dir))
    if str(data["meta"].get("chain_id")) != "4663":
        raise ValueError("Census data must identify chain 4663")
    tokens = set()
    for pool in data["pools"]:
        for key in ("token0", "token1"):
            token = pool[key].lower()
            if not re.fullmatch(r"0x[0-9a-f]{40}", token):
                raise ValueError("Invalid census token address")
            if token not in (WETH, "0x" + "0" * 40):
                tokens.add(token)
    return sorted(tokens)[:limit]


async def request_record(session, token, endpoint, *, params=None, headers=None):
    record = {
        "token": token,
        "endpoint": endpoint,
        "http_status": None,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "response": None,
        "response_headers": {},
        "fields_present": [],
        "fields_nonempty": [],
        "data_status": "unknown",
        "error": None,
    }
    started = time.monotonic()
    try:
        async with session.get(
            endpoint,
            params=params,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30),
            allow_redirects=False,
        ) as response:
            record["http_status"] = response.status
            record["response_headers"] = {
                key: value
                for key, value in response.headers.items()
                if any(
                    part in key.lower()
                    for part in ("credit", "ratelimit", "compute", "retry-after")
                )
            }
            try:
                record["response"] = await response.json(content_type=None)
            except (ValueError, UnicodeError):
                record["error"] = "Response was not valid JSON"
            if response.status != 200:
                record["error"] = f"HTTP {response.status}"
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        # Exception text can contain authenticated request URLs or headers.
        record["error"] = type(exc).__name__
    record["latency_ms"] = round((time.monotonic() - started) * 1000, 3)
    return record


def account_fields(record, fields):
    record["fields_present"] = sorted(fields)
    record["fields_nonempty"] = sorted(
        key
        for key, value in fields.items()
        if value is not None and value != "" and value != [] and value != {}
    )
    record["data_status"] = "available" if record["fields_nonempty"] else "unknown"


def save_probe(data_dir, provider, records, *, important_fields=()):
    names = set(important_fields)
    for record in records:
        names.update(record["fields_present"])
    summary = {
        name: {
            "present": sum(name in record["fields_present"] for record in records),
            "nonempty": sum(name in record["fields_nonempty"] for record in records),
        }
        for name in sorted(names)
    }
    output = {
        "version": 1,
        "chain_id": 4663,
        "provider": provider,
        "calls": len(records),
        "selection_rule": "Unique non-native, non-WETH census tokens sorted by address",
        "field_summary": summary,
        "records": records,
    }
    path = data_directory(data_dir) / f"probe_{provider}.json"
    path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    return output
