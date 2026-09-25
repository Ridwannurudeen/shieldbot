# ShieldBot Python SDK

Async Python client for the ShieldBot agent transaction firewall. It sends a transaction your agent is about to sign to `POST /api/agent/firewall` and returns an ALLOW, WARN or BLOCK verdict, with a small local cache and a configurable fail mode for when the API cannot be reached.

This client covers the agent firewall check only. Token scans, the transaction firewall, reputation, threat graph, rescue and injection scans are in the [TypeScript SDK](https://github.com/Ridwannurudeen/shieldbot/tree/main/sdk) or the REST API.

## Install

The package is not on PyPI yet. Install it from the repository:

```bash
pip install "git+https://github.com/Ridwannurudeen/shieldbot.git#subdirectory=sdk/python"
```

or from a local clone:

```bash
git clone https://github.com/Ridwannurudeen/shieldbot.git
pip install ./shieldbot/sdk/python
```

After publication it will install with `pip install shieldbot` (planned name, not published yet).

Requires Python 3.9 or later. The only dependency is `httpx`.

## Changes since the unpublished 3.0.0 tree

Nothing was ever published, but code built from earlier copies of this repository behaves differently:

- `chain_id` must be a positive `int`. Anything else, including a string such as `"56"`, a `bool` or a `float`, raises `ValueError` before any request. A string chain used to be sent as it was.
- A verdict from the local cache is a copy with `cached=True`, as in the TypeScript SDK. It used to be the cached object itself, with the API's `cached` value, so a caller that changed a returned verdict changed what later calls got.

## Before you call check()

- **API key.** `check()` needs an API key (`X-API-Key`). There is no self-serve signup yet; keys are issued by the ShieldBot operator.
- **Registered agent.** The API answers 404 for an agent that is not registered. Register it once with `POST /api/agent/register` using the same API key (or the TypeScript SDK's `register()`); a different key gets 403.

## Usage

```python
import asyncio

from shieldbot import ShieldBot


async def main():
    shield = ShieldBot(api_key="sb_...", agent_id="my-agent")
    try:
        verdict = await shield.check({
            "from": "0xYourAgentWallet",
            "to": "0xTargetContract",
            "data": "0x",
            "value": "0",
            "chain_id": 4663,
        })
    finally:
        await shield.close()

    if not verdict.allowed:
        print(verdict.verdict, verdict.risk_display, verdict.flags)


asyncio.run(main())
```

### Transaction fields

| Key | Required | Notes |
|-----|----------|-------|
| `from` | yes | Sender address |
| `to` | yes | Target address |
| `chain_id` | yes | Chain ID from the table below, as a positive `int`. The SDK never assumes a chain: without it, or with anything but a positive `int` (a string such as `"56"`, a `bool`, a `float`), `check()` raises `ValueError` before sending anything. |
| `data` | no | Calldata as a hex string, default `"0x"` |
| `value` | no | Wei from 0 to 2**256 - 1, as an `int` or a decimal or `0x` hex string; omitted or `None` means `"0"`. The SDK sends it as a decimal string; anything else raises `ValueError` before sending, so the API never prices an unreadable value as zero. |

## Verdicts and unknown results

`check()` returns a `Verdict` with `verdict` (`"ALLOW"`, `"WARN"` or `"BLOCK"`), the `allowed` and `blocked` shortcuts, `score`, `flags`, `evidence`, `policy_check`, `status`, `coverage`, `coverage_reasons`, `risk_display`, `risk_level`, `category_scores`, `confidence`, `cached`, `latency_ms` and `analysis_unavailable`.

`cached` is `True` for a verdict from the local cache. Each call gets its own `Verdict`, so setting a field on one does not change what later calls get; the lists and dicts inside it (`flags`, `coverage` and the like) are shared with the cache, so treat them as read-only.

Incomplete analysis is never reported as safe. When `status` is not `"ok"`, `risk_level` is `"UNKNOWN"`, or coverage is missing or incomplete, the verdict has `status == "unknown"`, `risk_display` starting with `"Unknown"`, and an ALLOW from the API is downgraded to WARN.

## Fail modes

Network errors, timeouts and 5xx responses use the fail mode set with `fail_mode=`:

- `"cached"` (default): return an unexpired cached verdict for the identical transaction, otherwise WARN with `analysis_unavailable=True`.
- `"open"`: ALLOW with `analysis_unavailable=True`. Only use this if your agent can tolerate unchecked transactions.
- `"closed"`: BLOCK with `analysis_unavailable=True`.

4xx responses (invalid key, unregistered agent, unsupported chain, rate limit) are never turned into a verdict: they raise `ShieldBotError` with `status_code` and `message`.

## Configuration

```python
ShieldBot(
    api_key="sb_...",
    agent_id="my-agent",
    base_url="https://api.shieldbotsecurity.online",  # default
    cache_size=10000,    # local verdict cache entries
    cache_ttl=60,        # seconds a cached verdict stays valid
    fail_mode="cached",  # "cached" | "open" | "closed"
    timeout=10.0,        # seconds
)
```

## Supported chains

| Chain | ID |
|-------|-----|
| BNB Smart Chain | 56 |
| Ethereum | 1 |
| Base | 8453 |
| Arbitrum | 42161 |
| Polygon | 137 |
| Optimism | 10 |
| opBNB | 204 |
| Robinhood Chain | 4663 |

The API rejects any other chain ID with HTTP 400, which the SDK raises as `ShieldBotError`. `GET /api/health` returns the live list as `supported_chains`.

## License

MIT
