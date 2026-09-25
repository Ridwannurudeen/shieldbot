# ShieldBot TypeScript SDK

TypeScript and JavaScript client for the ShieldBot API: contract scans, the transaction firewall, agent firewall verdicts, agent reputation, the threat graph, wallet approval rescue and prompt injection scans. Requires Node.js 18 or later (it uses the global `fetch`).

## Install

The package is not on npm yet. npm cannot install a subdirectory of a Git repository, so build a tarball from a clone:

```bash
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot/sdk
npm ci
npm pack        # builds dist/ and writes shieldbot-sdk-3.1.0.tgz
```

Then, in your project:

```bash
npm install /path/to/shieldbot/sdk/shieldbot-sdk-3.1.0.tgz
```

After publication it will install with `npm install @shieldbot/sdk` (planned name, not published yet and may change before release).

## Changes since the unpublished 3.0.0 tree

Nothing was ever published, but code built from earlier copies of this repository behaves differently:

- `scan`, `firewall`, `check`, `rescue` and `queryThreatGraph` require a chain and throw `MISSING_CHAIN_ID` without one. They used to fall back to BNB Chain (56).
- A chain must be a positive integer `number`: anything else, including a string such as `'56'`, throws `INVALID_CHAIN_ID` before any request. A string chain used to be sent as it was.
- The optional chain filter of `getMempoolAlerts` and `getThreats` is checked the same way when it is given. A filter of `0` used to be dropped, which asked for every chain, and a string was sent as it was.
- `queryThreatGraph(address, { chainId, maxDepth? })` takes the chain and the depth in an options object, and the chain is required. It used to take `maxDepth` as its second argument and send no chain at all, which the API treated as BNB Chain. A call still written that way, such as `queryThreatGraph(address, 1)`, throws `MISSING_CHAIN_ID` instead of reading the depth as a chain.
- `health()` is typed with `supported_chains`, the field the API actually returns, instead of `chains`.
- `check()` and `firewall()` send `value` as decimal wei and throw `INVALID_VALUE` for anything that is not an integer from 0 to 2^256 - 1. They used to forward it unchanged.
- `rescue()` results are typed with `status`, `coverage`, `coverage_reasons`, `scanned_blocks` and `total_value_at_risk_usd`, and `rescue()` throws `SCAN_UNAVAILABLE` when the scan read nothing, instead of returning an empty approval list.
- `rescue`, `getCampaign` and `queryThreatGraph` throw `INVALID_ADDRESS` before any request for an address that is not `0x` and 40 hex digits. They used to put any string in the request path: an address ending in `#` dropped the chain (the API then read BNB Chain), one ending in `?chain_id=1&` replaced it, and `../` reached other routes with your API key.
- `rescue` and `queryThreatGraph` throw `CHAIN_MISMATCH` (status 502) when the answer's `chain_id` is not the chain asked for (the number, or the same digits as a string).
- `timeout` must be a positive number of milliseconds, at most 2^31 - 1, or the constructor throws `INVALID_TIMEOUT`. `timeout: 0` used to mean the default. `finalTimeout` follows the same rule, checked by `firewall()` before any request.
- `cacheSize: 0` turns the local verdict cache off. It used to mean the default of 10000 entries. A size that is not a whole number of 0 or more throws `INVALID_CACHE_SIZE`.
- `check()` caches a copy of the verdict it returns, and every cache hit is a copy too. It used to cache the returned object itself, so a caller that set a field on it changed what later cache hits returned.
- `firewall()` with `onFirst`: an `error` event rejects with code `STREAM_ERROR` (status 500 when the event has none) instead of no code; `onFirst` may return a promise, which is awaited, and its rejection rejects the call instead of going unhandled; and a `first` event that is not an interim verdict (`status` not `'unknown'`, `classification` not one of `CAUTION`, `HIGH_RISK` and `BLOCK_RECOMMENDED`, or `final` not `false`) is dropped instead of passed to `onFirst`.

## API key

`check()` and `register()` need an API key and an `agentId`. Every other call works without a key under a per-IP rate limit; with a key, the key's quota applies instead. There is no self-serve signup yet: keys are issued by the ShieldBot operator.

## Quick start

```typescript
import { ShieldBot } from '@shieldbot/sdk';

const shield = new ShieldBot({ apiKey: 'sb_...' });

// Scan a token. chainId is required.
const scan = await shield.scan('0xTokenAddress', { chainId: 4663 });
if (scan.status === 'unknown') {
  // Incomplete analysis: neither safe nor risky. Do not treat it as clean.
}
console.log(scan.risk_display, scan.classification);

// Agent firewall: register the agent once, then check each transaction before signing.
const agent = new ShieldBot({ apiKey: 'sb_...', agentId: 'my-agent' });
await agent.register('0xOwnerAddress');
const verdict = await agent.check({
  from: '0xAgentWallet',
  to: '0xTarget',
  data: '0x',
  value: '0',
  chainId: 4663,
});
if (!verdict.allowed) {
  console.log(verdict.verdict, verdict.risk_display, verdict.flags);
}
```

## Methods

| Method | Endpoint | API key |
|--------|----------|---------|
| `scan(address, { chainId })` | `POST /api/scan` | optional |
| `firewall(to, { chainId, from?, data?, value?, onFirst?, finalTimeout? })` | `POST /api/firewall` | optional |
| `check({ from, to, chainId, data?, value? })` | `POST /api/agent/firewall` | required, with `agentId` and a registered agent |
| `register(ownerAddress, policy?)` | `POST /api/agent/register` | required, with `agentId` |
| `checkReputation(agentId?)` | `GET /api/reputation/{agentId}` | optional |
| `queryThreatGraph(address, { chainId, maxDepth? })` | `GET /api/graph/check/{address}` | optional |
| `scanForInjection(content, depth?)` | `POST /api/scan/injection` | optional |
| `getCampaign(address)` | `GET /api/campaign/{address}` | optional |
| `rescue(walletAddress, chainId)` | `GET /api/rescue/{walletAddress}` | optional |
| `getMempoolAlerts(chainId?, limit?)` | `GET /api/mempool/alerts` | optional |
| `getThreats({ chainId?, limit?, since? })` | `GET /api/threats/feed` | optional |
| `health()` | `GET /api/health` | no |

`rescue()`, `getCampaign()` and `queryThreatGraph()` put the address in the request path, so they take only `0x` followed by 40 hex digits (upper, lower or mixed case), and throw `ShieldBotError` with code `INVALID_ADDRESS` before any request for anything else. `rescue()` and `queryThreatGraph()` also throw code `CHAIN_MISMATCH` (status 502) if the answer's `chain_id` is not the chain they asked for.

`value` for `check()` and `firewall()` is wei as a decimal or `0x` hex string; omitted or `null` means `0`. The SDK sends it as a decimal string and throws `ShieldBotError` with code `INVALID_VALUE` before any request for anything that is not an integer from 0 to 2^256 - 1, so the API never prices an unreadable value as zero. The API answers `check()` with 404 until the agent is registered with the same API key; a different key gets 403.

## Unknown results

Incomplete analysis is never reported as safe. Scan and firewall results carry `status`, `coverage`, `coverage_reasons` and `risk_display`; when `status` is `'unknown'` the result is not a clean bill of health. `check()` also downgrades an ALLOW to WARN when the API reports incomplete coverage, and marks the verdict `status: 'unknown'`.

`rescue()` results carry `status`, `coverage`, `coverage_reasons`, `scanned_blocks` (the block range whose approval history was read) and `total_value_at_risk_usd`. When `status` is not `'ok'` the scan is incomplete: an empty `approvals` list does not mean the wallet has no risky approvals, and `total_value_at_risk_usd` is `null`. A partial scan is returned so you can show what was found and why the rest is missing. When nothing could be read, `rescue()` throws `ShieldBotError` with code `SCAN_UNAVAILABLE` (status 503) instead of returning an empty result.

```typescript
const rescue = await shield.rescue('0xWallet', 56);
if (rescue.status !== 'ok') {
  console.log('Incomplete approval scan:', rescue.coverage_reasons, rescue.scanned_blocks);
}
```

## Fast first verdict

`firewall()` can stream its answer. Pass `onFirst` and the API may send an interim verdict while its analysis still runs; `firewall()` still resolves with the final verdict, the same result a plain call returns, with `final: true`. Without `onFirst` the call is the plain request it always was.

```typescript
const result = await shield.firewall('0xTarget', {
  chainId: 56,
  from: '0xSender',
  data: '0x...',
  onFirst: (first) => {
    // Always status 'unknown', never SAFE: show it as "analysis in progress".
    if (first.classification === 'BLOCK_RECOMMENDED') {
      console.log('Blocked early:', first.danger_signals);
    }
  },
});
```

- The interim verdict (`FirstVerdict`) comes as soon as a hard floor already puts the transaction in `BLOCK_RECOMMENDED` (an address the ShieldBot operator confirmed as a scam, for example), otherwise about 3 seconds after the API starts on the request, and only while the analysis is still running. A fast analysis sends only the final.
- It always has `status: 'unknown'` and is never `SAFE`. Its `risk_score` and `classification` come only from floors already known, never from a partial average, and the final applies the same floors, so its band is never above the final's with one exception: since it is never `SAFE`, a floor below the `CAUTION` band shows as `CAUTION` while the final may be `SAFE`. `CAUTION` with `risk_score` 0 means nothing is known yet. It lists `pending_sources` (the analyzers still running) and `elapsed_ms`, and has no `evidence_hash` or `evidence_url`: only the final is recorded.
- The API sends no interim verdict when its policy mode is STRICT. That mode is the server's own: the SDK sends no `X-Policy-Mode` header, so a caller cannot choose STRICT here. A STRICT server answers with the plain JSON, which `firewall()` returns as it is, and `onFirst` is not called.
- `finalTimeout` (default 30000 ms) replaces `timeout` for a streamed call: it bounds the wait for the response and then for each next event. Like `timeout`, it must be positive and at most 2^31 - 1 ms, or `firewall()` throws `INVALID_TIMEOUT` before any request.
- An `error` event rejects with `ShieldBotError` code `STREAM_ERROR` and the API's HTTP status, or 500 when the event carries none. A stream that ends without a final rejects with code `NETWORK_ERROR`.
- `GET /api/verdicts` publishes this contract as `first_verdict`.
- The SDK holds the API to it: a `first` event whose `status` is not `'unknown'`, whose `classification` is not exactly `CAUTION`, `HIGH_RISK` or `BLOCK_RECOMMENDED`, or whose `final` is not `false` is dropped, and `onFirst` is not called for it. The API never sends one.
- An exception thrown by `onFirst`, or the rejection of a promise it returns, is not caught: `firewall()` rejects with it and stops reading the stream. A promise `onFirst` returns is awaited before the stream is read on, and the time it takes counts toward `finalTimeout`.

## Supported chains

`scan`, `firewall`, `check`, `rescue` and `queryThreatGraph` require a chain. The SDK never assumes one: without it they throw `ShieldBotError` with code `MISSING_CHAIN_ID` before sending anything. Chain parameters take a plain `number`, such as a wallet's chain ID, and it must be a positive integer: a string such as `'56'` or `'0x38'`, a fraction, zero or a negative number throws `ShieldBotError` with code `INVALID_CHAIN_ID`, also before sending anything. `getMempoolAlerts` and `getThreats` take an optional chain filter, checked the same way when it is given; leaving it out asks for every chain.

The chains below are exported as `SUPPORTED_CHAIN_IDS` (type `ChainId`), and `isSupportedChainId()` checks a number against them:

```typescript
import { isSupportedChainId } from '@shieldbot/sdk';

const chainId = Number(await provider.request({ method: 'eth_chainId' })); // any EIP-1193 wallet provider
if (!isSupportedChainId(chainId)) {
  // ShieldBot cannot analyze this chain: treat the transaction as unchecked, not as safe.
}
```

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

The SDK does not reject other chains itself. The API answers a chain it does not serve with HTTP 400, which the SDK throws as `ShieldBotError`; `check()` never turns it into a fail-mode verdict. `health()` returns the live list as `supported_chains`.

## Configuration

```typescript
const shield = new ShieldBot({
  apiKey: 'sb_...',          // Required for check() and register()
  agentId: 'my-agent',       // Required for check() and register()
  baseUrl: 'https://...',    // Custom API URL (default: https://api.shieldbotsecurity.online)
  timeout: 10000,            // Request timeout in ms: positive, at most 2^31 - 1 (else INVALID_TIMEOUT)
  cacheSize: 10000,          // Local verdict cache entries, a whole number >= 0; 0 turns the cache off
  cacheTtl: 60,              // Cache TTL in seconds (bounds stale decisions to one minute)
  failMode: 'cached',        // 'cached' | 'open' | 'closed'
});
```

## Fail modes

The fail mode applies to `check()` when the API is unreachable, times out or returns a 5xx error:

- **`cached`** (default): return an unexpired cached verdict for the identical transaction; otherwise return `WARN` with `analysis_unavailable: true`.
- **`open`**: allow the transaction (`analysis_unavailable: true`).
- **`closed`**: block the transaction (`analysis_unavailable: true`).

`check()` keeps verdicts in a local cache (`cacheSize`, `cacheTtl`), and a verdict from it has `cached: true`. With `cacheSize: 0` nothing is cached: every call asks the API, and the `cached` fail mode has no verdict to fall back on, so it returns `WARN`. Each call gets its own `Verdict` object, so setting a field on one does not change what later calls get. The objects and arrays inside it (`flags`, `coverage`, `coverage_reasons`, `category_scores`, `policy_check`) are shared with the cache, so treat them as read-only.

4xx responses to `check()` (invalid key, unregistered agent, unsupported chain, rate limit) are thrown as `ShieldBotError`, never turned into a verdict. The other methods throw `ShieldBotError` on every failure; `status` holds the HTTP status (408 with code `TIMEOUT`, 0 with code `NETWORK_ERROR`).

## Development

The package runs on Node.js 18 or later. `npm test` needs Node.js 20.4 or later: the stream tests (`tests/stream.cjs`) use `node:test`'s mock timers.

## License

MIT
