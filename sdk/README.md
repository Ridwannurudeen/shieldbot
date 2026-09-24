# ShieldBot TypeScript SDK

TypeScript and JavaScript client for the ShieldBot API: contract scans, the transaction firewall, agent firewall verdicts, agent reputation, the threat graph, wallet approval rescue and prompt injection scans. Requires Node.js 18 or later (it uses the global `fetch`).

## Install

The package is not on npm yet. npm cannot install a subdirectory of a Git repository, so build a tarball from a clone:

```bash
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot/sdk
npm ci
npm pack        # builds dist/ and writes shieldbot-sdk-3.0.0.tgz
```

Then, in your project:

```bash
npm install /path/to/shieldbot/sdk/shieldbot-sdk-3.0.0.tgz
```

After publication it will install with `npm install @shieldbot/sdk` (planned name, not published yet and may change before release).

## Changes since the unpublished 3.0.0 tree

Nothing was ever published, but code built from earlier copies of this repository behaves differently:

- `scan`, `firewall`, `check`, `rescue` and `queryThreatGraph` require a chain and throw `MISSING_CHAIN_ID` without one. They used to fall back to BNB Chain (56).
- `queryThreatGraph(address, chainId, maxDepth?)` takes the chain as a new second argument, so `maxDepth` moved to third. It used to send no chain at all, which the API treated as BNB Chain.
- `health()` is typed with `supported_chains`, the field the API actually returns, instead of `chains`.
- `check()` and `firewall()` send `value` as decimal wei and throw `INVALID_VALUE` for anything that is not a non-negative integer. They used to forward it unchanged.
- `rescue()` results are typed with `status`, `coverage`, `coverage_reasons`, `scanned_blocks` and `total_value_at_risk_usd`, and `rescue()` throws `SCAN_UNAVAILABLE` when the scan read nothing, instead of returning an empty approval list.

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
| `firewall(to, { chainId, from?, data?, value? })` | `POST /api/firewall` | optional |
| `check({ from, to, chainId, data?, value? })` | `POST /api/agent/firewall` | required, with `agentId` and a registered agent |
| `register(ownerAddress, policy?)` | `POST /api/agent/register` | required, with `agentId` |
| `checkReputation(agentId?)` | `GET /api/reputation/{agentId}` | optional |
| `queryThreatGraph(address, chainId, maxDepth?)` | `GET /api/graph/check/{address}` | optional |
| `scanForInjection(content, depth?)` | `POST /api/scan/injection` | optional |
| `getCampaign(address)` | `GET /api/campaign/{address}` | optional |
| `rescue(walletAddress, chainId)` | `GET /api/rescue/{walletAddress}` | optional |
| `getMempoolAlerts(chainId?, limit?)` | `GET /api/mempool/alerts` | optional |
| `getThreats({ chainId?, limit?, since? })` | `GET /api/threats/feed` | optional |
| `health()` | `GET /api/health` | no |

`value` for `check()` and `firewall()` is wei as a decimal or `0x` hex string (default `0`). The SDK sends it as a decimal string and throws `ShieldBotError` with code `INVALID_VALUE` before any request for anything that is not a non-negative integer, so the API never prices an unreadable value as zero. The API answers `check()` with 404 until the agent is registered with the same API key; a different key gets 403.

## Unknown results

Incomplete analysis is never reported as safe. Scan and firewall results carry `status`, `coverage`, `coverage_reasons` and `risk_display`; when `status` is `'unknown'` the result is not a clean bill of health. `check()` also downgrades an ALLOW to WARN when the API reports incomplete coverage, and marks the verdict `status: 'unknown'`.

`rescue()` results carry `status`, `coverage`, `coverage_reasons`, `scanned_blocks` (the block range whose approval history was read) and `total_value_at_risk_usd`. When `status` is not `'ok'` the scan is incomplete: an empty `approvals` list does not mean the wallet has no risky approvals, and `total_value_at_risk_usd` is `null`. A partial scan is returned so you can show what was found and why the rest is missing. When nothing could be read, `rescue()` throws `ShieldBotError` with code `SCAN_UNAVAILABLE` (status 503) instead of returning an empty result.

```typescript
const rescue = await shield.rescue('0xWallet', 56);
if (rescue.status !== 'ok') {
  console.log('Incomplete approval scan:', rescue.coverage_reasons, rescue.scanned_blocks);
}
```

## Supported chains

`scan`, `firewall`, `check`, `rescue` and `queryThreatGraph` require a chain. The SDK never assumes one: without it they throw `ShieldBotError` with code `MISSING_CHAIN_ID` before sending anything. Chain parameters take a plain `number`, such as a wallet's chain ID.

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
  timeout: 10000,            // Request timeout in ms
  cacheSize: 10000,          // Local verdict cache entries
  cacheTtl: 60,              // Cache TTL in seconds (bounds stale decisions to one minute)
  failMode: 'cached',        // 'cached' | 'open' | 'closed'
});
```

## Fail modes

The fail mode applies to `check()` when the API is unreachable, times out or returns a 5xx error:

- **`cached`** (default): return an unexpired cached verdict for the identical transaction; otherwise return `WARN` with `analysis_unavailable: true`.
- **`open`**: allow the transaction (`analysis_unavailable: true`).
- **`closed`**: block the transaction (`analysis_unavailable: true`).

4xx responses to `check()` (invalid key, unregistered agent, unsupported chain, rate limit) are thrown as `ShieldBotError`, never turned into a verdict. The other methods throw `ShieldBotError` on every failure; `status` holds the HTTP status (408 with code `TIMEOUT`, 0 with code `NETWORK_ERROR`).

## License

MIT
