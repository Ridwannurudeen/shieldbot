<div align="center">

# ShieldBot

**ShieldBot is the security layer that says what it checked.** Every verdict carries its coverage, and an agent can refuse to act on anything stale or Unknown; the verdict registry and guard that let a Robinhood Chain contract do the same are built, tested and deployed on Robinhood Chain ([addresses](docs/DEPLOYMENTS.md)). We build on GoPlus, honeypot.is and others; we do not pretend to replace them.

[Try it](#try-it) · [Browser extension](extension/) · [Judge guide](docs/JUDGE_GUIDE.md) · [Recorded simulations](tests/fixtures/robinhood_simulation/) · [Verdict registry source](contracts/base/src/ShieldBotVerdictRegistry.sol) · [Deployed contracts](docs/DEPLOYMENTS.md) · [Test results](docs/TESTING.md)

</div>

A token can accept a buy and refuse the sell. A familiar stock ticker can belong to an unrelated contract. On Robinhood Chain (**4663**, an Arbitrum Orbit L2), ShieldBot checks token launches, simulates supported buy/sell routes, and preserves missing evidence as **UNKNOWN**.

The core scan path refuses to call incomplete data safe and flags dangers supported by its checks. **This is not a claim that every interface blocks every unknown transaction.** Human interfaces can offer a proceed option; SDK callers must enforce the returned decision.

**Start with the [ten-minute judge guide](docs/JUDGE_GUIDE.md).** Its recorded honeypot and three-outcome examples run locally without a network connection or API key once Python dependencies are installed.

## Try it

1. **Replay the evidence offline.** With the Python dependencies from the [judge guide's preparation](docs/JUDGE_GUIDE.md#preparation) installed, the [local evidence path](#run-the-local-evidence-path) replays the recorded honeypot and the other simulations with no network connection or API key.
2. **Load the browser extension.** [`extension/`](extension/) is version 3.1.0 and loads unpacked: open `chrome://extensions`, turn on Developer mode, choose Load unpacked and select `extension/`. The extension itself needs no API key or account, and [SETUP_GUIDE.md](SETUP_GUIDE.md) says what each surface shows. The [demo page](https://shieldbotsecurity.online/try/) sends one Robinhood Chain transaction per firewall outcome; it needs a wallet extension installed alongside, connected and switched to Robinhood Chain (4663), preferably with a fresh test account. 3.1.0 has not been tested against MetaMask or Rabby.
3. **The Web Store build is older.** The [Chrome Web Store listing](https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk) served 3.0.1 on 2026-10-04, which predates the chain-identification fix. Evaluate the unpacked build.
4. **Check a live record.** [Section 3 of the judge guide](docs/JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api) hashes a served evidence document and matches it to its event in the verdict registry `0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138`, deployed on Robinhood Chain on 2026-09-27.

Live: [shieldbotsecurity.online](https://shieldbotsecurity.online) · [threat dashboard](https://api.shieldbotsecurity.online/dashboard)

## On-chain permission before funds move

[`ShieldBotVerdictGuard`](contracts/base/src/ShieldBotVerdictGuard.sol) reads the latest registry record and allows only LOW or MEDIUM within the caller's publication-age tolerance. `check(address subject, uint64 maxAge)` returns `(bool allowed, uint8 reason)`; `requireAllowed(address subject, uint64 maxAge)` reverts with `NotAllowed(subject, reason)` on denial. MEDIUM deliberately accepts moderate reported risk; permission is not a token-safety guarantee.

The guard answers one of seven reason codes, from `ALLOWED` (0) to `FUTURE_TIMESTAMP` (6). A high-risk or honeypot record keeps its adverse reason even when expired, and a zero `maxAge` always denies. The [reason table and its precedence](docs/JUDGE_GUIDE.md#what-the-on-chain-guard-enforces) are in the judge guide.

The worked consumer is [`ShieldBotGuardedTransfer`](contracts/base/GUARDED_TRANSFER.md): it pins the guard, subject, USDG token and recipient, asks the guard before `safeTransferFrom` runs, and reverts with `ShortDelivery(requested, delivered)` unless the recipient's balance rises by exactly `amount`. A Robinhood Chain simulation transferred 500,000 units of Paxos USDG and credited the recipient exactly 500,000 units. What exact credit catches, what it does not, and the recipient constraint are in the [judge guide](docs/JUDGE_GUIDE.md#on-chain-transfer-demonstration-offline).

[Run the local allowed/honeypot/unknown/expired demonstration](docs/JUDGE_GUIDE.md#on-chain-transfer-demonstration-offline). It uses the real registry, guard and transfer in the Foundry test VM with a mock ERC-20; it does not establish a live deployment.

## Scope before the demo

- **Repository versus release:** the browser extension's provider-bound chain-identification fix is on `main` but remains unreleased. The shipped extension still has an omitted-chain identification limitation. Source tests do not establish released Robinhood coverage; real MetaMask, Rabby and EIP-6963 testing and Chrome Web Store review remain outstanding.
- **Simulation is route-bounded:** Robinhood support covers the implemented native/WETH v4 routes, Doppler-hooked v4 routes, and WETH-quoted V2 pairs. USDG is supported only for Doppler-hooked v4 pools. Hookless USDG pools are explicitly unsupported; the V2 adapter discovers WETH pairs, not USDG pairs. No V2 USDG route is covered. Whether any V2 USDG pairs exist has not been rechecked.
- **Unknown is an outcome:** RPC failure, unsupported routes, insufficient liquidity, unattributed reverts or unmeasurable fields must not be read as a clean bill of health. A successful simulated round-trip describes that amount, route and recorded state, not future sellability.
- **Coverage is partial across surfaces:** scan metadata reaches the REST, MCP, Telegram and SDK paths, but auxiliary MCP tools, phishing checks, signature heuristics and dashboard summaries do not all have equivalent coverage semantics. The dashboard's Robinhood Chain panel links each blocked launch to its stored evidence document at `/api/verdict`; its other tiles are summaries. See [the detailed limitations](docs/TECHNICAL.md).
- **On-chain publication covers a bounded set:** the registry is live on Robinhood Chain ([DEPLOYMENTS.md](docs/DEPLOYMENTS.md)). Production records Telegram scans, guard rescans, and launches or rechecks that are blocked or guard-watched; other launch verdicts are stored with `onchain_status: off`, which is not on-chain evidence.

## What is different

### Stock-token impostors are labelled, not scored

Robinhood Chain tokens are compared with Robinhood's published list of official stock tokens. A listed contract is reported as official. A token is reported as an impostor when its ticker and name both copy an official token, when it claims Robinhood beside an official ticker or company name, or when it matches only after look-alike characters are folded. A bare shared ticker or name, or a symbol in another issuer's convention (TSLAx named an xStock, TSLA.d, wTSLA, bTSLA named Backed), is a collision. This is a name check against Robinhood's list, not authentication of any issuer; an impostor label heads the report and the launch alert, and no label changes the risk score or the published on-chain verdict.

### Missing evidence has a representation

Provider fields can be `true`, `false` or `null`; `null` does not become a measured zero. Analyzer coverage and reasons travel through the [risk engine](core/risk_engine.py), [API](api.py), and consumer models. The [evidence mapper](core/verdict_evidence.py) emits `UNKNOWN` for an incomplete scan, even if its numeric score is low. An attributed simulation honeypot remains `HONEYPOT` when other fields are missing.

The [Solidity registry](contracts/base/src/ShieldBotVerdictRegistry.sol) uses `UNKNOWN = 0`, followed by `LOW`, `MEDIUM`, `HIGH`, `HONEYPOT`. An address never recorded therefore reads as unknown, not low risk; `recordCount` distinguishes absence from a recorded unknown. This is a distinction between missing data and an observed low-risk result, not an enforcement policy shared by every UI.

### A failed sell needs attribution

The [Robinhood simulator](services/robinhood_simulation.py) buys, measures what arrived, attempts a sell, and records a plain transfer to a fresh address. It does not label every sell revert a honeypot.

After a successful, adequately sized buy and successful approvals, `_sell_trap` accepts these specific causes:

| Sell failure | What it establishes in the simulation |
|---|---|
| Route-specific `TRANSFER_FROM_FAILED` | The token refused the sell transfer to the pool. |
| V2 `INSUFFICIENT_INPUT_AMOUNT` or v4 `SwapAmountCannotBeZero` | The pair or pool manager received no sell credit. |
| Wrapped `HookCallFailed` attributed to that pool's own hook | The pool's hook prevented the sell. |

Other reverts remain **unattributed and unknown**, with the reason preserved. Router errors, missing approvals and an unsupported RPC method are not evidence that the token is a honeypot. Separately, a successful sell returning zero output is classified as a trap only after payout-log checks and a minimum buy-cost threshold rule out the implemented dust/rounding case; otherwise it stays unknown.

The recorded honeypot at block **65,554,454** bought successfully, rejected the sell with `TransferHelper: TRANSFER_FROM_FAILED`, and still allowed a plain transfer. Its sell tax is **unknown**, not an invented 100%. [Replay it locally](docs/JUDGE_GUIDE.md#1-replay-the-recorded-honeypot-offline).

### The evidence document is committed by hash

[Canonical JSON](core/verdict_evidence.py) uses sorted keys, compact separators and UTF-8; its `keccak256` digest is submitted to the verdict registry. The API serves the exact canonical string alongside publication status. A judge can hash those bytes and compare them with the `evidenceHash` in a `VerdictRecorded` event.

That comparison proves document integrity against a recorder's on-chain commitment. It does **not** prove the recorder's observations were correct. The contract accepts records from an authorized recorder; the owner can rotate that recorder. It holds no funds, makes no external calls and has no upgrade mechanism in the reviewed source. [Exact verification commands](docs/JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api).

The [verdict guard](contracts/base/VERDICT_GUARD.md) enforces **publication freshness**, not observation freshness. The registry sets `Record.timestamp = block.timestamp` when the recording transaction executes. The publisher's observation-age cutoff gates broadcast only; an already broadcast transaction can land arbitrarily later, so observation age is not bounded on-chain.

Use **`maxAge = 600` seconds for the demo only with `GUARD_WATCH_MAX_SUBJECTS=1`**, and **900 seconds as the production minimum at the default four watched subjects**. Both are calculations, not on-chain observations, and neither guarantees uninterrupted permission. Recurring publication covers only the bounded [watched set](docs/guard-rescans.md); the derivation and the denial windows are in the [judge guide](docs/JUDGE_GUIDE.md#freshness-operating-conditions).

### Seven recorded request/response pairs

[Fixtures](tests/fixtures/robinhood_simulation/) preserve the simulation requests and unmodified call results for native/WETH v4 pools, Doppler hooks, V2, the proven honeypot and USDG. The fixture notes explicitly say that block-header fields other than `number` were trimmed. They are recorded RPC evidence, not full historical state or cryptographic execution proofs.

Tests rebuild the calldata and compare it with the saved request, then evaluate the recorded response. Mutated failure cases test where the classifier must remain unknown. Offline replay tests this implementation against the recordings; it does not execute an archival EVM.

## We simulate round-trips for USDG-quoted launches

For **Doppler-hooked v4 pools only**, the simulator funds a simulated buyer with Paxos USDG through a storage override. The source and fixture record the verified implementation layout: `balanceData` is at **slot 1**, with the `uint64` balance packed into the low eight bytes. The request overrides `keccak256(abi.encode(buyer, 1))` and performs the approvals, buy and sell inside `eth_simulateV1`.

The [USDG fixture](tests/fixtures/robinhood_simulation/v4_doppler_usdg.json) records block **67,286,521**; [tests](tests/test_robinhood_simulation_usdg.py) check the slot calculation, uint64-sized funding budget, exact calldata and returned measurements. Hookless USDG pools remain unsupported, and V2 USDG pairs are not part of the implemented route discovery. These are simulated balances, not payments, deposits or real buyer funding. The storage-layout verification is recorded provenance; the live chain probe has not been repeated since.

## Architecture and entry points

```text
Chain adapters / provider lookups / Robinhood eth_simulateV1
                         |
             Analyzers -> RiskEngine
             status + coverage + reasons + findings
                         |
        REST / MCP / Telegram / SDK / extension source
                         |
       4663 scan publication -> canonical evidence in SQLite
                         |
         optional publisher -> ShieldBotVerdictRegistry
                                      |
                          ShieldBotVerdictGuard
                        check / requireAllowed
                                      |
                       ShieldBotGuardedTransfer
                         exact recipient credit
```

The registry publication path is wired to Robinhood Telegram scans and hunter scans, not every REST request. With `PUBLISH_LAUNCH_VERDICTS_ONCHAIN=0`, the hunter's launch and recheck verdicts are stored and served but recorded on-chain only when blocked or watched by the guard; guard rescans are always recorded. Launch discovery and its feed are 4663-specific. Backend services use FastAPI, async HTTP and SQLite; contract, market, behavioral, honeypot, intent and signature analyzers have different data requirements. Consumer policy and display behavior differ.

| Interface in the repository | Entry point and scope |
|---|---|
| REST | `POST /api/scan`: a quick contract check with no sell simulation, so a token it recognises reads Unknown there, never SAFE. `POST /api/firewall`: transaction analysis and the full token check. |
| Agent API | `POST /api/agent/firewall`: policy decision; unknown coverage, or a native value with no USD estimate (any chain but BSC and opBNB), requires owner approval rather than automatic allowance. |
| API keys | `POST /api/keys/free`: one free-tier key (60 requests a minute, 1,000 a day) per email address, created from a single-use emailed link that expires after 30 minutes. Off, with a 503, unless the server has a Resend API key. See [TECHNICAL.md](docs/TECHNICAL.md#api-demo). |
| Evidence | `GET /api/verdict/4663/{address}`: latest stored evidence and publication status. |
| Launch feed | `GET /api/launches/4663`: discovered launches and available scan outcomes; not every token on the chain. |
| MCP | [mcp_server/](mcp_server/): scan and launch tools; approval-risk and threat-graph stubs explicitly report unknown. |
| SDKs | [Python](sdk/python/) and [TypeScript](sdk/): retain coverage metadata. Explicit fail-open configuration can allow unavailable analysis. |
| Telegram | [bot.py](bot.py): 12 registered commands, including `/launchalerts` and `/stopalerts`; advisory output does not stop wallet transactions. |
| Browser / RPC proxy | [extension/](extension/) has the shipped-chain limitation above. The [proxy](rpc/proxy.py) sees only requests routed through it, forwards contract creation without analysis, and receives raw transactions after signing. |

### Configured scan chains, not equal coverage

The [container](core/container.py) and [Web3 client](utils/web3_client.py) configure these eight adapters. This table describes source routing, not independently verified live availability on each chain.

| Chain | ID |
|---|---:|
| Ethereum | 1 |
| Robinhood Chain | 4663 |
| BNB Smart Chain | 56 |
| Base | 8453 |
| Arbitrum One | 42161 |
| Polygon PoS | 137 |
| Optimism | 10 |
| opBNB | 204 |

Provider availability varies by chain. Robinhood Chain and Arbitrum use ShieldBot's own `eth_simulateV1` path. On Arbitrum it simulates only pools pairing the token with WETH on Uniswap V3, Uniswap V2 or SushiSwap ([arbitrum_simulation.py](services/arbitrum_simulation.py)); a token with no such pool, for example one traded only on Camelot or only against stablecoins, gets GoPlus's honeypot and tax flags alone. Robinhood Chain is excluded from pending-transaction mempool monitoring, as are Base, Arbitrum and Optimism, which have no public mempool. A pool larger than 8 MB (Ethereum's and Polygon's today) is watched through the node's candidate next block, its pending block, rather than the whole pool; the pool's size is checked again every 10 minutes. A configured adapter does not establish supported honeypot simulation, reputation or liquidity data for every token.

## Run the local evidence path

From a checkout with the project Python dependencies available:

```bash
python -m pytest tests/test_robinhood_simulation.py tests/test_robinhood_simulation_usdg.py -q -p no:cacheprovider
python -m pytest sdk/python/tests/ -q -p no:cacheprovider
```

Verified on **2026-10-04** at `main` revision **`0f1c326`**: the main Python suite returned **6,550 passed**, and the two fresh-process import test files, run separately, returned **114 passed**. Commands, exclusions and dependency qualifications are in [TESTING.md](docs/TESTING.md), and earlier measurements in [SUBMISSION.md](docs/SUBMISSION.md#reproducible-verification). These counts are test results, not scan volume or detection-accuracy measurements.

For dependency setup and the short copy/paste examples, follow [JUDGE_GUIDE.md](docs/JUDGE_GUIDE.md). No wallet, private key, deployment or broadcast is needed for the offline path.

## ShieldBot does not issue a token

ShieldBot does not issue, sell, control or endorse any token. An earlier extension release used the BNB Chain token `0x4904c02efa081cb7685346968bac854cdf4e7777` (SHIELDBOT) as an access gate for its deployer alert feed; that gate has been removed. Tokens using the ShieldBot name, including the two Robinhood Chain tokens below, are not ShieldBot products.

| Symbol | Name | Token address | Pool (paired with NVDA, opened 2026-09-15) |
|---|---|---|---|
| SBOT | shieldbot | `0x8adba5e2f8ebe8a6f8d9f4c8151fba7ce2328900` | `0xc5183c987d5429466e271003c15d333e313e488f` |
| SHIELD | shieldbot_ | `0x7bf4c3cd40710b027282b6b85d86f75acfcbd0f1` | `0xb4a4085eec22bc088e46a615ddb2f1b327235a86` |

Token names, symbols and pools as listed by GeckoTerminal (network `robinhood`) and confirmed on-chain.

## Submission status and measured usage

- **Registry deployment:** the Robinhood Chain verdict registry, guard and guarded transfer were deployed on 2026-09-27. Their addresses, owner, recorder and deployment transactions are in [DEPLOYMENTS.md](docs/DEPLOYMENTS.md), with the Base and BNB Smart Chain contracts, which were retired on 2026-09-26 and receive no new records.
- **Measured usage:** the `GET /api/stats` snapshot supplied on **2026-09-22** is recorded in [SUBMISSION.md](docs/SUBMISSION.md); its time of day and the revision serving it were not supplied. Dashboard loading values and historical projections are not usage evidence.
- **Release boundary:** this README describes this repository snapshot. Deployment, live evidence URLs and the browser-store release must be verified separately.

Use of the hosted service is covered by the [Terms of Service](https://shieldbotsecurity.online/terms.html) and the [Privacy Policy](https://shieldbotsecurity.online/privacy.html).

MIT — see [LICENSE](LICENSE).
