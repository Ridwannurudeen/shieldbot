<div align="center">

# ShieldBot

**On-chain guarded transfers for Robinhood Chain, backed by inspectable token-risk evidence.**

[Judge guide](docs/JUDGE_GUIDE.md) · [Recorded simulations](tests/fixtures/robinhood_simulation/) · [Verdict registry source](contracts/base/src/ShieldBotVerdictRegistry.sol) · [Test results](docs/TESTING.md)

</div>

A token can accept a buy and refuse the sell. A familiar stock ticker can belong to an unrelated contract. On Robinhood Chain (**4663**, an Arbitrum Orbit L2), ShieldBot checks token launches, simulates supported buy/sell routes, and preserves missing evidence as **UNKNOWN**.

The core scan path refuses to call incomplete data safe and flags dangers supported by its checks. **This is not a claim that every interface blocks every unknown transaction.** Human interfaces can offer a proceed option; SDK callers must enforce the returned decision. There is no dedicated stock-issuer authentication check: fake stock-token impostors are part of the problem, not a solved identity-verification feature.

**Start with the [ten-minute judge guide](docs/JUDGE_GUIDE.md).** Its recorded honeypot and three-outcome examples run locally without a network connection or API key once Python dependencies are installed.

## On-chain permission before funds move

[`ShieldBotVerdictGuard`](contracts/base/src/ShieldBotVerdictGuard.sol) reads the latest registry record and allows only LOW or MEDIUM within the caller's publication-age tolerance. `check(address subject, uint64 maxAge)` returns `(bool allowed, uint8 reason)`; `requireAllowed(address subject, uint64 maxAge)` reverts with `NotAllowed(subject, reason)` on denial. MEDIUM deliberately accepts moderate reported risk; permission is not a token-safety guarantee.

| Code | Reason | Meaning |
|---|---|---|
| 0 | `ALLOWED` | Recorded LOW/MEDIUM, non-future and within a positive `maxAge` |
| 1 | `NO_RECORD` | No evidence hash has been recorded |
| 2 | `UNKNOWN` | Fresh record with incomplete evidence |
| 3 | `HIGH` | High risk, even when expired or future-dated |
| 4 | `HONEYPOT` | Proven sell trap in the recorded verdict, even when expired or future-dated |
| 5 | `EXPIRED` | Non-adverse record exceeds `maxAge`, or `maxAge` is zero |
| 6 | `FUTURE_TIMESTAMP` | Non-adverse publication is ahead of the check clock |

Denial precedence is `NO_RECORD → HIGH/HONEYPOT → FUTURE_TIMESTAMP → EXPIRED → UNKNOWN`; fresh LOW/MEDIUM returns `ALLOWED`. An old honeypot still reports `HONEYPOT`, avoiding a misleading suggestion to retry after a refresh. A zero tolerance always denies.

The worked consumer is [`ShieldBotGuardedTransfer`](contracts/base/GUARDED_TRANSFER.md): it pins the guard, subject, USDG token and recipient. After approval, a caller invokes `transfer(amount, maxAge)`. The guard must allow the subject before `safeTransferFrom` runs; the recipient's balance increase must then equal `amount` exactly or the entire call reverts with `ShortDelivery(requested, delivered)`. Only a successful exact credit emits `GuardedTransfer`. Fee tokens are rejected. Recipients must be EOAs or passive contracts; forwarding in a recipient hook fails the credit check.

[Run the local allowed/honeypot/unknown/expired demonstration](docs/JUDGE_GUIDE.md#on-chain-transfer-demonstration-offline). It uses the real registry, guard and transfer in the Foundry test VM with a mock ERC-20; it does not establish a live deployment.

## Scope before the demo

- **Repository versus release:** the browser extension's provider-bound chain-identification fix is on a branch and will **not** be released before the submission deadline. The shipped extension still has an omitted-chain identification limitation. Source tests do not establish released Robinhood coverage; real MetaMask, Rabby and EIP-6963 testing and Chrome Web Store review remain outstanding.
- **Simulation is route-bounded:** Robinhood support covers the implemented native/WETH v4 routes, Doppler-hooked v4 routes, and WETH-quoted V2 pairs. USDG is supported only for Doppler-hooked v4 pools. Hookless USDG pools are explicitly unsupported; the V2 adapter discovers WETH pairs, not USDG pairs. No V2 USDG route is covered. The owner's observation that no V2 USDG pairs exist has not been independently rechecked in this documentation pass.
- **Unknown is an outcome:** RPC failure, unsupported routes, insufficient liquidity, unattributed reverts or unmeasurable fields must not be read as a clean bill of health. A successful simulated round-trip describes that amount, route and recorded state, not future sellability.
- **Coverage is partial across surfaces:** scan metadata reaches the REST, MCP, Telegram and SDK paths, but auxiliary MCP tools, phishing checks, signature heuristics and dashboard summaries do not all have equivalent coverage semantics. The dashboard is not an evidence viewer. See [the detailed limitations](docs/TECHNICAL.md).
- **On-chain publication is pending deployment:** the registry and publisher are in this checkout. No deployment address or live confirmation is asserted here. An evidence document with `onchain_status: off` is stored locally only.

## What is different

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

Use **`maxAge = 600` seconds for the demo only with `GUARD_WATCH_MAX_SUBJECTS=1`**. This is a required condition: `GuardedTransfer.subject` is a single immutable address, and the demo watches exactly that subject. Use **900 seconds as the production minimum at the default four watched subjects**. Coordinator measurements put healthy record ages at typically **320–360 s**, a healthy worst of **~437 s**, **~625 s** with four subjects bunched after restart, and **~740 s** after one lost interval. Thus `maxAge = 300` would deny a perfectly healthy token for roughly **6–30% of wall time**; Foundry's `MAX_AGE = 300` is a boundary-test fixture, not operating guidance. These supplied measurements were not re-probed during this local-only work.

Recurring publication covers only the bounded [watched set](docs/guard-rescans.md). Neither operating window guarantees uninterrupted permission: lost intervals, scan overruns, repeated failures and delayed inclusion can cause denials. An overrun can publish UNKNOWN and cause **60–150 s** of content denial in the measured scenario, even before expiry; choose a demo subject whose scans complete reliably.

### Seven recorded request/response pairs

[Fixtures](tests/fixtures/robinhood_simulation/) preserve the simulation requests and unmodified call results for native/WETH v4 pools, Doppler hooks, V2, the proven honeypot and USDG. The fixture notes explicitly say that block-header fields other than `number` were trimmed. They are recorded RPC evidence, not full historical state or cryptographic execution proofs.

Tests rebuild the calldata and compare it with the saved request, then evaluate the recorded response. Mutated failure cases test where the classifier must remain unknown. Offline replay tests this implementation against the recordings; it does not execute an archival EVM.

## We simulate round-trips for USDG-quoted launches

For **Doppler-hooked v4 pools only**, the simulator funds a simulated buyer with Paxos USDG through a storage override. The source and fixture record the verified implementation layout: `balanceData` is at **slot 1**, with the `uint64` balance packed into the low eight bytes. The request overrides `keccak256(abi.encode(buyer, 1))` and performs the approvals, buy and sell inside `eth_simulateV1`.

The [USDG fixture](tests/fixtures/robinhood_simulation/v4_doppler_usdg.json) records block **67,286,521**; [tests](tests/test_robinhood_simulation_usdg.py) check the slot calculation, uint64-sized funding budget, exact calldata and returned measurements. Hookless USDG pools remain unsupported, and V2 USDG pairs are not part of the implemented route discovery. These are simulated balances, not payments, deposits or real buyer funding. The storage-layout verification is recorded provenance; this documentation pass did not repeat a live chain probe.

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

The registry branch is wired to Robinhood Telegram scans and hunter scans, not every REST request. Launch discovery and its feed are 4663-specific. Backend services use FastAPI, async HTTP and SQLite; contract, market, behavioral, honeypot, intent and signature analyzers have different data requirements. Consumer policy and display behavior differ.

| Interface in the repository | Entry point and scope |
|---|---|
| REST | `POST /api/scan`, `POST /api/firewall`: scan results and transaction analysis. |
| Agent API | `POST /api/agent/firewall`: policy decision; unknown coverage requires owner approval rather than automatic allowance. |
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
| Robinhood Chain | 4663 |
| BNB Smart Chain | 56 |
| Ethereum | 1 |
| Base | 8453 |
| Arbitrum One | 42161 |
| Polygon PoS | 137 |
| Optimism | 10 |
| opBNB | 204 |

Provider availability varies by chain. Robinhood uses its own `eth_simulateV1` path; it is excluded from pending-transaction mempool monitoring. A configured adapter does not establish supported honeypot simulation, reputation or liquidity data for every token.

## Run the local evidence path

From a checkout with the project Python dependencies available:

```bash
python -m pytest tests/test_robinhood_simulation.py tests/test_robinhood_simulation_usdg.py -q -p no:cacheprovider
python -m pytest sdk/python/tests/ -q -p no:cacheprovider
```

Measured on **2026-09-22** in `build/oh-integration`: **2,917 passed, 1 skipped** (`python -m pytest tests/ -q -p no:cacheprovider --ignore=tests/test_bot_app.py`); Foundry **114 passed, 0 failed, 0 skipped**, including both 10,000-case permission fuzz tests. The simulation subset returned **192 passed**; the separate Python SDK suite returned **21 passed**. Size build and formatting of touched Solidity files passed. All five Slither gates exited zero; the unchanged attestor also reports two preexisting low-severity event-reentrancy findings alongside the known OpenZeppelin finding. Commands, exclusion and dependency qualifications are in [TESTING.md](docs/TESTING.md). These counts are test results, not scan volume or detection-accuracy measurements.

For dependency setup and the short copy/paste examples, follow [JUDGE_GUIDE.md](docs/JUDGE_GUIDE.md). No wallet, private key, deployment or broadcast is needed for the offline path.

## Submission status and measured usage

- **Registry deployment:** `OWNER TODO — fill the deployment table in docs/JUDGE_GUIDE.md after deployment`.
- **Measured usage:** `OWNER TODO — insert the live GET /api/stats response, UTC retrieval time and deployed revision`. No scan-volume figure has been supplied. Dashboard loading values and historical projections are not usage evidence.
- **Release boundary:** this README describes this repository snapshot. Deployment, live evidence URLs and the browser-store release must be verified separately.

MIT — see [LICENSE](LICENSE).
