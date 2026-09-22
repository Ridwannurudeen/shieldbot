# ShieldBot — Arbitrum Open House Singapore submission draft

**DO NOT SUBMIT WITH ANY `OWNER_FILL_...` FIELD REMAINING. All three contract deployments are pending.**

Buildathon window: **September 14–October 4, 2026**. Submission closes **October 4, 2026 at 15:59 UTC**. These event dates are supplied by the owner for this submission; they were not independently checked during local preparation.

## What was built and why

ShieldBot adds token-risk evidence and an explicit on-chain permission check for Robinhood Chain (**4663**). A token can accept a buy yet refuse a sell, while unavailable provider data can be mistaken for a clean result. The Robinhood implementation discovers launches, simulates supported buy/sell routes, preserves missing evidence as UNKNOWN, and stores canonical evidence documents for inspection.

Three contracts connect that evidence to an application action:

- [`ShieldBotVerdictRegistry`](../contracts/base/src/ShieldBotVerdictRegistry.sol) records an authorized recorder's verdict and the keccak256 hash of its evidence document. The owner can rotate the recorder through the registry's access controls.
- [`ShieldBotVerdictGuard`](../contracts/base/src/ShieldBotVerdictGuard.sol) reads an immutable registry and allows only recorded LOW or MEDIUM verdicts within the caller's positive publication-age limit. Missing, unknown, high-risk, honeypot, expired and future-dated records are denied.
- [`ShieldBotGuardedTransfer`](../contracts/base/src/ShieldBotGuardedTransfer.sol) pins the guard, subject, USDG token and recipient. It checks permission before transferring the caller's approved USDG and reverts unless the recipient's balance increases by exactly the requested amount. The subject being assessed need not itself be USDG.

The intended users are people inspecting Robinhood launches and applications that want to make a payment conditional on a recorded risk policy. The contract consumer adds enforcement for that specific payment path; advisory interfaces and other wallet transactions have different behavior. This is a working implementation and reproducible test path, not a claim of measured adoption or detection accuracy.

## Deployment evidence — owner must complete

**NOT DEPLOYED AS OF THIS DRAFT (2026-09-22).** No live contract verification or live guarded USDG payment is claimed. Complete every field below from the actual chain-4663 deployment and completed source-verification results. A submitted explorer verification request is not a completed result.

| Contract | Deployed address | Deployment transaction hash |
|---|---|---|
| ShieldBotVerdictRegistry | **OWNER_FILL_REGISTRY_ADDRESS** | **OWNER_FILL_REGISTRY_DEPLOY_TX_HASH** |
| ShieldBotVerdictGuard | **OWNER_FILL_GUARD_ADDRESS** | **OWNER_FILL_GUARD_DEPLOY_TX_HASH** |
| ShieldBotGuardedTransfer | **OWNER_FILL_TRANSFER_ADDRESS** | **OWNER_FILL_TRANSFER_DEPLOY_TX_HASH** |

| Contract | Etherscan verified source link | Blockscout verified source link | Sourcify match link |
|---|---|---|---|
| ShieldBotVerdictRegistry | **OWNER_FILL_REGISTRY_ETHERSCAN_VERIFICATION_LINK** | **OWNER_FILL_REGISTRY_BLOCKSCOUT_VERIFICATION_LINK** | **OWNER_FILL_REGISTRY_SOURCIFY_VERIFICATION_LINK** |
| ShieldBotVerdictGuard | **OWNER_FILL_GUARD_ETHERSCAN_VERIFICATION_LINK** | **OWNER_FILL_GUARD_BLOCKSCOUT_VERIFICATION_LINK** | **OWNER_FILL_GUARD_SOURCIFY_VERIFICATION_LINK** |
| ShieldBotGuardedTransfer | **OWNER_FILL_TRANSFER_ETHERSCAN_VERIFICATION_LINK** | **OWNER_FILL_TRANSFER_BLOCKSCOUT_VERIFICATION_LINK** | **OWNER_FILL_TRANSFER_SOURCIFY_VERIFICATION_LINK** |

Follow the [deployment runbook](../contracts/base/DEPLOY_ROBINHOOD.md) and fill the additional online-evidence fields in the [judge guide](JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api). Reconcile this draft's deployment status with those records before submitting. With `ROBINHOOD_VERDICT_REGISTRY` unset, evidence is still stored and served, but publication is off; an `off` result is not on-chain evidence.

## What was produced during the Buildathon

ShieldBot existed before September 14. The pre-window revision `c1d1adf` already contains the risk engine, REST API, Telegram bot, browser extension, Python and TypeScript SDKs, MCP server and an attestor contract. Those foundations are not claimed as new Buildathon work.

The public history through the starting revision `04203be` contains these four in-window commits. Dates below come from git history; the descriptions also reflect the changed files and current implementation.

| Date (2026) | Commit | Work landed during the window |
|---|---|---|
| September 17 | `a60fc45` | Robinhood Chain routing and adapter; explicit unknown provider coverage through the engine and consumer paths; explorer enrichment; chain census tooling and regression tests. |
| September 19 | `00b3c81` | Robinhood `eth_simulateV1` buy/sell simulation, recorded route fixtures, launch discovery and hunter integration; durable API quotas and hardening of incomplete-data and sell-failure classification. |
| September 20 | `9ca9c31` | Verdict registry and deployment tooling; canonical evidence, persistent history and optional publisher; public launch feed, MCP launch access, opt-in Telegram alerts and shared RPC budgeting; Doppler USDG simulation and its recorded fixture. |
| September 22 | `04203be` | Verdict guard and exact-credit guarded USDG transfer, wiring assertions and Foundry tests; observation provenance, refresh publication and bounded guard-subject rescans; extension chain-identification source fix; revised coverage disclosures and reproducible judge guide. |

Reproduce the history boundary from the repository root:

```bash
git log 04203be --since=2026-09-14T00:00:00Z --until=2026-10-04T15:59:00Z --format='%h %aI %s'
git show --stat a60fc45 00b3c81 9ca9c31 04203be
```

Additional in-window work on `chore/oh-final` removes the stale hardcoded deployment address and makes setup fail immediately when `VPS_IP` is unset, adds a [read-only post-deployment verifier](../scripts/verify_deployment.py) with [mocked RPC tests](../tests/test_verify_deployment.py), and assembles this submission package. This branch work is separate from the four commits already landed on `main`; it does not establish a deployment or a released extension.

## Sponsor technologies used

| Technology | Concrete integration in this repository |
|---|---|
| Robinhood Chain | Chain-4663 adapter, launch discovery and `eth_simulateV1` simulation; the verdict contracts and owner deployment runbook target this chain. See [adapter](../adapters/robinhood.py), [discovery](../services/launch_discovery.py) and [simulator](../services/robinhood_simulation.py). |
| Paxos / USDG | Doppler-hooked v4 USDG round-trip simulation uses a simulated balance override for the Paxos proxy identified by `USDG` in the simulator. A [recorded fixture](../tests/fixtures/robinhood_simulation/v4_doppler_usdg.json) and [tests](../tests/test_robinhood_simulation_usdg.py) cover the request and measurements. The guarded transfer is designed to move real approved USDG after deployment; no such live payment is claimed here. |
| OpenZeppelin | The registry uses `Ownable2Step`; the guarded transfer uses `SafeERC20` and `ReentrancyGuard`. Imports are visible in the contract sources linked above, with dependencies pinned in the repository. |

## Coverage and trust boundaries

- **Extension fix is not released.** The provider-bound chain-identification fix is in the repository, but the shipped browser extension retains its omitted-chain identification limitation. Real MetaMask, Rabby and EIP-6963 testing and Chrome Web Store review remain outstanding; released Robinhood extension coverage is not claimed.
- **Simulation covers selected routes.** Native/WETH v4 routes, supported Doppler-hooked v4 routes and WETH-quoted V2 pairs are implemented. USDG support is **Doppler-hooked v4 only**. Hookless USDG pools and V2 USDG routes are not covered. A simulated round-trip applies to its route, amount and recorded state, not future sellability.
- **Missing data stays meaningful.** Unsupported routes, RPC failures and unattributed sell reverts can remain UNKNOWN. Human interfaces may offer a proceed option, SDK callers must enforce the returned decision, and auxiliary tools do not all share the core scan's coverage semantics. There is no stock-issuer authenticity check. The RPC proxy sees only requests routed through it, forwards contract creation without analysis, and receives raw transactions after signing.
- **Freshness is publication age.** `maxAge` measures time since the registry transaction executed, not time since the underlying observation. Sustained satisfaction of a finite `maxAge` is possible only for actively watched subjects with timely successful publication. The watched set defaults to four; a subject recorded once eventually expires without another publication. The documented 600-second demo setting requires `GUARD_WATCH_MAX_SUBJECTS=1` watching exactly the transfer's immutable subject; the production minimum is 900 seconds for four subjects. Failures, UNKNOWN updates and delayed inclusion can still deny permission. See [watch conditions](guard-rescans.md).
- **The recorder is trusted.** Matching canonical evidence to an on-chain hash establishes the recorder's commitment to those bytes, not the accuracy of the scan. Guard permission deliberately accepts MEDIUM risk. It depends on the pinned registry and recorder, sequencer timestamps and the pinned USDG implementation; it does not authenticate an issuer or establish that a token is safe.
- **Exact credit has a recipient constraint.** The transfer rejects fee tokens and requires an EOA or passive recipient; forwarding funds in a recipient hook can fail its balance-delta check. The offline demonstration uses a mock ERC-20, not a live USDG payment.

## Reproducible verification

Start with [docs/JUDGE_GUIDE.md](JUDGE_GUIDE.md): replay the recorded honeypot and decision semantics offline, then run the registry/guard/transfer tests in Foundry. After the owner supplies deployment evidence, its read-only path compares the served canonical document with the designated registry's receipt event. Recorded RPC replay checks this implementation against saved responses; it is not archival EVM execution. The [test report](TESTING.md) states measured results, commands and exclusions.
