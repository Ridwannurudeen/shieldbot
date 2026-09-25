# ShieldBot — Arbitrum Open House Singapore submission draft

**DO NOT SUBMIT WITH ANY `OWNER_FILL_...` FIELD REMAINING. All three contract deployments are pending.**

Buildathon window: **September 14–October 4, 2026**, as supplied by the owner. The owner quotes the rules as allowing entrants to "bring an existing project or start from scratch"; the rules were not independently fetched during this local-only preparation. The history below distinguishes the existing product from work landed during that window.

## What was built and why

ShieldBot adds token-risk evidence and an explicit on-chain permission check for Robinhood Chain (**4663**). A token can accept a buy yet refuse a sell, while unavailable provider data can be mistaken for a clean result. The Robinhood implementation discovers launches, simulates supported buy/sell routes, preserves missing evidence as UNKNOWN, and stores canonical evidence documents for inspection.

Three contracts connect that evidence to an application action:

- [`ShieldBotVerdictRegistry`](../contracts/base/src/ShieldBotVerdictRegistry.sol) records an authorized recorder's verdict and the keccak256 hash of its evidence document. The owner can rotate the recorder through the registry's access controls.
- [`ShieldBotVerdictGuard`](../contracts/base/src/ShieldBotVerdictGuard.sol) reads an immutable registry and allows only recorded LOW or MEDIUM verdicts within the caller's positive publication-age limit. Missing, unknown, high-risk, honeypot, expired and future-dated records are denied.
- [`ShieldBotGuardedTransfer`](../contracts/base/src/ShieldBotGuardedTransfer.sol) pins the guard, subject, USDG token and recipient. It checks permission before transferring the caller's approved USDG and reverts unless the recipient's balance increases by exactly the requested amount. The subject being assessed need not itself be USDG.

The intended users are people inspecting Robinhood launches and applications that want to make a payment conditional on a recorded risk policy. The contract consumer adds enforcement for that specific payment path; advisory interfaces and other wallet transactions have different behavior. This is a working implementation and reproducible test path, not a claim of measured adoption or detection accuracy.

## Robinhood Chain observation census

From **2026-09-14T02:18:58Z** to **2026-09-22T17:19:08Z**, about 8.6 days, the standalone collector recorded **68,666 tokens** first appearing in observed liquidity pool creation events on Robinhood Chain, about 8,000 a day. These are first observed pool appearances, not token deployments or ShieldBot scans. V4 accounted for 57,142 and V2 for 11,674. V3 was not measured, and source counts can overlap.

Of 68,394 mature tokens, **19,668 (28.76%)** met the minimal bar of at least 10 Swap logs or at least 0.5 ETH-side liquidity within 1,800 seconds. Another 33,565, about 49%, were unknown because the evidence was insufficient. The report excluded 272 young tokens. The pass rate stayed between 26% and 32% across the threshold grid. Missing liquidity evidence is unknown, never zero. V4 liquidity is a reconstructed estimate, not executable exit liquidity.

Discovery latency across 106,914 pool events was p50 55.4 seconds and p90 138.2 seconds. The long tail includes historical replay and does not measure live detection lag. Doppler was the top identified launch stack with 21,727 tokens. Candidate contracts are not proven launchpads. Their counts overlap and must not be summed. See [the census method and limits](census-4663.md).

## Live usage evidence — measured September 22, 2026

The owner supplied this snapshot from **GET https://api.shieldbotsecurity.online/api/stats**, measured **2026-09-22**. The complete supplied block is reproduced verbatim; the endpoint is public and can be fetched again. No time of day was supplied, and these counters were not re-fetched or estimated during this local-only preparation.

```text
transactions_monitored : 496628
suspicious_approvals   : 2091
contracts_scanned      : 86
threats_detected       : 1
transactions_blocked   : 1
sandwiches_caught      : 0
chains_protected       : 7
```

This is a live product with real monitoring volume and a small number of completed contract scans: **496,628 transactions monitored**, **2,091 suspicious approvals**, **86 contracts scanned**, **1 threat detected**, **1 transaction blocked**, and **0 sandwiches caught**. These product-wide counters do not establish unique users, detection accuracy, Buildathon-only usage, Robinhood-only usage, or adoption of the undeployed guard.

**The `chains_protected: 7` counter is stale.** The owner's same-day production observation from **GET https://api.shieldbotsecurity.online/api/health** reports `supported_chains: [56,1,8453,42161,137,204,10,4663]`: eight configured chains including Robinhood. **GET https://api.shieldbotsecurity.online/api/launches/4663** returned **HTTP 200**. Availability of a route is not equal provider coverage across chains.

Revision **`27aca4d`** was deployed to production on **2026-09-23**. After deployment, a live Robinhood Chain scan returned `contract_age_days: 145`, `is_verified: true`, and `status: ok`. `/api/health` listed chain 4663.

**OWNER_FILL_EXTERNAL_FEEDBACK_STATUS** — Before submission, replace with either a dated, consented summary of an actual reply (distinguishing interest from an integration commitment), or: **"As of the submission date, no reply has been received; external validation remains outstanding."** A lack of replies is an explicit outcome, not a reason to imply endorsement.

## Deployment evidence — owner must complete

**THE THREE VERDICT CONTRACTS ARE NOT DEPLOYED AS OF THIS DRAFT (2026-09-22).** The backend's live usage above does not establish their deployment. No live contract verification or live guarded USDG payment is claimed. Complete every field below from the actual chain-4663 deployment and completed source-verification results. A submitted explorer verification request is not a completed result.

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

**Deployment verifier is ready for deploy day.** The owner dry-ran [`scripts/verify_deployment.py`](../scripts/verify_deployment.py) against live 4663 on **2026-09-22**. It correctly reported `PASS RPC chain id: 4663`, correctly detected no code at undeployed addresses, correctly matched USDG to the Paxos proxy used by the simulation, and exited non-zero with `SUMMARY: FAIL (2 passed, 11 failed)`. These are the owner's measured results, not a live run repeated here. The expected failures expose missing deployments; they are not a successful deployment check. The repository also contains [mocked RPC verifier tests](../tests/test_verify_deployment.py).

## What was produced during the Buildathon

ShieldBot existed before September 14. The pre-window revision `c1d1adf` already contains the risk engine, REST API, Telegram bot, browser extension, Python and TypeScript SDKs, MCP server and an attestor contract. Those foundations are not claimed as new Buildathon work.

The local `main` history through **`27aca4d`** contains these **eleven in-window commits**, all on its first-parent history. Dates below come from git history; the descriptions also reflect the changed files and current implementation. The commits labeled PRs #10 to #12 each have one parent, and the in-window merge-only log is empty: the work landed in the main history without separate two-parent merge commits. The preceding `c1d1adf` is the September 13 merge of PR #9.

| Date (2026) | Commit | Work landed during the window |
|---|---|---|
| September 17 | `a60fc45` | Robinhood Chain routing and adapter; explicit unknown provider coverage through the engine and consumer paths; explorer enrichment; chain census tooling and regression tests. |
| September 19 | `00b3c81` | Robinhood `eth_simulateV1` buy/sell simulation, recorded route fixtures, launch discovery and hunter integration; durable API quotas and hardening of incomplete-data and sell-failure classification. |
| September 20 | `9ca9c31` | Verdict registry and deployment tooling; canonical evidence, persistent history and optional publisher; public launch feed, MCP launch access, opt-in Telegram alerts and shared RPC budgeting; Doppler USDG simulation and its recorded fixture. |
| September 22 | `04203be` | Verdict guard and exact-credit guarded USDG transfer, wiring assertions and Foundry tests; observation provenance, refresh publication and bounded guard-subject rescans; extension chain-identification source fix; revised coverage disclosures and reproducible judge guide. |
| September 22 | `3a5bc0e` | Removed a stale hardcoded deployment address; setup scripts require `VPS_IP`; deployment-address regression tests and DNS instructions. |
| September 22 | `98c2d4e` | Read-only deployment verifier, mocked RPC tests and runbook instructions. |
| September 22 | `0a0276c` | Initial factual submission package with deployment placeholders and coverage boundaries. |
| September 22 | `5673c7c` | Two test-only CI fixes in the guard Foundry test and Python guard-admin test; no production implementation change in this commit. |
| September 22 | `18b87c7` | Failed token identification no longer skips honeypot and market checks or allows a SAFE result. |
| September 22 | `c452b72` | Transaction-specific SDK cache keys, a 60 second default cache lifetime, and no cached score for STRICT policy. |
| September 23 | `27aca4d` | A genuinely failed Robinhood pool simulation now leaves the combined result incomplete. |

Reproduce the history boundary from the repository root:

```bash
git log --since=2026-09-14 --until=2026-10-05 --oneline
git log 27aca4d --first-parent --since=2026-09-14 --until=2026-10-05 --format='%h %cI %p %s'
git log 27aca4d --merges --since=2026-09-14 --until=2026-10-05 --oneline
git show --stat a60fc45 00b3c81 9ca9c31 04203be 3a5bc0e 98c2d4e 0a0276c 5673c7c 18b87c7 c452b72 27aca4d
git diff --name-only 04203be 27aca4d
```

In particular, waves 2 to 3 (`9ca9c31`) and the guard, guarded transfer and freshness chain (`04203be`) both landed inside the window. The former `chore/oh-final` work is included in `main` through the later commits above. This submission update is documentation work on `docs/oh-submission`, based on `main` at `27aca4d`. It does not establish deployment of the three verdict contracts or a released extension.

## Pre-submission review

A pre-submission review found three fail-closed gaps in the Python pipeline. Commit `18b87c7` made token-identification failures continue through honeypot and market checks instead of allowing a SAFE result. Commit `c452b72` bound SDK cache keys to the sender, target, chain, full calldata and value, reduced the default cache lifetime to 60 seconds, and stopped STRICT policy from using a cached score. Commit `27aca4d` made a genuinely failed Robinhood pool simulation leave the combined result incomplete. All three fixes were tested and deployed on **2026-09-23**. The same review examined the three contracts and found no issue.

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
- **Blockscout key is a coverage dependency.** Without a configured `BLOCKSCOUT_API_KEY`, otherwise clean 4663 tokens render UNKNOWN because required contract-age evidence is unavailable; a successful sell simulation alone does not make the overall scan complete. A simulation-proven honeypot can still remain HONEYPOT. `BLOCKSCOUT_API_KEY` was configured in production on **2026-09-22**. A live Robinhood Chain scan on **2026-09-23** returned `contract_age_days: 145`, `is_verified: true`, and `status: ok`. See [explorer coverage](../services/explorer_service.py) and [unknown-coverage tests](../tests/test_provider_unknowns.py).
- **Freshness is publication age.** `maxAge` measures time since the registry transaction executed, not time since the underlying observation. Sustained satisfaction of a finite `maxAge` is possible only for actively watched subjects with timely successful publication. The watched set defaults to four; a subject recorded once eventually expires without another publication. The documented 600-second demo setting requires `GUARD_WATCH_MAX_SUBJECTS=1` watching exactly the transfer's immutable subject; the production minimum is 900 seconds for four subjects. Failures, UNKNOWN updates and delayed inclusion can still deny permission. See [watch conditions](guard-rescans.md).
- **The recorder is trusted.** Matching canonical evidence to an on-chain hash establishes the recorder's commitment to those bytes, not the accuracy of the scan. Guard permission deliberately accepts MEDIUM risk. It depends on the pinned registry and recorder, sequencer timestamps and the pinned USDG implementation; it does not authenticate an issuer or establish that a token is safe.
- **Exact credit has a recipient constraint.** The transfer rejects any transfer where the recipient does not receive exactly `amount`. This covers tokens that deduct a fee from the recipient's credit. A token that debits the sender by more than `amount` while crediting the recipient exactly `amount` would pass this check. The recipient must be an EOA or passive contract; forwarding funds in a recipient hook can fail the balance-delta check. A Robinhood Chain simulation transferred 500,000 units of Paxos USDG and credited the recipient exactly 500,000 units. The offline contract demonstration uses a mock ERC-20, not a live USDG payment.

## Reproducible verification

Start with [docs/JUDGE_GUIDE.md](JUDGE_GUIDE.md): replay the recorded honeypot and decision semantics offline, then run the registry/guard/transfer tests in Foundry. After the owner supplies deployment evidence, its read-only path compares the served canonical document with the designated registry's receipt event. Recorded RPC replay checks this implementation against saved responses; it is not archival EVM execution. The [test report](TESTING.md) states measured results, commands and exclusions.

Verified on **2026-09-23** at `main` revision **`27aca4d`**: the main suite completed with **3,054 passed, 1 skipped**, excluding the bot app suite. The Python SDK completed with **32 passed**. The TypeScript SDK completed with **21 passed**. CI run **35863129734** passed Foundry tests, Solidity security, Python tests and security, and the SDK audit and build. Tests do not establish live usage or contract deployment.

## Owner completion checklist: 16 distinct placeholders

There are **15 deployment-evidence fields** (3 contract addresses, 3 deployment transaction hashes, 9 explorer/source-verification links) and **1 status field** below. Each identifier appears once in the body and once in this checklist: **32 concrete placeholder occurrences**. Fill both occurrences together. No contract address, deployment transaction hash or explorer evidence URL has been invented. The judge guide has its own additional online-evidence fields; those are outside this document's count.

- [ ] **OWNER_FILL_REGISTRY_ADDRESS**
- [ ] **OWNER_FILL_REGISTRY_DEPLOY_TX_HASH**
- [ ] **OWNER_FILL_GUARD_ADDRESS**
- [ ] **OWNER_FILL_GUARD_DEPLOY_TX_HASH**
- [ ] **OWNER_FILL_TRANSFER_ADDRESS**
- [ ] **OWNER_FILL_TRANSFER_DEPLOY_TX_HASH**
- [ ] **OWNER_FILL_REGISTRY_ETHERSCAN_VERIFICATION_LINK**
- [ ] **OWNER_FILL_REGISTRY_BLOCKSCOUT_VERIFICATION_LINK**
- [ ] **OWNER_FILL_REGISTRY_SOURCIFY_VERIFICATION_LINK**
- [ ] **OWNER_FILL_GUARD_ETHERSCAN_VERIFICATION_LINK**
- [ ] **OWNER_FILL_GUARD_BLOCKSCOUT_VERIFICATION_LINK**
- [ ] **OWNER_FILL_GUARD_SOURCIFY_VERIFICATION_LINK**
- [ ] **OWNER_FILL_TRANSFER_ETHERSCAN_VERIFICATION_LINK**
- [ ] **OWNER_FILL_TRANSFER_BLOCKSCOUT_VERIFICATION_LINK**
- [ ] **OWNER_FILL_TRANSFER_SOURCIFY_VERIFICATION_LINK**
- [x] `BLOCKSCOUT_API_KEY` configured in production on 2026-09-22 and verified by a live scan on 2026-09-23.
- [ ] **OWNER_FILL_EXTERNAL_FEEDBACK_STATUS**
