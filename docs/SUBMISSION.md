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

**Demand surface: launchpads, routers and agents.** The owner's September 22 market investigation found that **no mainnet lender on 4663 accepts arbitrary collateral**: Morpho on 4663 is the Robinhood Earn back end with curated markets; anora lends against curated originators; `squeeze` is unbuilt; Nokturn is undeployed with a four-token allowlist. This is an owner-supplied finding, not an independent market survey performed in this documentation pass. The guard is aimed at launchpads, routers and agents; no existing arbitrary-collateral lending market or lender integration is claimed.

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

The owner reports deployed revision **`04203be`**; the locally verified `main` baseline is **`5673c7c`**. Git shows four intervening commits: setup changes (`3a5bc0e`), deployment-verifier tooling (`98c2d4e`), the submission draft (`0a0276c`), and two test-only fixes in `5673c7c`. The complete difference is therefore broader than those two test fixes. The production revision and endpoint observations are supplied evidence, not remote checks performed in this pass.

## External validation — sought, no reply received

As of **2026-09-22**, the owner reports outreach to prospective integrators in the categories **launchpads, routers and trading agents on 4663**. **No reply has been received.** No external endorsement, accepted integration or validated customer demand is claimed. Parties are not named without their consent; outreach is evidence of seeking feedback, not evidence that the product has been validated externally.

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

The local `main` history through **`5673c7c`** contains these **eight in-window commits**, all on its first-parent history. Dates below come from git history; the descriptions also reflect the changed files and current implementation. The commits labeled PRs #10–#12 each have one parent, and the in-window merge-only log is empty: the work landed in the main history without separate two-parent merge commits. The preceding `c1d1adf` is the September 13 merge of PR #9.

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

Reproduce the history boundary from the repository root:

```bash
git log --since=2026-09-14 --until=2026-10-05 --oneline
git log 5673c7c --first-parent --since=2026-09-14 --until=2026-10-05 --format='%h %cI %p %s'
git log 5673c7c --merges --since=2026-09-14 --until=2026-10-05 --oneline
git show --stat a60fc45 00b3c81 9ca9c31 04203be 3a5bc0e 98c2d4e 0a0276c 5673c7c
git diff --name-only 04203be 5673c7c
```

In particular, waves 2–3 (`9ca9c31`) and the guard, guarded transfer and freshness chain (`04203be`) both landed inside the window. The former `chore/oh-final` work is now included in `main` through the later commits above. This evidence update is documentation work on `docs/oh-evidence`, based on `5673c7c`; it does not establish a contract deployment or a released extension.

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
- **Blockscout key is a coverage dependency.** Without a configured `BLOCKSCOUT_API_KEY`, otherwise clean 4663 tokens render UNKNOWN because required contract-age evidence is unavailable; a successful sell simulation alone does not make the overall scan complete. A simulation-proven honeypot can still remain HONEYPOT. Production configuration: **OWNER_FILL_BLOCKSCOUT_API_KEY_STATUS** — owner must state **configured** or **not configured**, with a check date, without including the key itself. Configuration was not inspected in this local-only pass. See [explorer coverage](../services/explorer_service.py) and [unknown-coverage tests](../tests/test_provider_unknowns.py).
- **Freshness is publication age.** `maxAge` measures time since the registry transaction executed, not time since the underlying observation. Sustained satisfaction of a finite `maxAge` is possible only for actively watched subjects with timely successful publication. The watched set defaults to four; a subject recorded once eventually expires without another publication. The documented 600-second demo setting requires `GUARD_WATCH_MAX_SUBJECTS=1` watching exactly the transfer's immutable subject; the production minimum is 900 seconds for four subjects. Failures, UNKNOWN updates and delayed inclusion can still deny permission. See [watch conditions](guard-rescans.md).
- **The recorder is trusted.** Matching canonical evidence to an on-chain hash establishes the recorder's commitment to those bytes, not the accuracy of the scan. Guard permission deliberately accepts MEDIUM risk. It depends on the pinned registry and recorder, sequencer timestamps and the pinned USDG implementation; it does not authenticate an issuer or establish that a token is safe.
- **Exact credit has a recipient constraint.** The transfer rejects fee tokens and requires an EOA or passive recipient; forwarding funds in a recipient hook can fail its balance-delta check. The offline demonstration uses a mock ERC-20, not a live USDG payment.

## Reproducible verification

Start with [docs/JUDGE_GUIDE.md](JUDGE_GUIDE.md): replay the recorded honeypot and decision semantics offline, then run the registry/guard/transfer tests in Foundry. After the owner supplies deployment evidence, its read-only path compares the served canonical document with the designated registry's receipt event. Recorded RPC replay checks this implementation against saved responses; it is not archival EVM execution. The [test report](TESTING.md) states measured results, commands and exclusions.

For this documentation update on **2026-09-22**, based on `5673c7c`, the command `python -m pytest tests/ -q -p no:cacheprovider --ignore=tests/test_bot_app.py` completed with **2989 passed, 1 skipped, 4 warnings in 120.42s**. The excluded bot suite is not part of that passing count. Foundry was not run during this pass; the linked report's Foundry results are historical. Tests do not establish live usage or deployment.

## Owner completion checklist — 17 distinct placeholders

There are **15 deployment-evidence fields** (3 contract addresses, 3 deployment transaction hashes, 9 explorer/source-verification links) and **2 status fields** below. Each identifier appears once in the body and once in this checklist: **34 concrete placeholder occurrences**. Fill both occurrences together. No contract address, deployment transaction hash or explorer evidence URL has been invented. The judge guide has its own additional online-evidence fields; those are outside this document's count.

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
- [ ] **OWNER_FILL_BLOCKSCOUT_API_KEY_STATUS**
- [ ] **OWNER_FILL_EXTERNAL_FEEDBACK_STATUS**
