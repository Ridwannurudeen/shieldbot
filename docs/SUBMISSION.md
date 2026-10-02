# ShieldBot — Arbitrum Open House Singapore submission

The three contracts were deployed on Robinhood Chain (4663) on 2026-09-27; see [Deployment evidence](#deployment-evidence).

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

The owner supplied this snapshot from **GET https://api.shieldbotsecurity.online/api/stats**, measured **2026-09-22**. The complete supplied block is reproduced verbatim. No time of day was supplied. The endpoint is public, but several of its counters no longer measure what they measured on that date, so these figures cannot be reproduced from it: see the correction below.

```text
transactions_monitored : 496628
suspicious_approvals   : 2091
contracts_scanned      : 86
threats_detected       : 1
transactions_blocked   : 1
sandwiches_caught      : 0
chains_protected       : 7
```

The contract counters (**86 contracts scanned**, **1 threat detected**, **1 transaction blocked**) come from the database; on 2026-09-26, after the deployment below, they read 87, 1 and 1 (`threats_detected` under the definition given in the correction below). The mempool counters (transactions monitored, suspicious approvals, sandwiches caught) are superseded by the correction below and are not cited as evidence. None of these counters establish unique users, detection accuracy, Buildathon-only usage, Robinhood-only usage, or adoption of the undeployed guard.

**The `chains_protected: 7` counter is stale.** The owner's same-day production observation from **GET https://api.shieldbotsecurity.online/api/health** reports `supported_chains: [56,1,8453,42161,137,204,10,4663]`: eight configured chains including Robinhood. **GET https://api.shieldbotsecurity.online/api/launches/4663** returned **HTTP 200**. Availability of a route is not equal provider coverage across chains.

Revision **`27aca4d`** was deployed to production on **2026-09-23**. After deployment, a live Robinhood Chain scan returned `contract_age_days: 145`, `is_verified: true`, and `status: ok`. `/api/health` listed chain 4663.

Production has since moved on: it runs **`5ac17f1`**, deployed on **2026-09-26**. After that deployment, `/api/health` listed the same eight chains and `/api/ready` answered 200 to ten requests over about 18 seconds. A live Robinhood Chain scan of USDG (`0x5fc5360d0400a0fd4f2af552add042d716f1d168`) returned `contract_age_days: 144`, `is_verified: true`, and `status: ok`; the September 23 scan above was of a token this document does not name. BNB Chain scans of CAKE and USDT returned `status: ok` with contract ages of 2,195 and 2,213 days. Before this deployment both came back UNKNOWN, because Etherscan refuses creation lookups on BNB Chain for the configured key; BNB Chain ages now come from Sourcify's deployment record when Etherscan refuses and Sourcify has verified the contract, and otherwise stay UNKNOWN. An Ethereum USDC scan returned `status: ok`.

On **2026-09-27** production moved to **`c9ae9c9`**, which wired in the verdict registry below. It records the Robinhood Chain verdicts of Telegram scans, guard rescans, and launches or rechecks that are blocked or guard-watched; with `PUBLISH_LAUNCH_VERDICTS_ONCHAIN=0` it stores other launch verdicts as `off`, which is not on-chain evidence.

On **2026-09-28** production moved to **`dc9f015`**, which keeps that wiring and adds protocol recognition. Uniswap's current routers and position managers are recognised on every supported chain, so an unlimited Permit2 permit for one of them is named and scored as a known protocol instead of raising CAUTION. A trusted router's swap is judged by its tokens only when every command it runs is one ShieldBot checks and pays the sender; otherwise it answers CAUTION and names where the funds go. After that deployment `/api/health` listed the same eight chains.

On **2026-09-29** production moved to **`ca5e395`**, which adds ShieldBot's own sell simulation on Arbitrum One (42161). honeypot.is does not serve Arbitrum One and GoPlus reports no buy or sell tax for new tokens there, so before this deployment every entry of a 66-entry Arbitrum One benchmark ended UNKNOWN. ShieldBot now simulates a buy and a sell over `eth_simulateV1` in the pools pairing the token with WETH on Uniswap V3, Uniswap V2 and SushiSwap, under the same rules as on Robinhood Chain: a token is a honeypot only on evidence attributable to it. When the pool holding the most WETH sells at a tax of 50% or less but another pool refuses the sell, the result is UNKNOWN. A token with no WETH pair on those three exchanges gets no simulation, and its sellability rests on GoPlus as before. Wallet approval history on Arbitrum One is now read over about 35 days instead of under 18 hours. After that deployment `/api/health` listed the same eight chains and `/api/ready` answered 200 five times. `/api/firewall` answered an approval of ARB (`0x912ce59144191c1204e64559fe8253a0e49e6548`) to Uniswap's SwapRouter02 with SAFE, risk 6.4 and `status: ok`, every coverage category complete. It answered ARBROKER (`0x8328ffdecbd36294b4fcc50c1c25cde18f4a8b2b`) with BLOCK_RECOMMENDED, risk 80 and "Honeypot detected": a holder's sell makes the token forward its ETH to a tax wallet that refuses ETH, so the sell reverts, while GoPlus reported it on 2026-09-29 as not a honeypot.

Later on **2026-09-29** production moved to **`6371cb5`**, which fixes a database fault. From about 22:25 UTC on 2026-09-28 until a restart at 13:06 UTC on 2026-09-29, Robinhood Chain launch discovery stopped: one write on the API's shared SQLite connection failed on a lock and left its transaction open, and every later write on that connection failed until the restart. Discovery then caught up, so launches from that window were found late rather than missed; on-chain verdict recording from scans in that window may be incomplete, because those writes failed. Each write on that connection now commits on its own, the verdict sender's writes roll back when they fail, and the operator gets a Telegram alert when the launch watch fails 15 cycles in a row. After that deployment `/api/health` listed the same eight chains, launch discovery was current, and `/api/ready` answered 200 six times in a row, a minute after three 503 answers.

On **2026-09-30** production moved to **`bdf4cff`**. It closes two ways a token could read SAFE when ShieldBot's own sell simulation, on Robinhood Chain or Arbitrum One, had not settled it. When the simulation could not run at all because the RPC answered with an error, every trade field was left empty and a complete, clean GoPlus answer filled them, so the scan could read SAFE. It now stays UNKNOWN, and the Telegram report and the extension's side panel show the honeypot check as Unknown instead of "Not Honeypot" or "No". A pool lookup the RPC could not answer used to count as "no pool", which also left the token to GoPlus; it now leaves the scan UNKNOWN too. A request the RPC answers with an error of its own is sent once more, so one transient error does not leave a healthy token UNKNOWN. On Arbitrum One, the rule above held in the simulator, but when the pool holding the most WETH sold and another pool refused the sell, a clean GoPlus answer could still fill the sellability it left open and make the token SAFE. That case is now marked as a simulation that could not settle the token, so it stays UNKNOWN. GoPlus reported ARBROKER as not a honeypot, which is why its answer must not settle a token the simulation left open. The side panel change reaches users only with the next extension release. After that deployment `/api/health` listed the same eight chains and launch discovery was current. `/api/firewall` answered the same ARB approval with SAFE, risk 6.4 and `status: ok`. It answered ARBROKER with BLOCK_RECOMMENDED and risk 80, a honeypot that cannot be sold according to ShieldBot's own simulation; its status reads UNKNOWN because DexScreener lists no Arbitrum One pair for it and the reverted sell leaves its sell tax unmeasured.

On **2026-10-01** production moved to **`622b944`**. `/api/scan` is a quick contract check that simulates no sell, so for a contract ShieldBot recognises as a token it now answers UNKNOWN instead of a possible SAFE, with the reason that `/api/firewall` runs the full token check. Scan results quoted above that came from `/api/scan` were taken before this change. `/api/firewall` and the Telegram bot are unchanged. The landing page now says the three Robinhood Chain contracts were deployed on 27 September 2026, and `urllib3` moved to 2.8.0 for three published advisories. After that deployment `/api/health` listed the same eight chains and launch discovery was current. `/api/scan` answered ARB on Arbitrum One with CAUTION and `status: unknown`, and `/api/firewall` answered the same ARB approval with SAFE, risk 6.4 and `status: ok`.

On **2026-10-02** production moved to **`73836a4`**. It changes the landing site only: a light redesign with self-hosted fonts, a hero demo that plays recorded verdict examples, and a section on the Robinhood Chain registry and guard that says which verdicts are recorded on-chain (Telegram scans, guard rescans, and launches that are blocked or guard-watched). The API, the Telegram bot and the contracts are unchanged; outside the site and the documentation, the only changed file is the site's claims test. After that deployment `/api/health` listed the same eight chains, launch discovery was 0 blocks behind, and the landing page served the new build.

Production now runs **`af9b975`**, deployed later on **2026-10-02**. A pasted address, or `/scan` or `/token` with no chain prefix, now asks which chain the address is on and offers one button per supported chain; a prefix such as `rh:` still scans at once, and every report names the chain it covers, as `Chain: <name> (<id>)`. Before this a bare paste used the chain last saved for that chat, which defaults to BNB Chain, so a Robinhood Chain token could come back as a BNB Chain report. The API, the contracts and the landing site are unchanged. The cutover took a database backup and recorded `73836a4` as its rollback point. After that deployment `/api/health` listed the same eight chains, both units stayed active with no restarts, launch discovery caught up to 0 blocks behind, the WOOD and VIRTUAL verdicts still read LOW and confirmed, and the landing page, its documents and the dashboard all answered 200.

**Correction, 2026-09-26.** Changes made after the September 22 snapshot, and faults found in the code that produced it, mean some of its counters must not be read as first presented:

- In the code that served the snapshot, unchanged in this respect through `27aca4d`, the mempool counters were held in memory and restarted with the API process, so 496,628 was a count since the process had last started, not an all-time total. It also counted a transaction again each time it stayed in the pool for more than 60 seconds, because the pending set was pruned by age and refilled from the pool on every poll; commit `048d820` (2026-09-26) keys the set by pool membership instead. Commit `1a74293`, in production since the later 2026-09-23 deployment of `e820c2e`, added `mempool_counting_since`, the moment the current count began, and made a source that is not running in the API process report `null`. The 496,628 figure has no current equivalent.
- Since the **2026-09-26** deployments, `chains_protected` (merge `2f81d0b`) counts only the chains whose public mempool is currently observable (4 on 2026-09-26: Ethereum, BNB Chain, Polygon and opBNB), so it is not comparable with the 7 above. `threats_detected` (merge `7c0e144`) now counts the contracts whose stored risk level is HIGH, where it counted scores of 71 or more.
- In the code that served the snapshot, the approval counter added one for every pending unlimited or very large `approve()`, whoever the spender was, so ordinary approvals to DEX routers were counted, and a pending approval was counted again each time it was re-read after 60 seconds. Since commit `66e617b` (2026-09-26, in production the same day) the monitor alerts only when the spender is already known to be bad: an admin blacklist entry, a GoPlus theft label, or a wallet rather than a contract. The 2,091 figure is therefore a count of large pending approvals, repeats included, not of approvals whose spender was known to be an attacker.

## External validation

**As of 2026-09-28**, from the owner's message records: on 2026-09-17 the ecosystem team of an EVM layer-1 chain contacted ShieldBot, unprompted, about bringing its wallet scan and approval management to their chain. On 2026-09-24 they agreed to a private demonstration of approval management: a Telegram-triggered wallet scan, the approvals it finds, and a revoke the user signs in their own wallet. They offered test wallets, test gas and RPC details for it. This is interest in a demonstration, not an integration commitment: no agreement has been signed, no payment has been made, and the demonstration has not taken place yet. The team is not named because it has not agreed to be named in this document.

## Deployment evidence

The three contracts were deployed on Robinhood Chain (4663) on **2026-09-27** from `0x8d02b6ECffed8A3e1e5C3649AA4670c72C366ae4`, the registry's owner, built from `main` at `c9ae9c9`; the contract sources are unchanged since `04203be`. The registry's recorder is `0xc68a90dcdfE8FBf770a7f29904B928cA6D00F453`. The transfer's subject is VIRTUAL (`0xc6911796042b15d7Fa4F6CDe69e245DdCd3d9c31`), its token is Paxos USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`) and its recipient is the owner. No live guarded USDG payment is claimed.

| Contract | Deployed address | Deployment transaction hash |
|---|---|---|
| ShieldBotVerdictRegistry | [`0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138`](https://robin.etherscan.io/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138) | [`0x14275435a6f9cff13681b15b230f69c7c40579a4e308a7cc503d25ff1b731fef`](https://robin.etherscan.io/tx/0x14275435a6f9cff13681b15b230f69c7c40579a4e308a7cc503d25ff1b731fef) |
| ShieldBotVerdictGuard | [`0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e`](https://robin.etherscan.io/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e) | [`0xad4ada88dc23df69351ecd378dcab7033aaec71fd3edca711b9c05962b9565b3`](https://robin.etherscan.io/tx/0xad4ada88dc23df69351ecd378dcab7033aaec71fd3edca711b9c05962b9565b3) |
| ShieldBotGuardedTransfer | [`0x336254bA85406D9af39357101b688E2B757751b3`](https://robin.etherscan.io/address/0x336254bA85406D9af39357101b688E2B757751b3) | [`0x7ee90d6204f182526870c0323e131b87dd7ad5e15ffafcffaeb1c2f0748e26f7`](https://robin.etherscan.io/tx/0x7ee90d6204f182526870c0323e131b87dd7ad5e15ffafcffaeb1c2f0748e26f7) |

| Contract | Etherscan verified source link | Blockscout verified source link | Sourcify match link |
|---|---|---|---|
| ShieldBotVerdictRegistry | [verified source](https://robin.etherscan.io/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138#code) | [verified source](https://robinhoodchain.blockscout.com/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138?tab=contract) | [exact match](https://sourcify.dev/server/v2/contract/4663/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138) |
| ShieldBotVerdictGuard | [verified source](https://robin.etherscan.io/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e#code) | [verified source](https://robinhoodchain.blockscout.com/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e?tab=contract) | [exact match](https://sourcify.dev/server/v2/contract/4663/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e) |
| ShieldBotGuardedTransfer | [verified source](https://robin.etherscan.io/address/0x336254bA85406D9af39357101b688E2B757751b3#code) | [verified source](https://robinhoodchain.blockscout.com/address/0x336254bA85406D9af39357101b688E2B757751b3?tab=contract) | [exact match](https://sourcify.dev/server/v2/contract/4663/0x336254bA85406D9af39357101b688E2B757751b3) |

Sourcify holds full exact matches (creation and runtime code) for all three. Blockscout shows each contract through its Sourcify lookup; a first page load can show "Verify & publish" before that match appears.

The [judge guide](JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api) checks a published verdict against these contracts without trusting the API; the [deployment runbook](../contracts/base/DEPLOY_ROBINHOOD.md) has the steps that were followed. With `ROBINHOOD_VERDICT_REGISTRY` unset, evidence is still stored and served, but publication is off; an `off` result is not on-chain evidence. With `PUBLISH_LAUNCH_VERDICTS_ONCHAIN=0`, the hunter's launch and recheck verdicts are likewise stored and served as `off` unless blocked or watched by the guard, while guard rescans and Telegram scans are recorded.

**Deployment verifier: PASS.** On **2026-09-27**, [`scripts/verify_deployment.py`](../scripts/verify_deployment.py) run against the live contracts with `--max-age 900` reported `SUMMARY: PASS (13 passed, 0 failed)`, including `guard.check(subject, maxAge): allowed=True, reason=0` for VIRTUAL. The guard watch refreshes that subject's record (`GUARD_WATCH_MAX_SUBJECTS=1`, one record about every 350 seconds); a later run can deny if refreshes fail. The repository also contains [mocked RPC verifier tests](../tests/test_verify_deployment.py).

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

After `27aca4d`, `main` gained **102 further first-parent commits**, authored from September 22 to September 26 and all inside the window, through `5ac17f1`, the revision in production on 2026-09-26. Most are platform work across all supported chains rather than Robinhood-specific features; the rest are documentation and site changes:

- **September 23 to 24:** audit-driven fixes. Unmeasured scan fields report UNKNOWN instead of clean; one verdict vocabulary and a scoring redesign with declared floors; a coverage endpoint and an Unknown ledger; provider circuit breakers, a readiness endpoint and a gated deploy script with rollback; server-judged signatures and hardening of the repository extension (manifest 3.1.0, not released); SDK and MCP validation fixes; transactional database writes; an evidence document per scan.
- **September 25:** repository and documentation cleanup; the site and docs present ShieldBot as a multichain product.
- **September 26:** mempool monitor fixes (API stalls from oversized txpool reads, evidence-only approval alerts, directional sandwich detection); a deadline on Wallet Health scans that reports the unread block range as partial coverage; the BNB Chain verifier and Base attestor writers retired; BNB Chain contract ages dated from Sourcify when Etherscan refuses.

Reproduce the history boundary from the repository root:

```bash
git log --since=2026-09-14 --until=2026-10-05 --oneline
git log 27aca4d --first-parent --since=2026-09-14 --until=2026-10-05 --format='%h %cI %p %s'
git log 27aca4d --merges --since=2026-09-14 --until=2026-10-05 --oneline
git show --stat a60fc45 00b3c81 9ca9c31 04203be 3a5bc0e 98c2d4e 0a0276c 5673c7c 18b87c7 c452b72 27aca4d
git diff --name-only 04203be 27aca4d
git log 27aca4d..5ac17f1 --first-parent --format='%h %ad %s' --date=short
git log 27aca4d..5ac17f1 --first-parent --merges --oneline
```

In particular, waves 2 to 3 (`9ca9c31`) and the guard, guarded transfer and freshness chain (`04203be`) both landed inside the window. The former `chore/oh-final` work is included in `main` through the later commits above. This history was last brought up to date on 2026-09-26 against `main` at `5ac17f1`, and the deployment section on 2026-10-02 against `af9b975`. It does not establish a released extension.

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

Start with [docs/JUDGE_GUIDE.md](JUDGE_GUIDE.md): replay the recorded honeypot and decision semantics offline, then run the registry/guard/transfer tests in Foundry. Its read-only online path (section 3) compares the served canonical document with the designated registry's receipt event. Recorded RPC replay checks this implementation against saved responses; it is not archival EVM execution. The [test report](TESTING.md) states measured results, commands and exclusions.

Verified on **2026-09-23** at `main` revision **`27aca4d`**: the main suite completed with **3,054 passed, 1 skipped**, excluding the bot app suite. The Python SDK completed with **32 passed**. The TypeScript SDK completed with **21 passed**. CI run **35863129734** passed Foundry tests, Solidity security, Python tests and security, and the SDK audit and build. Tests do not establish live usage or contract deployment.

Re-verified on **2026-09-26** at **`5ac17f1`**: `python -m pytest -q -p no:cacheprovider --ignore=tests/test_import_order.py --ignore=tests/test_integration_imports.py` completed with **5,942 passed**, and the two excluded fresh-process import test files, `tests/test_import_order.py` and `tests/test_integration_imports.py`, with **112 passed**. CI run **36266495465** passed all four jobs. The SDK suites were not re-run locally for this update.

Re-verified on **2026-09-27** at **`c9ae9c9`**: the same two commands completed with **5,986 passed** and **113 passed**, and CI run **36345012629** passed all four jobs.

Re-verified on **2026-09-28** at **`dc9f015`**: the same two commands completed with **6,131 passed, 1 failed** and **113 passed**. The failure is a timing test of the rescue scan's deadline, `tests/test_rescue_scan_deadline.py`, which this change did not touch; run alone it failed once and then passed five times in a row. CI run **36480532540** passed all four jobs.

Re-verified on **2026-09-29** at **`ca5e395`**: the same two commands completed with **6,174 passed, 1 failed** and **114 passed**. The failure is the same rescue-scan deadline timing test. It scans BNB Chain, whose approval-history reads this change leaves as they were; run alone it passed four times out of five. CI run **36570678894** passed all four jobs.

Re-verified on **2026-09-29** at **`6371cb5`**: the same two commands completed with **6,186 passed, 1 failed** and **114 passed**. The failure is the same rescue-scan deadline timing test, which uses no database. CI run **36611937857** passed all four jobs.

Re-verified on **2026-09-30** on the exact tree of **`bdf4cff`**: the same two commands completed with **6,249 passed** and **114 passed**, with no failures. This revision fixes the rescue-scan deadline timing test, which then passed five runs in a row. CI run **36675143346** passed all four jobs.

Re-verified on **2026-10-01** at **`622b944`**: the same two commands completed with **6,270 passed** and **114 passed**, with no failures, and the dependency audit found no known vulnerabilities. CI run **36857074269** passed all four jobs.

Re-verified on **2026-10-01** at **`9e9b761`**, whose Python code is identical to `73836a4`'s: the same two commands completed with **6,275 passed, 1 failed** and **114 passed**. The failure is a timing test of the verdict sender's lease, `tests/test_verdict_sender_lease.py`, which this change did not touch; run alone, that file then passed 26 of 26 three times in a row. At `73836a4` the site's claims and dashboard tests completed with **65 passed**.

Re-verified on **2026-10-02** at **`af9b975`**: the same two commands completed with **6,355 passed** and **114 passed**, with no failures.

## Owner completion checklist: 17 items, all done

The **15 deployment-evidence fields** (3 contract addresses, 3 deployment transaction hashes, 9 explorer/source-verification links) were filled on 2026-09-27 and 2026-09-28 from the deployment receipts, the chain and the explorers. The external validation status was filled on 2026-09-28.

- [x] Registry address
- [x] Registry deployment transaction
- [x] Guard address
- [x] Guard deployment transaction
- [x] Transfer address
- [x] Transfer deployment transaction
- [x] Registry Etherscan link
- [x] Registry Blockscout link
- [x] Registry Sourcify link
- [x] Guard Etherscan link
- [x] Guard Blockscout link
- [x] Guard Sourcify link
- [x] Transfer Etherscan link
- [x] Transfer Blockscout link
- [x] Transfer Sourcify link
- [x] `BLOCKSCOUT_API_KEY` configured in production on 2026-09-22 and verified by a live scan on 2026-09-23.
- [x] External validation status
