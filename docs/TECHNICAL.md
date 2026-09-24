# ShieldBot - Technical Documentation

Coverage and operational corrections below describe the current source tree. The original February 2026 diagrams and demo outputs are illustrative, not evidence of a deployed version or a complete scan.

## Architecture Overview

### System Design

ShieldBot follows a **3-tier architecture**:

```
┌─────────────────────────────────────────────────────────────────┐
│                        DELIVERY LAYER                            │
├─────────────────────────────────────────────────────────────────┤
│  • Chrome Extension (Manifest V3, EIP-6963)                      │
│  • Telegram Bot (python-telegram-bot 20.7)                       │
│  • FastAPI REST API (uvicorn, async endpoints)                   │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│                      INTELLIGENCE ENGINE                         │
├─────────────────────────────────────────────────────────────────┤
│  • RiskEngine: Composite weighted scoring (4 categories)         │
│  • AI Analyzer: LLM-powered forensic analysis                    │
│  • Calldata Decoder: Function signature + router detection       │
│  • Tenderly Simulator: Pre-execution transaction simulation      │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│                       DATA SERVICES LAYER                        │
├─────────────────────────────────────────────────────────────────┤
│  1. ContractService  → GoPlus + BscScan + Scam DBs               │
│  2. HoneypotService  → Honeypot.is simulation API                │
│  3. DexService       → DexScreener market data                   │
│  4. EthosService     → Ethos Network reputation                  │
│  5. TenderlyService  → Transaction simulation                    │
│  6. GreenfieldService → BNB Greenfield storage (SDK)             │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│                       BLOCKCHAIN LAYER                           │
├─────────────────────────────────────────────────────────────────┤
│  • BSC Mainnet (chain ID 56)                                     │
│  • opBNB Mainnet (chain ID 204)                                  │
│  • BNB Greenfield (decentralized storage)                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. Chrome Extension (Real-Time Firewall)

**Architecture**: Manifest V3 with isolated worlds

```javascript
// Extension Components
manifest.json       → Permissions, content_scripts, background service worker
inject.js           → Runs in "MAIN" world, wraps window.ethereum.request()
content.js          → Runs in "ISOLATED" world, renders overlays
background.js       → Service worker, API communication, modal injection
popup.html/js       → Extension popup UI (scan history, settings)
```

**Transaction Interception Flow**:

```
User clicks "Swap" on PancakeSwap
         ↓
dApp calls window.ethereum.request({method: 'eth_sendTransaction', params: [...]})
         ↓
inject.js (MAIN world) intercepts the call
         ↓
Sends transaction to background.js via window.postMessage
         ↓
background.js calls ShieldBot API: POST /api/firewall
         ↓
API returns verdict: {classification: "HIGH_RISK", risk_score: 85, ...}
         ↓
background.js injects modal:
  • HIGH_RISK → Red risk overlay (cancel/proceed)
  • MEDIUM_RISK → Orange warning overlay (proceed/cancel)
  LOW_RISK: Passthrough only with complete required scan coverage
  INCOMPLETE: Unknown warning; browser proceed override remains
         ↓
User action:
  • User chooses Block: Transaction rejected (never reaches wallet)
  • WARN + Cancel: Transaction rejected
  • WARN + Proceed: Transaction forwarded to wallet
  • ALLOW: Transaction forwarded to wallet immediately
```

**Key Technical Details**:
- **EIP-6963 Compatible**: Detects multiple wallet providers via `eip6963:announceProvider` events
- **Provider Wrapping**: Wraps discovered providers' `request()` methods; this is not a wallet-level guarantee against bypass.
- **Transaction Metadata**: The extension reads transaction requests for analysis, but does not access wallet private keys.
- **API Calls**: Transaction interception uses the background service worker; the side panel also calls the API directly.

**Release limitation:** The previously shipped extension does not resolve the active provider chain when a dApp omits `chainId`; that path defaults to BNB Chain (56). Its result is not evidence of protection on Robinhood Chain (4663) or another omitted chain. The chain-resolution repair on this branch is unreleased. Do not claim the Web Store build has that repair or multichain protection based on this branch. Validate the unpacked build with real wallets, chain switches and unavailable providers before a separately reviewed release.

### Coverage Contract and Remaining MCP Limitations

For scan responses, `core.extension_formatter.is_scan_incomplete` is the shared incompleteness check. An unknown or partial result is not a safety decision; an observed risk score is not proof that missing checks passed.

The MCP adapters have narrower coverage than their names may suggest:

- `check_approval_risk` and `query_threat_graph` are unimplemented adapters. They return `status: "unknown"`, coverage reasons and null result fields; they do not enumerate approvals or establish absence of cluster connections.
- `simulate_transaction` returns an `error` with null measurements when Tenderly is unavailable or simulation fails. When simulation produces a result, it returns `success`, `revert_reason`, `asset_changes`, `warnings` and `gas_estimate`; approval changes are not measured and remain null. Output is limited to fields reported by the simulation provider.
- `check_deployer` uses the local index. An unindexed contract returns `deployer: null`, null counts and `status: "unknown"`; a found deployer also stays `unknown`, because the index holds only contracts ShieldBot itself has scanned, so its counts are lower bounds.
- `check_agent_reputation` is a block-rate heuristic over at most 1,000 local firewall records. An unregistered agent, or a registered agent with no history, returns a null trust score and `status: "unknown"`; a history that reaches the 1,000-record cap also stays `unknown`, because its count is a lower bound.
- `scan_for_injection` checks a fixed regex list. `clean: true` means no listed pattern matched, not that arbitrary content is safe; the returned depth label does not add a deeper analysis pass.

These legacy MCP limits remain open. Consumers must not promote their empty lists, lower-bound counts or regex result into an authorization decision.

### Evidence Documents for API Verdicts

Every `/api/firewall` and `/api/scan` response carries `evidence_hash` and `evidence_url` (`core/scan_evidence.py`, `api.py` `_with_evidence`). The document uses the Robinhood Chain registry's canonical form: `canonical_bytes` (sorted keys, compact separators, UTF-8, no NaN) and `evidence_hash` = keccak256 of those bytes (`core/verdict_evidence.py`). It is ShieldBot's own record and is never recorded on a chain; its `schema` key (`shieldbot-scan-evidence`, `schema_version` 1) is absent from registry documents, so one can never be read as the other.

Fields: `endpoint`; `source` (`scan`, or `cache` with `cached_scan_at`); `chain_id`; `target` (lower case; for a signature request, the typed data's contract); `target_token` (name and symbol, when the scan resolved them); `classification`, `risk_score`, `risk_level` and `status` as the response gave them; `coverage`, `coverage_reasons` and `failed_sources`; `notes`, as the response gave them; `analyzers`, each analyzer's `status` (`ok`, `unknown`, `skipped` or `failed`), engine category `score`, `coverage`, `reason`, the coverage `fields` it declares (`answered` or `unknown`) and the `field_providers` it names (a router swap keys them `token:analyzer`). `failed` is recorded only for a whole analyzer (it raised or ran past the registry's deadline): the Unknown ledger counts provider outcomes for the whole process, not per scan, so a provider that failed and one that had no data both leave a field `unknown`, and `reason` says which; `policy_mode`; `observed_block` (the oldest block a sell simulation read, Robinhood Chain only, else null); `transaction`; `shieldbot_commit` (read from `.git` at startup, null when unreadable); and `scanned_at`, the time of the scan behind the verdict. A field the answering path does not report is null, never a default: the legacy fallback has no `risk_level`, `failed_sources` or `analyzers`, and `/api/scan` has no `analyzers`.

It never holds the caller's `from` address, IP address, API key or calldata. `transaction` is set only for a transaction-specific verdict (an approval, a claim, typed data or a call that pays): the decoded `function`, `calldata_keccak` (keccak256 of the calldata bytes), and for typed data `sign_method`, `typed_data_primary_type` and `typed_data_keccak` (keccak256 of its canonical JSON). Any mention of the caller's address is replaced with `[caller]`, whichever form the request gave it in (`0x`, `0X` or no prefix, any letter case).

A verdict served from `contract_scores` (the five-minute cache) gets a new document with `source: "cache"`, `analyzers: null` (the row keeps only scores and coverage), and both `cached_scan_at` and `scanned_at` set to the time of the scan that wrote the row. Every hit on one row whose request resolves the same target token therefore gives the same bytes, one hash and one stored document, whose `stored_at` is when it was first served. It does not reuse the original scan's document, because the cached answer is recomputed from the row: its classification (a simulation revert's BLOCK is not stored), policy mode and request can differ from what that document recorded.

The document is stored in `scan_evidence` under its hash before the response returns; if the store fails, `evidence_url` is null and the hash still names the verdict's document, and if the document cannot be serialised both are null. Neither failure withholds the verdict. `GET /api/evidence/{hash}` returns `canonical` (the string to hash), the parsed `evidence`, `stored_at`, `expires_at` and a `verify` note; `GET /evidence/{hash}` shows the same document as a page with no scripts under `default-src 'none'`, every value HTML-escaped and the canonical JSON printed for keccak256 verification. Both are public, rate-limited by IP like every route, and 404 for a hash never stored or already pruned. Documents are kept 90 days (`SCAN_EVIDENCE_RETENTION_DAYS`). One is about 1 to 2 KB.

Example (an unlimited `approve` on a covered token, from the test harness; the calldata hash is shortened here):

```json
{"analyzers":{"behavioral":{"coverage":1,"fields":{},"score":0,"status":"ok"},"honeypot":{"coverage":1.0,"field_providers":{"is_honeypot":"eth_simulateV1"},"fields":{},"score":0,"status":"ok"},"market":{"coverage":1,"fields":{},"score":0,"status":"ok"},"structural":{"coverage":1.0,"fields":{"contract_age_days":"answered","is_verified":"answered"},"score":0,"status":"ok"}},"cached_scan_at":null,"chain_id":56,"classification":"SAFE","coverage":{"behavioral":1,"honeypot":1.0,"market":1,"structural":1.0},"coverage_reasons":{},"endpoint":"/api/firewall","failed_sources":[],"observed_block":777,"policy_mode":"BALANCED","risk_level":"LOW","risk_score":0.0,"scanned_at":1790267750,"schema":"shieldbot-scan-evidence","schema_version":1,"shieldbot_commit":null,"source":"scan","status":"ok","target":"0xabababababababababababababababababababab","target_token":{"name":"TestToken","symbol":"TT"},"transaction":{"calldata_keccak":"0xa13e16d1...cb41d80f","function":"approve","sign_method":null,"typed_data_keccak":null,"typed_data_primary_type":null}}
```

The scan coverage contract does not cover all auxiliary browser features. The phishing check has two sources: a host on MetaMask's open phishing list ([eth-phishing-detect](https://github.com/MetaMask/eth-phishing-detect), fetched when the API starts and hourly after that, with the last good copy kept when a fetch fails) is reported as phishing with `source: "metamask"` and the matched list entry, whatever GoPlus says; the list's page-level entries (a host plus a path) are not used, because checks are cached per host. Only the API process loads the list, from its startup; the bot builds a phishing service too but never starts the list, so a check made there would be GoPlus-only (the bot runs no phishing checks today). When the list does not flag the host and GoPlus gives no answer (HTTP error, network error, malformed reply), it returns `is_phishing: null` with a `reason`, the server holds that for 45 seconds per domain, and the extension shows no banner; so a missing banner does not prove that a phishing check completed. The side-panel injection renderer defaults a missing score to zero and labels it "Safe", so that display does not prove an injection check completed either. Neither is fail-closed protection and must not be advertised as such.

The browser also retains user overrides: generic incomplete results, API errors and risk overlays offer "Proceed Anyway". The new chain-resolution path independently rejects unknown, mismatched or changed chains, but it does not remove those other overrides. Signature requests are analysed by the same `/api/firewall` endpoint (without the text of a message or the hash to sign), and a Block Recommended verdict needs Proceed held for 1.5 seconds in Balanced mode, and the popup wallet-health request is explicitly BNB-only (`chain_id=56`). Do not describe this extension as an unbypassable security boundary or claim that every incomplete check prevents signing.

---

### 2. Risk Engine (Composite Scoring)

**File**: `core/risk_engine.py`

**ShieldScore Computation** (historical scoring sketch, not the complete authorization path):

```python
# Category Weights
STRUCTURAL_WEIGHT = 0.40   # Contract verification, ownership, bytecode
MARKET_WEIGHT = 0.25       # Liquidity, volume, FDV
BEHAVIORAL_WEIGHT = 0.20   # Wallet reputation, scam flags
HONEYPOT_WEIGHT = 0.15     # Honeypot simulation, taxes

# Base Score
composite_score = (
    structural_score * 0.40 +
    market_score * 0.25 +
    behavioral_score * 0.20 +
    honeypot_score * 0.15
)

# Escalation Rules (override base score)
if honeypot_confirmed:
    composite_score = max(composite_score, 80)

if rug_pull_pattern:  # mint + proxy + owner not renounced
    composite_score = max(composite_score, 85)

if severe_reputation and new_pair:  # <24h pair + scam flags
    composite_score += 15

# Reduction Rules
if ownership_renounced and high_liquidity:  # >$100k liquidity
    composite_score -= 20

# Final Verdict
if composite_score >= 71:
    return "HIGH_RISK"  # Risk classification, not browser enforcement
elif composite_score >= 31:
    return "MEDIUM_RISK"  # Warning
else:
    return "LOW_RISK"  # Not authorization; coverage and policy checks still apply
```

**Structural Score Factors** (0-100):
- Contract verification status (BscScan)
- Bytecode patterns (mint, pause, blacklist, proxy)
- Ownership status (renounced vs. active owner)
- Contract age (days since deployment)
- Source code patterns (if verified)
- Top-10 holder concentration, tokens only (`top10_holder_percent`, from GoPlus's holder list): the share of supply its largest holders own, leaving out burn addresses, the chain adapter's known lockers, holders GoPlus marks locked, and the pairs and pool managers named in GoPlus's `dex` list for the token. A pool that list does not name (a Uniswap V4 pool it does not list, for example) counts as a holder and can inflate the share. 70% or more adds 10 points and 90% or more 20, with a flag. On GoPlus data of 2026-09-24, 17 of the 20 benchmark safes read 3-66% and cbETH 91.5% (bridge and staking contracts); 7 of the 14 benchmark honeypots read 71-100%. No safe changes class (`tests/test_benchmark_safe_scores.py`). A missing or unreadable list adds the note `Top-10 holder share unknown: no readable GoPlus holder list` and no score. A token GoPlus has no holder list for (most fresh launches) reads exactly as it did before the signal, apart from that note.
- The rule for signals like this one: a missing secondary, add-only signal is named in a note, not counted as a coverage gap. It only adds risk, so its absence cannot make a token read safer than without it. Status comes from the coverage fields the analyzers declare, and STRICT fails a verdict on the required coverage in `core/policy.py` (`REQUIRED_COVERAGE`).
- Notes are information, not danger signals. An analyzer declares them in `data['notes']`; the risk engine returns them in their own `notes` list and never in `critical_flags`. `/api/firewall` (a router swap names each note's path token) and `/api/scan` responses carry `notes` as their own field, outside `danger_signals` (`/api/scan`'s is always empty: its legacy scanner has no note-producing signal); a cached answer keeps the notes its row was scored with; evidence documents record them; the Telegram report lists them under "Notes" and MCP `scan_contract` returns them. The extension's transaction and signature overlays list them in their own "Notes" section, drawn as neutral information apart from the danger signals; they change nothing the overlay decides. Two notes exist: the missing holder list and "Volatility unknown: 24h price change unavailable". "Market data unknown" stays a flag, because it names a coverage gap.

**Market Score Factors** (0-100):
- Liquidity depth (DexScreener)
- Trading volume / liquidity ratio (wash trade detection)
- Pair age (new pairs = risky)
- FDV / 24h volume ratio
- Price volatility (>200% change = flag); skipped, and named in the note "Volatility unknown", when DexScreener omits the 24h change

**Behavioral Score Factors** (0-100):
- Wallet reputation (Ethos Network)
- Scam database matches (GoPlus Security, local blacklist)
- Historical abuse flags
- Community reports

**Honeypot Score Factors** (0-100):
- Honeypot.is simulation result
- Buy/sell tax differential (>50% sell tax = honeypot)
- Transfer restrictions
- Liquidity lock status (PinkLock, Unicrypt)

#### Feedback loops

The routes that feed these loops are open to anyone, so nothing they send can block a transaction on its own or change a threshold.

- **Outcomes** (`POST /api/outcome`): each row records who sent it in `outcome_events.source`, `key:<key_id>` for a valid API key or `client` otherwise (rows stored before the column existed are `client`). The decision must be `proceed`, `block` or `ignore`, the outcome `safe`, `scam` or `unknown`, the address must parse and a transaction hash must be 32 bytes of hex. Callers without a key are limited to 10 outcomes a minute per IP. No score reads these rows.
- **Local scam blacklist** (`scam_blacklist` table): three different reporters of the Telegram bot's `/report` on the same chain within 30 days put an address on it as a `community` entry for that chain, which expires after 30 days. A report is for the chain a `/scan` of the same text would check: its chain prefix (`eth:0x...`), else the reporter's current chain. A report of an address already listed changes nothing. A community entry is a medium-severity scam match: it raises a score to 40 (CAUTION) on every target type and does nothing else: no points above that, and unlike a scam database match it does not withhold the 20-point discount for renounced ownership and deep liquidity. It is shown as "Reported by N users", never counts as a scam database match, and on its own can never reach BLOCK. The AI prompts name it on its own line, "Community reports, unconfirmed, not a scam database match", not among the warnings. `/api/firewall`, `/api/scan` and the bot apply the same severity floors: a block-severity match (GoPlus labels the token a scam, or an admin confirmed the address) holds 90, any other scam database match 70, a community report alone 40. On `/api/firewall` and the router-swap path, a reverted simulation escalates a verdict to BLOCK only when the score before the community floor (`score_before_community_floor`, which both risk engine entry points return) is 30 or more, so community reports neither turn a routine revert (slippage, a deadline, an allowance) into a BLOCK nor keep a risky target's revert from one; the deployer campaign boost moves the verdict to the band of the boosted score (community 40 plus the largest boost, 25, is 65: HIGH_RISK). An admin can confirm an address, which makes it an `admin` entry that never expires and a block-severity match (floor 90), or remove any entry:

  ```bash
  # chainId omitted: the entry covers every chain
  curl -X POST https://api.shieldbotsecurity.online/api/admin/blacklist -H "X-Admin-Secret: $ADMIN_SECRET" \
       -H "Content-Type: application/json" -d '{"address": "0x...", "chainId": 56, "reason": "drainer"}'
  # chain_id omitted: removes the entry that covers every chain
  curl -X DELETE "https://api.shieldbotsecurity.online/api/admin/blacklist/0x...?chain_id=56" -H "X-Admin-Secret: $ADMIN_SECRET"
  ```

  Protected addresses (the BNB Chain routers, WBNB, BUSD and USDT) are refused everywhere and ignored if found in the table. The API and the bot load the unexpired entries at startup and reload them every 30 minutes: the API in its hunter sweep, which first deletes expired entries, and the bot on its own timer. A change made in one process can take up to 30 minutes to reach the other.

  Nothing on the blacklist is written on chain. A community blacklisting writes no record, and an admin confirmation is an off-chain full scam match only: the bot is the one process that sends from the BSC recorder and Base attestor wallets, and a second sender would collide with its nonces. Confirmed scams are not recorded on chain until the owner decides whether to retire those legacy writers.

  `POST /api/report` stores reports in `community_reports` and does not feed the blacklist. Those reports are anonymous web reports keyed by a hash of the client IP, and IPs are cheap to multiply, so they stay evidence for the admin to read, not a signal in scores.
- **Calibration**: the HIGH and MEDIUM thresholds, and a confidence boost, come from `core/calibration_config.json` (or `CALIBRATION_CONFIG_PATH`), read at startup. `scripts/calibrate.py` proposes new values from trusted labels only: benchmark entries with recorded scores (`--scores`, see `eval/README.md`) and outcome rows sent with an active paid API key (a key in `api_keys` that is active and whose tier is not `free`). It never reads `client` rows, rows from self-serve free keys, rows from deactivated keys or rows from keys no longer in `api_keys`. It reads the config the service reads (`calibration_config_path`, resolved against the repository root when relative, as the service runs from there) unless `--config` names another, and refuses an `--out` that is one of its inputs, so it never writes the config. With fewer than 20 trusted labels it proposes nothing. It never proposes a HIGH at or below 40 (three community reports alone would then be HIGH, which the RPC proxy blocks) or a MEDIUM at or below 30 (below the extension's CAUTION band): such a value is raised to 41 or 31, listed under `clamped` with the reason, and the proposal is marked `needs_owner_review`. It is also marked, with a line under `warnings`, when one key supplied more than half the trusted labels.

  ```bash
  cd /opt/shieldbot && venv/bin/python scripts/calibrate.py --db shieldbot.db --out /tmp/calibration-proposal.json \
      [--scores eval/data/live_scores.json]
  ```

  To apply a proposal, read it first: `warnings` and `labels.outcomes.by_source` show how many outcome rows each API key supplied, `bins` gives the safe and scam labels per 10-point score bin, and `metrics` gives the precision and recall of the current and proposed thresholds. If you accept it, copy `proposed.high_threshold`, `proposed.medium_threshold` and `proposed.confidence_boost` into the config file by hand, commit the change, deploy it and restart the API and the bot. A threshold change moves the LOW, MEDIUM and HIGH risk levels (the RPC proxy blocks on HIGH); the extension's CAUTION, HIGH_RISK and BLOCK bands (31, 50 and 71) are fixed.

---

### 3. Data Services (Parallel Intelligence)

The analyzer registry schedules applicable checks concurrently. The historical direct-call sketch below omits explicit chain routing; use `bot.py` and `core/registry.py` for the current path.

**Historical BNB-only sketch**:
```python
contract_data, honeypot_data, dex_data, ethos_data, token_info = await asyncio.gather(
    contract_service.fetch_contract_data(address),
    honeypot_service.fetch_honeypot_data(address),
    dex_service.fetch_token_market_data(address),
    ethos_service.fetch_wallet_reputation(address),
    web3_client.get_token_info(address),
)
# This sketch is not a latency measurement.
```

**Service Details**:

#### ContractService (`services/contract_service.py`)
- BscScan API: Contract verification, source code, deployment age
- Web3.py: Bytecode analysis, ownership checks
- Scam databases: GoPlus Security and the local blacklist
- Rate limiting: 0.25s delay between BscScan calls (free tier = 5 req/sec)

#### HoneypotService (`services/honeypot_service.py`)
- Honeypot.is API: Buy/sell simulation
- Tax extraction: Buy tax %, sell tax %
- Transfer simulation: Can buy? Can sell?
- Missing buy/sell fields remain null with explicit coverage reasons; an unresolved simulation cannot establish sellability (`services/honeypot_service.py`).

#### DexService (`services/dex_service.py`)
- DexScreener API: Token market data
- Metrics: Liquidity USD, 24h volume, FDV, pair age
- Anomaly detection: Volume > 10x liquidity (wash trading)
- Multi-pair aggregation: Sums volume only across the requested chain; missing volume on any selected pair leaves the total unknown

#### EthosService (`services/ethos_service.py`)
- Ethos Network API: Wallet reputation scoring
- Scam flags, abuse history, community reviews
- Reputation score: normalized to 0-100; higher is more reputable. A missing profile receives a neutral default, which is not proof of trust.

#### TenderlyService (`services/tenderly_service.py`)
- Optional Tenderly Simulation API: reports success/revert, gas usage and parsed asset deltas when configured and available
- Warns about reported failed subcalls and more than 50 state changes. The latter is a heuristic, not proof of reentrancy; there is no excessive-gas detector in this service.

#### GreenfieldService (`services/greenfield_service.py`)
- Optional BNB Greenfield SDK: creates an object record on-chain and uploads JSON bytes to a storage provider
- The firewall attempts an upload only when the service is enabled and risk is at least 50; failure leaves the URL absent. This is separate from Robinhood verdict evidence.
- Bucket: `shieldbot-reports`
- Public URLs: `https://greenfield-sp.bnbchain.org/view/shieldbot-reports/reports/<id>.json`

#### Provider circuit breakers (`core/circuit_breaker.py`)
- One breaker per provider and chain, for chains in `utils/chain_info.py` only; a provider whose request names no chain has one breaker. They cover GoPlus token security (`goplus_token`), GoPlus address labels (`goplus_address`), GoPlus phishing (`goplus_phishing`), Sourcify, Blockscout, Etherscan (verification and contract creation), honeypot.is, DexScreener and Token Sniffer.
- Three failed lookups in a row (a timeout, a connection error, a reply that is not JSON, HTTP 429 or 5xx) open a breaker for 60 seconds, after which one probe goes through and an answer closes it. While it is open nothing is sent: the lookup gets the answer a timeout gives (Unknown, never clean) and counts as failed in the Unknown ledger. `/api/ready` lists every breaker used so far as `ok` or `open`; an open breaker does not make the process unready.
- An open breaker's refusal is cached on some paths and not on others, on purpose. The GoPlus token-security and address-label lookups keep it for 30 seconds, like any failed lookup, so during an outage each address is asked at most every 30 seconds and a closed breaker is noticed up to 30 seconds late. The explorer lookups (Sourcify and Blockscout) never cache a refusal, so lookups resume as soon as the breaker closes; while Sourcify's breaker is open, no caller waits on a Sourcify lookup already in flight. Etherscan keeps no refusal either. The phishing check holds any no-verdict answer, a refusal included, for 45 seconds per domain.

---

### 4. AI Analyzer (LLM-Powered)

**File**: `utils/ai_analyzer.py`

Uses an **LLM API** for contextual risk analysis:

```python
# Input: Composite risk data from all services
scan_data = {
    'contract': contract_data,
    'honeypot': honeypot_data,
    'dex': dex_data,
    'ethos': ethos_data,
    'risk': risk_output,
}

# Output: Human-readable forensic analysis
ai_analysis = """
This contract exhibits a dangerous rug pull pattern:

🚨 Critical Issues:
- Mint function allows owner to create unlimited tokens
- Proxy pattern enables owner to change logic at any time
- Ownership NOT renounced (active owner can rug)
- Only $2,300 liquidity (easy to drain)
- Pair created <12 hours ago (pump-and-dump window)

💡 Recommendation: DO NOT INTERACT
This is a textbook rug pull setup. Owner can mint tokens to dilute holders,
or upgrade the proxy to steal funds. The low liquidity + new pair indicates
a coordinated scam launch.
"""
```

**Why AI?**
- Explains **WHY** a contract is risky (not just flags)
- Contextualizes **COMBINATIONS** of signals (e.g., "mint + proxy + new pair = rug")
- Adds contextual explanations; no measured false-positive reduction is claimed
- Provides **educational value** (users learn security patterns)

The AI never sets a score or a verdict. The legacy scanners score from their heuristics alone, and when the analysis pipeline fails the firewall's fallback takes its score and classification from those heuristics and the band table in `core/verdicts.py`; the model is told that verdict and only its explanation text is kept. In the firewall and forensic report prompts, token names and symbols, function names, labels, warnings and scam database reasons appear only as quoted, length-capped text that the prompt calls untrusted; the advisor chat's tool results are not treated this way yet.

---

## Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Backend** | Python | 3.11+ | Async runtime |
| **Web Framework** | FastAPI | Latest | REST API endpoints |
| **ASGI Server** | uvicorn | Latest | Production server |
| **Async HTTP** | aiohttp, httpx | Latest | Non-blocking API calls |
| **Web3** | web3.py | 6.15+ | Blockchain interaction |
| **Telegram** | python-telegram-bot | 20.7 | Bot framework |
| **AI** | LLM API | Latest | Forensic analysis |
| **Simulation** | Tenderly API | V1 | Transaction simulation |
| **Storage** | BNB Greenfield SDK | Latest | On-chain reports |
| **Extension** | Chrome Manifest V3 | Latest | Browser integration |

---

## Project Structure

```
shieldbot/
├── README.md                    # Project overview
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment template
├── bot.py                       # Telegram bot entry point
├── api.py                       # FastAPI backend entry point
│
├── docs/
│   ├── PROJECT.md               # Problem, solution, impact, roadmap
│   ├── TECHNICAL.md             # This file (architecture, setup)
│   └── EXTRAS.md                # Additional documentation (optional)
│
├── scanner/
│   ├── transaction_scanner.py  # Pre-tx security checks
│   └── token_scanner.py        # Token safety analysis (legacy)
│
├── core/
│   ├── risk_engine.py          # Composite weighted scoring
│   ├── extension_formatter.py  # Chrome extension response format
│   └── telegram_formatter.py   # Telegram message format
│
├── services/
│   ├── contract_service.py     # GoPlus + BscScan intelligence
│   ├── honeypot_service.py     # Honeypot.is simulation
│   ├── dex_service.py          # DexScreener market data
│   ├── ethos_service.py        # Ethos Network reputation
│   ├── tenderly_service.py     # Tenderly simulation
│   └── greenfield_service.py   # BNB Greenfield storage
│
├── utils/
│   ├── ai_analyzer.py          # AI forensic analysis
│   ├── calldata_decoder.py     # Transaction decoder + whitelist
│   ├── risk_scorer.py          # Heuristic scoring logic
│   ├── web3_client.py          # Web3 + liquidity lock detection
│   ├── scam_db.py              # Multi-source scam database
│   ├── firewall_prompt.py      # AI system prompt
│   └── onchain_recorder.py     # On-chain scan recording
│
├── extension/
│   ├── manifest.json           # Extension config (V3)
│   ├── inject.js               # Provider wrapper (MAIN world)
│   ├── content.js              # Modal renderer (ISOLATED world)
│   ├── background.js           # Service worker (API calls)
│   ├── popup.html              # Extension popup UI
│   ├── popup.js                # Popup logic
│   └── overlay.css             # Firewall modal styles
│
└── contracts/
    └── ShieldBotVerifier.sol   # On-chain verification contract (deployed on BSC Mainnet)
```

---

## Setup & Installation

### ⚠️ Important Note for Judges/Evaluators

**You don't need all API keys to evaluate ShieldBot!**

**Minimum setup to test core features:**
1. **Only BSCSCAN_API_KEY is required** (free at [bscscan.com/myapikey](https://bscscan.com/myapikey))
2. Run: `uvicorn api:app --host 0.0.0.0 --port 8000`
3. Visit: `http://localhost:8000/test`
4. Available checks run with the configured providers; missing or unsupported provider coverage must remain unknown. A BscScan key alone does not provide every risk check.

**Features that require optional API keys:**
- **Telegram Bot**: Requires TELEGRAM_BOT_TOKEN → **Historical bot link: [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot), availability unverified here**
- **BNB Greenfield**: Requires GREENFIELD_PRIVATE_KEY → Optional, only for report uploads
- **Tenderly Simulation**: Requires TENDERLY_API_KEY → Optional, core features work without it
- **AI Analysis**: Requires AI_API_KEY → Optional enhancement

**Easiest evaluation methods:**
1. **Historical Telegram link** (availability unverified here): [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot)
2. **Demo Video** (3 minutes): [Watch on YouTube](https://youtu.be/a-PbFsZz0Ds)
3. **Local API** (BscScan key only): Follow setup below

---

### Prerequisites

- **Python 3.11+** ([download](https://www.python.org/downloads/))
- **Git** ([download](https://git-scm.com/downloads))
- **Chrome/Brave Browser** (for extension testing)
- **API Keys** (see Environment Variables below)

### 1. Clone Repository

```bash
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv

# Linux/Mac
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

**Dependencies:** `requirements.txt` is the source of truth for installed package requirements.

### 4. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env`:

```env
# REQUIRED: Telegram Bot
TELEGRAM_BOT_TOKEN=your_telegram_bot_token

# REQUIRED: Blockchain
BSCSCAN_API_KEY=your_bscscan_api_key
BSC_RPC_URL=https://bsc-dataseed1.binance.org/
OPBNB_RPC_URL=https://opbnb-mainnet-rpc.bnbchain.org

# OPTIONAL: Advanced Features
TENDERLY_API_KEY=your_tenderly_key
TENDERLY_PROJECT_ID=your_tenderly_project_id
GREENFIELD_PRIVATE_KEY=your_greenfield_private_key
AI_API_KEY=your_ai_api_key

# OPTIONAL: Extension CORS
CORS_ALLOW_ORIGINS=chrome-extension://YOUR_EXTENSION_ID,http://localhost:8000
```

**How to Get API Keys**:

| Service | URL | Free Tier |
|---------|-----|-----------|
| BscScan | https://bscscan.com/myapikey | ✅ 5 req/sec |
| Telegram Bot | https://t.me/BotFather | ✅ Unlimited |
| Tenderly | https://dashboard.tenderly.co/ | ✅ 100 sim/month |
| AI API | https://console.anthropic.com/ | ✅ $5 free credit |
| Greenfield | https://greenfield.bnbchain.org/ | ✅ Pay-as-you-go |

### 5. Run Services

**Terminal 1: FastAPI Backend**
```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2: Telegram Bot**
```bash
python bot.py
```

**Verify Services**:
- FastAPI: http://localhost:8000/docs (Swagger UI)
- Health: http://localhost:8000/api/health
- Test Page: http://localhost:8000/test

### 6. Install Chrome Extension

1. Open Chrome: `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select `/path/to/shieldbot/extension/` folder
5. Copy the **Extension ID** (e.g., `abcdefghijklmnopqrstuvwxyz123456`)
6. Update `.env`: `CORS_ALLOW_ORIGINS=chrome-extension://YOUR_EXTENSION_ID`
7. Restart FastAPI backend

**Verify Extension**:
- Visit http://localhost:8000/test
- Click "Test BLOCK Verdict" → Should show red modal
- Click "Test WARN Verdict" → Should show orange overlay
- Click "Test ALLOW Verdict" → Should pass through silently

---

## Demo Guide

### 🎥 Video Walkthrough

**Watch the complete 3-minute demo:** [View on YouTube](https://youtu.be/a-PbFsZz0Ds)

The video shows:
- Chrome extension intercepting and blocking honeypot transactions
- Telegram bot displaying token names and symbols
- Real-time risk analysis with composite ShieldScore
- BNB Greenfield forensic report storage

### Illustrative Output Examples

These are historical mockups, not recorded scans or current schemas. The browser offers cancel/proceed overrides, including for high risk. Use [JUDGE_GUIDE.md](JUDGE_GUIDE.md) for recorded Robinhood evidence.

**Extension BLOCK Verdict:**
```
╔═══════════════════════════════════════════════════════════╗
║              🔴 TRANSACTION BLOCKED                        ║
║                                                            ║
║  Risk Score: 85/100 - HIGH RISK                           ║
║                                                            ║
║  ⚠️ Critical Flags:                                       ║
║  ✗ Honeypot confirmed - cannot sell after buying          ║
║  ✗ Sell tax: 99%                                          ║
║  ✗ Ownership not renounced                                ║
║  ✗ Low liquidity: $2,000                                  ║
║  ✗ Contract not verified                                  ║
║                                                            ║
║  Contract: 0x1234...5678                                   ║
║                                                            ║
║  This transaction has been blocked for your protection.   ║
║  ShieldBot detected multiple high-risk indicators.        ║
╚═══════════════════════════════════════════════════════════╝
```

**Telegram Bot Response (with Token Names):**
```
🟢 ShieldBot Intelligence Report

Token: Wrapped BNB (WBNB)
Address: 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
Risk Archetype: Low Risk
Rug Probability: 5% | Risk Level: LOW
Confidence: 95%

✓ Category Scores:
  • Structural: 10/100 (LOW)
  • Market: 5/100 (LOW)
  • Behavioral: 0/100 (SAFE)
  • Honeypot: 0/100 (SAFE)

✓ No Critical Flags

Contract Details:
  • Verified: ✓ Yes (BscScan)
  • Age: 1825 days (5.0 years)
  • Ownership: Renounced
  • Liquidity: $523,450,000

Market Metrics:
  • Liquidity: $523.45M
  • 24h Volume: $145.2M
  • Pair Age: 1825 days
```

**BNB Greenfield Forensic Report:**
```json
{
  "report_id": "3a4039ef0349eb5f",
  "timestamp": "2026-02-16T03:45:12.234Z",
  "contract_address": "0x1234567890abcdef1234567890abcdef12345678",
  "chain_id": 56,
  "risk_score": 85,
  "risk_level": "HIGH",
  "rug_probability": 87.5,
  "confidence_level": 75,
  "risk_archetype": "honeypot",
  "critical_flags": [
    "Honeypot confirmed - cannot sell after buying",
    "Sell tax 99%",
    "Ownership not renounced",
    "Low liquidity ($2,000)",
    "Contract not verified"
  ],
  "category_scores": {
    "structural": 90,
    "market": 75,
    "behavioral": 45,
    "honeypot": 95
  },
  "data_sources": {
    "goplus": { "is_honeypot": true, "honeypot_score": 95 },
    "honeypot_is": { "can_buy": true, "can_sell": false, "sell_tax": 99 },
    "dexscreener": { "liquidity_usd": 2000, "pair_age_hours": 12 },
    "ethos": { "reputation_score": 45, "scam_flags": true },
    "tenderly": { "simulation_success": false }
  },
  "public_url": "https://greenfield-sp.bnbchain.org/view/shieldbot-reports/reports/3a4039ef0349eb5f.json"
}
```

### Telegram Demo Commands (deployment availability unverified here)

**Bot**: [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot)

**Commands to Try**:

1. **Example Contract Scan**:
   ```
   /scan 0x10ED43C718714eb63d5aA57B78B54704E256024E
   ```
   *(PancakeSwap Router; inspect coverage as well as the risk result.)*

2. **Example Token Check**:
   ```
   /token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
   ```
   *(WBNB; the returned result depends on current provider coverage.)*

3. **Report Scam**:
   ```
   /report 0xSCAMADDRESS
   ```

### Chrome Extension Demo

**Prerequisites**:
- Extension installed and enabled
- FastAPI backend running on port 8000
- CORS configured correctly

**Test Page Demo** (http://localhost:8000/test):

1. **BLOCK Verdict**:
   - Click "Test BLOCK Verdict (Honeypot Token)"
   - Full-screen **red modal** appears
   - Shows risk score 85/100, critical flags
   - Choosing Block rejects the transaction; the proceed override forwards it to the wallet

2. **WARN Verdict**:
   - Click "Test WARN Verdict (Unverified Contract)"
   - **Orange warning overlay** appears
   - Shows risk score 45/100, medium risk
   - Two buttons: "Proceed Anyway" or "Cancel Transaction"

3. **ALLOW Verdict**:
   - Click "Test ALLOW Verdict (PancakeSwap)"
   - **No overlay** appears
   - Transaction passes through silently
   - MetaMask popup appears immediately

**Live dApp Demo** (PancakeSwap):

1. Visit https://pancakeswap.finance/swap
2. Connect wallet (MetaMask/Rabby)
3. Try to swap BNB for a **known honeypot token** (e.g., `0xSCAMADDRESS`)
4. ShieldBot intercepts → Shows BLOCK modal
5. Inspect a WBNB transaction separately.
6. An allow result requires complete required coverage and a permitting policy; token familiarity alone is insufficient.

### API Demo

**Scan Contract**:
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"address": "0x10ED43C718714eb63d5aA57B78B54704E256024E"}'
```

**Firewall Check**:
```bash
curl -X POST http://localhost:8000/api/firewall \
  -H "Content-Type: application/json" \
  -d '{
    "to": "0x10ED43C718714eb63d5aA57B78B54704E256024E",
    "from": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD61",
    "value": "0x2386F26FC10000",
    "data": "0x",
    "chainId": 56
  }'
```

**Free API Key** (self-serve):
```bash
curl -X POST http://localhost:8000/api/keys/free \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
```

The server emails a link to `/api/keys/free/verify`. The link works once and expires after 30 minutes; its token is in the URL fragment, which browsers do not send, so it never appears in server or proxy logs, and the page creates the key only when you press its button, so a mail scanner that only fetches the link does not use it up. A scanner that also presses the button would create the key where nobody sees it; the address then has its one free key, and only the admin can deactivate it (`AuthManager.deactivate_key`; there is no route for it). The key is shown once on that page and only its hash is stored. Send it as the `X-API-Key` header; the free tier allows 60 requests a minute and 1,000 a day.

The request answers the same 200 whether the address is new, already has a pending link or already has a key, so it does not reveal which. An address that already has an active free key gets an email saying so instead of a link; the admin must deactivate that key before a new one can be issued. Limits: one active free key per email address, one email per address per 30 minutes (nothing new is sent while one is pending), and three requests a minute per IP. Without `RESEND_API_KEY` the endpoint answers 503 "Self-serve keys are not enabled" and issues nothing. `PUBLIC_API_URL` sets the host in the emailed link (default `https://api.shieldbotsecurity.online`); it is never taken from the request.

Both responses carry `evidence_hash` and `evidence_url`; see [Evidence Documents for API Verdicts](#evidence-documents-for-api-verdicts).

```bash
curl http://localhost:8000/api/evidence/<evidence_hash>
```

**Health Check**:
```bash
curl http://localhost:8000/api/health
```

---

## Testing

### Unit Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=. --cov-report=term-missing
```

**Selected test modules** (see [TESTING.md](TESTING.md) for measured suite results):
- `test_api.py` — Firewall & scan API endpoints
- `test_calldata.py` — Calldata decoder, selector detection, approval parsing
- `test_risk_scorer.py` — Heuristic scoring, confidence
- `test_intent_analyzer.py` — Intent mismatch detection
- `test_rpc_proxy.py` — RPC proxy intercept, fail-closed behavior
- `test_ownership.py` — Ownership renouncement checks
- `test_multichain_routing.py` — Chain adapter routing
- `test_policy.py` — Policy engine modes (STRICT/BALANCED)
- `test_calibration.py`, `test_calibrate_script.py` — Threshold proposals from trusted labels
- Additional modules cover provider coverage, Robinhood simulation fixtures, verdict publication, auth, persistence and other paths.

### Manual Testing Checklist

**Extension**:
- [ ] Loads without errors in Chrome
- [ ] Intercepts transactions on test page
- [ ] Shows correct verdict modals (BLOCK/WARN/ALLOW)
- [ ] Allows user to cancel WARN verdicts
- [ ] Router swap tokens are analyzed; undecodable or unscanned swap paths remain unknown
- [ ] Works with MetaMask, Rabby, and other EIP-6963 wallets

**Telegram Bot**:
- [ ] Responds to /start, /help commands
- [ ] /scan returns risk analysis for contracts
- [ ] /token shows token name, symbol, and risk score
- [ ] Handles invalid addresses gracefully
- [ ] Response time <3 seconds for scans

**API**:
- [ ] /api/firewall returns correct verdict for honeypots
- [ ] /api/scan returns composite risk data
- [ ] /api/health shows service status
- [ ] /test page renders correctly
- [ ] CORS allows extension requests
- [ ] Handles network errors gracefully (external APIs down)

---

## Deployment

### Production Deployment (VPS/Cloud)

**Recommended**: Ubuntu 22.04 LTS, 2GB RAM, 1 vCPU

```bash
# SSH to server
ssh user@your-server-ip

# Install dependencies
sudo apt update
sudo apt install python3.11 python3.11-venv nginx certbot

# Clone repo
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot

# Setup environment
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure .env (use production API keys)
nano .env

# Create systemd service for Telegram bot
sudo nano /etc/systemd/system/shieldbot-bot.service
```

**shieldbot-bot.service**:
```ini
[Unit]
Description=ShieldBot Telegram Bot
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/shieldbot
Environment="PATH=/home/ubuntu/shieldbot/venv/bin"
ExecStart=/home/ubuntu/shieldbot/venv/bin/python bot.py
Restart=always

[Install]
WantedBy=multi-user.target
```

**Start services**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable shieldbot-bot
sudo systemctl start shieldbot-bot

# Run one API process, matching shieldbot-api.service
uvicorn api:app --host 127.0.0.1 --port 8000
```

Run exactly one API process when verdict publication is configured. The API lifespan starts the verdict outbox sender, and its nonce lock is process-local. Multiple workers or API replicas would start competing senders for the same recorder. `shieldbot-api.service` deliberately sets no `--workers`; do not add workers, reload mode, or a second API instance to this deployment.

**Nginx Reverse Proxy** (for HTTPS):
```nginx
server {
    listen 80;
    server_name api.shieldbot.xyz;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

The API takes the client address from X-Forwarded-For; without it every user shares one rate-limit bucket. `deploy/nginx-api.conf.example` is the full reference vhost, with TLS and timeouts.

**SSL Certificate**:
```bash
sudo certbot certonly --webroot -w /var/www/html -d api.shieldbot.xyz
```

Serve the challenge location above before requesting the certificate, then configure TLS explicitly in the vhost. Use webroot issuance on the shared VPS; do not let Certbot rewrite its nginx listeners.

### Docker Deployment (Future)

```dockerfile
# Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "bot.py"]
```

---

## Performance Optimization

### Response Time Targets

| Operation | Historical target | Measurement |
|-----------|--------|---------|
| Extension verdict | <2s | Not measured for this submission |
| Telegram /scan | <3s | Not measured for this submission |
| API /firewall | <2s | Not measured for this submission |
| Greenfield upload | <5s | Not measured for this submission |

### Optimization Strategies

1. **Parallel API Calls**: All data services run via `asyncio.gather()`
2. **Caching**: 5-minute TTL for contract scans (Telegram bot)
3. **Router Recognition**: Recognized swaps analyze the decoded path tokens; router recognition does not bypass token checks
4. **Rate Limiting**: Respects BscScan free tier (5 req/sec)
5. **Connection Pooling**: Reuses HTTP connections via aiohttp

---

## Security Considerations

### Extension Security

- **No Private Key Access**: Extension never touches wallet private keys
- **Transport**: Verify the configured API URL and deployed TLS configuration; repository settings alone do not establish transport security.
- **Content Security Policy**: Strict CSP in manifest.json
- **No Remote Code Execution**: All logic bundled in extension

### API Security

- **CORS Allowlist**: Allows configured origins; this is not authentication
- **Rate Limiting**: API middleware applies key quotas or an IP-based fallback
- **STRICT and the score cache**: `/api/firewall` answers a repeat request for a target from its stored verdict for 5 minutes. The `X-Policy-Mode: STRICT` header skips that cache only on a request with a valid API key; any other STRICT request is answered from the cached facts judged in STRICT mode (a cached row with any Unknown in it blocks), so the header can no longer force a full uncached scan. That does not make every request cacheable: transaction-specific requests (paying calls, approvals, typed-data signatures) and swaps through a trusted router always scan fresh by design, because their verdict depends on the transaction as well as the target. For those, the IP rate limiter above is the control on repeated fresh scans.
- **AI Spend Cap**: advisor chat (API side panel and Telegram) and scan explanations share one daily token budget, `AI_DAILY_TOKEN_BUDGET` (default 1,000,000 input plus output tokens per UTC day, counted from the provider's reported usage and stored in SQLite). Once it is used, chat answers that AI chat is paused for today and explanations fall back to rule-based text. `AI_DAILY_TOKEN_BUDGET=0` pauses AI entirely, a kill switch; a negative value is refused and stops the API and bot at startup. The check runs before each call, so calls already in flight can overshoot it by their own size.
- **Input Validation**: Review the request model and handler for the endpoint being used; this document does not claim that every input path has identical validation.
- **Error Handling**: Inspect endpoint error responses separately; this document does not certify that every path redacts internal details.

### Data Privacy

- **Persistent Backend State**: SQLite retains scan scores, findings, agent transaction history, chat history and identifiers, subscriptions, verdict evidence, API scan evidence documents and publication outbox state (`core/database.py`).
- **Retention**: the hunter's sweep in the API process (at startup, then every 30 minutes) deletes chat messages older than 24 hours (each chat also keeps at most its last 50), API key usage rows (`api_usage`), daily key counts (`api_daily_usage`), daily AI token counts (`ai_token_usage`) and `/api/firewall` and `/api/scan` evidence documents (`scan_evidence`) older than 90 days, free key link requests at the first sweep after they expire (a link lasts 30 minutes), and community entries of the scam blacklist 30 days after they were added unless an admin confirmed them. Community reports are kept as evidence. Their `reporter_id` is HMAC-SHA256 of the client IP under `REPORTER_HASH_SECRET`, cut to 32 hex characters, or null when that secret is unset; the IP itself is never stored, and a startup migration cleared the IPs stored before. Nothing else expires on its own: beta signup emails, API keys and their owners, scan scores, outcome events, findings, agent firewall history, guardian wallets and alerts, launch alert subscriptions and Robinhood Chain verdict evidence (`verdict_evidence`) stay until deleted.
- **Local Extension State**: Browser storage holds settings, recent scan results, a chat identifier and recent chat messages. Removing the extension does not delete backend records.
- **External Processing**: Configured RPC and intelligence services receive the addresses or transaction data needed by the invoked checks. Optional AI and report publication flows can send additional analysis data; a risk threshold is not user consent.
- **Open Source**: All code auditable at https://github.com/Ridwannurudeen/shieldbot

#### Deleting a person's data

There is no deletion route. On the server, run these against `/opt/shieldbot/shieldbot.db` with the `sqlite3` shell, or Python's `sqlite3` module where the shell is not installed (the database is in WAL mode, so the API can stay up):

- **An email address**, in lower case as it is stored (beta list, free key requests, API keys it owns). The keys are deactivated and their owner replaced rather than deleted, and their usage rows go first:

  ```sql
  DELETE FROM beta_signups WHERE email = 'person@example.com';
  DELETE FROM free_key_requests WHERE email = 'person@example.com';
  DELETE FROM api_usage WHERE key_id IN (SELECT key_id FROM api_keys WHERE owner = 'person@example.com');
  UPDATE api_keys SET is_active = 0, owner = 'deleted' WHERE owner = 'person@example.com';
  ```

- **A client IP** (community reports). A stored reporter cannot be turned back into an IP, so hash the IP the way the API does, in the form the API received it, then clear the match. This prints `None` when `REPORTER_HASH_SECRET` is unset, in which case no report holds anything derived from an IP:

  ```bash
  cd /opt/shieldbot && venv/bin/python -c "import sys; from core.config import Settings; from core.database import reporter_hash; print(reporter_hash(Settings().reporter_hash_secret, sys.argv[1]))" 203.0.113.7
  ```

  ```sql
  UPDATE community_reports SET reporter_id = NULL WHERE reporter_id = '<printed hash>';
  ```

- **A Telegram user** (bot chats are stored under `tg-<user id>`; launch alert subscriptions and the alerts queued for them under the chat id, which for a private chat is the user id):

  ```sql
  DELETE FROM chat_history WHERE user_id = 'tg-123456789';
  DELETE FROM launch_alert_subscriptions WHERE chat_id = 123456789;
  DELETE FROM launch_alert_outbox WHERE chat_id = 123456789;
  ```

Side panel chats are stored under a hash of the install or IP and the chat id, which cannot be looked up from a person's details; they are deleted within 24 hours.

---

## Troubleshooting

### Extension Not Intercepting Transactions

1. Check extension is enabled: `chrome://extensions`
2. Verify CORS_ALLOW_ORIGINS includes extension ID
3. Restart FastAPI backend after .env changes
4. Check console for errors: Right-click extension → Inspect
5. Test on http://localhost:8000/test first

### Telegram Bot Not Responding

1. Check bot is running: `systemctl status shieldbot-bot`
2. Verify TELEGRAM_BOT_TOKEN is correct
3. Check logs: `journalctl -u shieldbot-bot -f`
4. Test API independently: `curl localhost:8000/api/health`

### API Calls Failing

1. Check all required API keys in .env
2. Verify internet connectivity (external APIs)
3. Test endpoints: http://localhost:8000/docs
4. Check rate limits (BscScan free tier = 5/sec)

### Greenfield Upload Failing

1. Verify GREENFIELD_PRIVATE_KEY is set
2. Check Greenfield bucket exists
3. Ensure wallet has BNB for gas
4. Test on testnet first

---

## Contributing

Contributions are welcome! Areas for improvement:

- **Additional Data Sources**: Chainlink feeds, on-chain heuristics
- **Machine Learning**: Pattern recognition from Greenfield reports
- **Mobile SDKs**: Trust Wallet, SafePal integration
- **Testing**: Unit tests, integration tests, E2E tests
- **Documentation**: Tutorials, security guides, case studies

**Contribution Process**:
1. Fork repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

---

## License

MIT License - see LICENSE file for details

---

## Contact & Support

- **Issues**: https://github.com/Ridwannurudeen/shieldbot/issues
- **Telegram**: [@Ggudman](https://t.me/Ggudman)
- **Twitter**: [@Ggudman1](https://twitter.com/Ggudman1)

---

**Last Updated**: February 2026
