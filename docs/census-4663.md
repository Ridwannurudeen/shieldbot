# Robinhood Chain observation census

This standalone tooling observes chain **4663** without sending transactions. It
does not modify ShieldBot's adapters or call competitor scanners. The live collector
is described below, and the results of the completed report window are in
[SUBMISSION.md](SUBMISSION.md#robinhood-chain-observation-census). These commands do
not install the example service.

## Live deployment

The observation census **is** now running. The paths in the examples below are
illustrative; the deployed instance uses different ones:

| | value |
|---|---|
| systemd unit | `rh-census-4663.service` |
| working directory | `/opt/rh-census-4663/app` |
| interpreter | `/opt/rh-census-4663/venv/bin/python` |
| data directory | `/var/lib/rh-census-4663` |

So the report against the live data is:

```bash
cd /opt/rh-census-4663/app
/opt/rh-census-4663/venv/bin/python -m scripts.census_4663.report --data-dir /var/lib/rh-census-4663
```

Two practical notes. The database is large (tens of GB, ~19M event rows), so a full
report takes far longer than a shell session usually stays open — **run it detached**
(`nohup ... &`) and collect `report.json` / `report.md` from the data directory
afterwards, rather than waiting on the pipe. A `COUNT(*)` over `events` is slow for
the same reason; use `max(rowid)` when you only need an order of magnitude.

## Collector

Run from the checkout root using the project's existing Python environment:

```bash
python -m scripts.census_4663.collect --data-dir /var/lib/shieldbot-census-4663 --from-block 62233970 --to-block 62287969
python -m scripts.census_4663.collect --data-dir /var/lib/shieldbot-census-4663 --follow
```

Those block numbers illustrate a 54,000-block replay, not a permanently recent
range. Choose a recent range ending at least 60 blocks behind the current tip.
On Windows, use a directory outside the checkout, such as a
`shieldbot-census-4663` folder in your user temp directory, instead of `/var/lib/...`.
The tool rejects data directories inside a git checkout.
Never commit the SQLite database, provider responses, reports or smoke results.

With no existing cursor and no `--from-block`, collection starts at the latest
confirmed block. With an existing cursor, it resumes at the next uncollected
block. Omit `--from-block` on resume, or repeat the original start exactly.
`--to-block` bounds replay; `--follow` polls every six seconds and stops at the
requested end if both are supplied. Only one collector may own a data directory.

Defaults are `--confirmations 60`, `--chunk-size 2000`, and `--rps 4`. The rate
ceiling counts HTTP requests, including retries, not individual JSON-RPC operations
inside a batch. Header and receipt requests batch up to 50 operations per HTTP
request. Size/range errors recursively halve log ranges. Transient transport and
throttling failures use bounded
exponential backoff. An exhausted or inconsistent request fails visibly without
advancing that chunk; rerunning resumes from its durable cursor.

The default RPC is `https://rpc.mainnet.chain.robinhood.com`. An operator may set
`CENSUS_RPC_URL` in the environment. For sustained collection, setting
`CENSUS_HEADER_RPC_URL=https://robinhood-rpc.publicnode.com` is recommended to
offload header reads when the primary RPC throttles batches. Only block headers
go to this optional endpoint; logs, transactions and receipts use the primary.
Both endpoints must return chain 4663, and log/receipt block hashes must match the
headers. The configured request-rate budget is divided evenly between endpoints.
PublicNode rejected this historical log range without a personal token during
verification, so it is used only for its publicly accessible header reads.
Every polling cycle verifies `eth_chainId` for each configured endpoint;
a mismatched RPC or database fails explicitly. Requests use aiohttp and explicit
timeouts, not urllib. SQLite WAL stores pools, decoded events, creation receipt
evidence, block hashes and cursor together in atomic chunk transactions.

The collector retains contiguous hashes at the end of each chunk and checks the
last confirmation-depth window on resume/follow. A changed hash rewinds to a
matching ancestor, deletes affected pools, events and evidence, and replays.
It retains event-block headers and chunk boundaries for deeper rewinds and time
coverage. Event timestamps come from canonical block headers: `eth_getLogs` can
return `blockTimestamp: 0x0` even when receipt logs have populated timestamps.
Reorg checks protect collector data; previously exported reports, probes and fixed
smoke selections are snapshots and must be regenerated or reviewed separately
after a reorg.

Measured sources:

- Uniswap v4 PoolManager `0x8366a39cc670b4001a1121b8f6a443a643e40951`:
  `Initialize`, then `Swap` and `ModifyLiquidity` for observed pools.
- Uniswap V2 factory `0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f`:
  `PairCreated`, then `Swap`, `Mint` and `Sync` on those pairs.
- Optional `--v3-factory ADDRESS`: records `PoolCreated` and launch-source
  evidence only. V3 trading/liquidity eligibility is unknown. No Robinhood v3
  factory is configured or claimed verified. Without this option reports say
  **v3 not measured**. The option cannot change within an existing census.

Topic0 hashes are computed with keccak from canonical ABI signatures, with source
links in `scripts/census_4663/events.py`. Sources are Uniswap
[v4 IPoolManager](https://github.com/Uniswap/v4-core/blob/main/src/interfaces/IPoolManager.sol),
[V2 factory](https://github.com/Uniswap/v2-core/blob/master/contracts/interfaces/IUniswapV2Factory.sol),
[V2 pair](https://github.com/Uniswap/v2-core/blob/master/contracts/interfaces/IUniswapV2Pair.sol)
and optional [V3 factory](https://github.com/Uniswap/v3-core/blob/main/contracts/interfaces/IUniswapV3Factory.sol).

## Report and metric definitions

```bash
python -m scripts.census_4663.report --data-dir /var/lib/shieldbot-census-4663
python -m scripts.census_4663.report --data-dir /var/lib/shieldbot-census-4663 --since 2026-09-13T00:00:00Z --until 2026-09-14T00:00:00Z
```

This writes `report.json` and `report.md` in the data directory. Dates must include
a timezone. The requested window is clamped to actual collected block timestamps;
the current wall clock cannot turn an incompletely observed token into a mature
one. Reports, probe token samples and smoke selection open the database read-only
and read one consistent snapshot while the collector runs. The collector keeps
committing; its WAL cannot be checkpointed past that snapshot until the command
finishes. Events and creation receipt evidence are streamed, so memory grows with
the number of pools and tokens, not with the number of events.

**New tokens** means unique non-native/non-WETH addresses at their first observed
pool creation in this census, not proof of token deployment. WETH is
`0x0bd7d308f8e1639fab988df18a8011f41eacad73`; native ETH is the zero address.
Daily counts use UTC and count each token once globally. V4/V2 source counts
deduplicate within each source and can overlap, so their sum need not equal the
global total. Starting a census mid-history creates a left-censored population:
old tokens gaining new pools can appear as new observations.

**Launch-source evidence** records each creation transaction's `from`, `to`, all
receipt emitters and receipt logs. A token is atomic-mint evidence when its first
ERC-20 `Transfer` in that receipt has a zero sender. This is evidence consistent
with atomic launch, not proof of token deployment or ownership: an existing token
can mint again. Otherwise its source is **prior**; no historical tracing is done.
Candidate launch contracts are the transaction recipient and emitting contracts,
ranked by distinct atomic-mint tokens after excluding known infrastructure and
observed token and pair/pool contracts. The infrastructure exclusions are the v4
PoolManager, PositionManager, Universal Router, Permit2, Quoter and StateView;
the V2 factory and Router02; and WETH. Full receipt evidence remains stored.
The remaining addresses are candidates, not confirmed independent launchpads.
Each candidate includes its topic0 histogram and an example transaction per topic
from observed creation receipts, including prior-token receipts.

The [Doppler deployment configuration](https://raw.githubusercontent.com/whetstoneresearch/doppler/main/deployments.config.toml)
identifies two chain-4663 components:

| Contract | Label | Launch stack |
| --- | --- | --- |
| `0xeb7c034704ef8dcd2d32324c1545f62fb4ad0862` | Doppler Airlock | Doppler |
| `0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544` | Doppler HookInitializer | Doppler |

The launch-source ranking groups these components as one **Doppler** stack and
counts the union of their token addresses once. Contract-level evidence remains
available. Counts attributed to contracts in the same launch transaction overlap;
they are not independent launchpads and must not be summed.

**Eligibility** is at least 10 observed swaps **OR** at least 0.5 ETH of ETH/WETH-side
liquidity within 1,800 seconds after a token's first observed pool. Pool activity
is combined per token. Tokens younger than 30 minutes at the report window end are
excluded and counted separately. The pass rate denominator is all mature tokens;
unknown cases remain in that denominator and are also reported separately. The
grid repeats this calculation for swaps 5/10/20 and ETH 0.1/0.5/1.0. Liquidity
retains Decimal precision through every threshold comparison, including the grid;
conversion to float is only for presentation.

- **V2 liquidity:** latest `Sync` WETH-side reserve divided by `10**18`.
  Missing `Sync` is unknown, not zero.
- **V4 liquidity:** reconstruct position liquidity by summing signed
  `ModifyLiquidity` deltas for each sender/tickLower/tickUpper/salt, then value its
  principal using the current `Initialize`/`Swap` `sqrtPriceX96`. For square-root
  bounds `a,b` and price `p` clamped to those bounds, token0 principal is
  `L * (1/p - 1/b)` and token1 principal is `L * (p - a)`. Divide the ETH-side amount
  by `10**18`. Decimal tick-price arithmetic estimates the
  [Uniswap principal formulas](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol);
  it does not reproduce exact Solidity rounding, fees, donations or hook claims.
  This is observed principal, not executable exit liquidity.
- Liquidity peaks sum **simultaneous** pool states, not independent maxima at
  different times. Missing, invalid or unsupported observations remain unknown.
  A known liquidity lower bound or sufficient observed swaps can establish a pass.

**Discovery latency** is creation-log ingestion time minus creation-block time.
JSON/Markdown include count, min, p50/p90/p95/p99 and max, in seconds. This measures
pool discovery events and includes confirmation depth, replay delay and request
time. A historical replay does not measure production real-time latency.

## Provider probes

```bash
python -m scripts.census_4663.probe_goplus --data-dir /var/lib/shieldbot-census-4663 --limit 10
python -m scripts.census_4663.probe_blockscout --data-dir /var/lib/shieldbot-census-4663 --limit 10
```

Both select deduplicated census tokens deterministically by address and wait at
least one second between HTTP requests. They record status, latency, exact calls,
raw JSON, fields present and fields nonempty. String `"0"`, numeric zero and false
are present values; absent/null/empty values are not negative security verdicts.
HTTP failures and malformed/mismatched data remain unknown. GoPlus highlights
`is_honeypot`, `buy_tax`, `sell_tax`, `cannot_sell_all`, `transfer_pausable` and
`is_open_source`. Compute-unit costs are not inferred; only exposed response
headers/body information is retained.

Outputs are `probe_goplus.json` and `probe_blockscout.json`. Call counts describe
that invocation; another invocation overwrites its prior output. Preserve a
timestamped copy outside the checkout if collecting repeated measurements.
GoPlus makes one request per selected token. Blockscout makes three.

Blockscout requires `BLOCKSCOUT_API_KEY` in the environment; without it the command
exits **2** and prints `BLOCKSCOUT_API_KEY is required`, without network activity.
The [official PRO route documentation](https://docs.blockscout.com/devs/pro-api-responses-and-routes)
defines the following paths, authenticated with an Authorization Bearer header:

```text
https://api.blockscout.com/4663/api/v2/addresses/<address>
https://api.blockscout.com/4663/api/v2/tokens/<address>
https://api.blockscout.com/4663/api/v2/smart-contracts/<address>
```

No per-instance Blockscout or Etherscan API is used for 4663. Probes measure
coverage; they do not equate provider availability with token safety.

## Fixed smoke cases and comparator records

```bash
python -m scripts.census_4663.smoke_cases select --data-dir /var/lib/shieldbot-census-4663 --out /var/lib/shieldbot-census-4663/smoke-v1.json
python -m scripts.census_4663.smoke_cases record --cases /var/lib/shieldbot-census-4663/smoke-v1.json --case-id 4663:0xTOKEN_ADDRESS --comparator manual-review --verdict unknown --raw-output /var/lib/shieldbot-census-4663/manual-output.txt --access-failure --failure-reason "Service unavailable" --notes "Recorded by operator"
```

`select` requires at least 20 distinct tokens and refuses to overwrite an existing
selection. The versioned JSON freezes its seed, rule, observation window and
evidence. Disjoint strata prioritize GoPlus flags, two-way swaps, buys without
sells, mature ineligible, unknown and young cases; round-robin allocation with
SHA-256(seed:token) ordering fills exactly 20 unique cases. No available stratum
is fabricated. Buy/sell direction describes observed pool logs, not guaranteed
sellability for a new buyer.

`record` reads a UTF-8 raw-output file and appends a timestamped verdict to the
selection's `.verdicts.jsonl` sidecar. Each case/comparator pair may be recorded
once. Access failures require an explicit reason. Serialize record commands to
avoid concurrent append races. These commands never call a comparator service.

## Operations and known limits

`deploy/census-4663.service` is an **example only**. Before an operator installs
it, provision the unprivileged `shieldbot-census` account, validate the interpreter
and checkout paths, and provide `/etc/shieldbot/census-4663.env` using the operator's
existing environment/secret mechanism. The unit keeps writable state in
`/var/lib/shieldbot-census-4663`, uses `Restart=on-failure`, and embeds no secrets.
There is no automatic seven-day stop: the operator controls the observation
start/end and stops the service after the intended period.

The public RPC is non-archive. This collector uses recent logs, block headers,
transactions and receipts, never old state reads. RPC availability and retained
history still bound replay. There is no pending-transaction measurement. Existing
pools whose creation predates the census are not monitored. V3 is not measured by
default. Tokens minted earlier are marked prior without tracing their launch
history. Missing source/provider coverage is unknown, not safe or verified.

Offline validation from the worktree root:

```bash
python -m pytest tests/ sdk/python/tests -q -p no:cacheprovider --ignore=tests/test_bot_app.py
```

The local exclusion is for the pre-existing missing `python-telegram-bot` package;
CI installs pinned dependencies and runs the complete suite on Python 3.11.
