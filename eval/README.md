# ShieldBot accuracy benchmark

This folder measures how ShieldBot's risk score separates labelled malicious addresses from safe ones.
It has no published result yet: no scores have been recorded against the v2 dataset below.

| File | What it is |
|---|---|
| `data/benchmark_v2.json` | The v2 dataset (`shieldbot-benchmark/2`): one class per entry, independent sources, dates. |
| `data/benchmark_v1.json` | The v1 dataset: 34 addresses, 2 of them marked stale. Its 14 honeypot labels came from honeypot.is, a provider ShieldBot scores with, so v1 measures agreement with that provider, not accuracy. |
| `live_scorer.py` | Scans every entry with the real analysis pipeline (network and API keys) and records the scores. |
| `cli.py` | Computes the results file from recorded scores, offline. |
| `verify_onchain.py` | Re-reads the on-chain facts every label rests on, from public RPCs. Nothing that scores imports it. |

## Size on 2026-09-24

v2 holds **650 entries in 5 of its 8 classes**; 259 of them (40%) are safe.

| Class | 1 | 56 | 8453 | 42161 | 137 | 10 | 204 | 4663 | Total |
|---|---|---|---|---|---|---|---|---|---|
| `honeypot` | | | | | | | | | 0 |
| `rug_pull` | | | | | | | | | 0 |
| `drainer_contract` | 70 | 14 | 3 | 11 | 9 | 8 | | | 115 |
| `approval_drainer_spender` | 41 | 25 | 10 | 23 | 19 | 13 | | | 131 |
| `address_poisoning` | 10 | 12 | 10 | 10 | 10 | | | | 52 |
| `impostor_token` | | | | | | | | 93 | 93 |
| `fake_claim` | | | | | | | | | 0 |
| `safe` | 74 | 54 | 44 | 22 | 19 | 14 | 3 | 29 | 259 |
| Total | 195 | 105 | 67 | 66 | 57 | 35 | 3 | 122 | 650 |

Entries are not all independent. The 115 drainer entries are 70 contracts: 45 are the same bytecode at the
same address on another chain. The 131 approved spenders are 91 addresses from 57 incidents (the same
contract on several chains counts once per chain). Counted by bytecode (the keccak of `eth_getCode`),
the classes hold fewer distinct contracts still:

| Class | Entries | With code | Distinct bytecodes | Groups sharing one bytecode (largest) |
|---|---|---|---|---|
| `drainer_contract` | 115 | 115 | 57 | 21 (6, 6, 6) |
| `approval_drainer_spender` | 131 | 119 | 81 | 12 (6, 6, 6) |
| `address_poisoning` | 52 | 0 (EOAs) | 0 | |
| `impostor_token` | 93 | 93 | 59 | 3 (31, 4, 2) |
| `safe` | 259 | 259 | 211 | 17 (20, 7, 4) |

The safe group of 20 is Robinhood's official tokens, one proxy bytecode; the group of 7 is Permit2 on each
chain. Read a class's rates with that in mind: a rate over distinct bytecodes is not computed yet.

Thin chains: opBNB (204) has 3 safe tokens and nothing else; OP Mainnet (10) has no poisoning (9
zero-value stablecoin transfers in 5,000 blocks, none matching); Base has 3 drainer contracts; Robinhood
Chain (4663) has only impostor tokens and safe entries. No chain has a honeypot, rug pull or fake claim.

## Sources, and why each is independent

A malicious label rests only on sources that nothing computing ShieldBot's score reads. Every entry, safe
ones included, also carries an `onchain` source: what a public RPC returned on 2026-09-24.

| Provider | What it gives | Independence check |
|---|---|---|
| `onchain` | `eth_getCode`, `symbol()` and `name()`, and Transfer logs, read from public RPCs | A direct read of the chain, stated in a form `verify_onchain.py` re-reads |
| `scamsniffer` | Scam Sniffer's open address blacklist, commit `929fe790` | Not read by any code. Whether GoPlus takes it in cannot be established from public information, so independence from GoPlus is asserted, not proven |
| `revokecash` | Revoke.cash's approval exploit list, commit `f1f85694` | The only mention in the code is a link to revoke.cash in a bot message. Whether GoPlus takes it in cannot be established from public information, so independence from GoPlus is asserted, not proven |
| `robinhood` | Robinhood's official token list, `api.robinhood.com/rhj/assets` (195 assets), not pinned: the API has no revisions | Nothing that computes a score reads it. `services/robinhood_assets.py` reads the same list and adds an impostor flag to bot and agent replies after scoring, which `eval/live_scorer.py` does not apply. The `impostor_token` labels rest on that same list and on a symbol and name rule close to that module's, so the class grades the score, which never sees the list, and cannot grade the impostor flag. The two rules differ: the seed's AMD "Advanced Micro Dog" is a collision under the module's rules and an `impostor_token` here |
| `uniswap` | Uniswap's default token list (commit `20b0d0de`) and deployment docs (commit `1c7597d7`) | Not read by any code |
| `pancakeswap` | PancakeSwap's token lists, commit `1dd8633d` | Not read by any code |
| `geckoterminal` | Pool reserves and pool creation dates | Not read by any code; ShieldBot reads DexScreener for liquidity, a separate provider over the same pools |

Considered and left out: Forta's labelled datasets. Their README says the labels are Etherscan's
`exploit`, `heist` and `phish-hack` tags, and Etherscan is a ShieldBot input.

## How each class was built

- `drainer_contract`: Scam Sniffer's list holds 4,607 addresses and no chain. Read on Ethereum, 278 of them
  held contract code that is not an EIP-7702 delegation (87 more were delegations). The class takes the
  first 70 of those contracts in list order (the seed's 15 among them), and each of those 70 again on
  BNB Chain, Base, Arbitrum, Polygon and OP Mainnet where the address holds byte-for-byte the same code
  (45 entries). An address also on Revoke.cash's list is filed under `approval_drainer_spender`.
- `approval_drainer_spender`: the evidence is a curated incident list that names the address, not a
  victim's approval and transfer read on chain. Every incident in Revoke.cash's list, one address per
  incident and chain (the first the incident lists), on the supported chains. Left out are the 10 incidents whose own
  description says the flaw was fixed, disabled or can no longer be exploited without telling approvers to
  revoke: `lifi-2024`, `lifi`, `maestro`, `socket`, `unizen`, `quixotic`, `flooring`, `magpie`,
  `dolomite` and `civtrade`. Radiant counts only on Arbitrum and BNB Chain: its description says the
  Ethereum and Base pools were never upgraded. The class mixes attacker contracts and wallets (12 entries
  are EOAs) with exploited protocol contracts whose flaw the list does not describe as fixed.
- `address_poisoning`: from the Transfer logs of USDT and USDC on each chain (bridged USDT on Base) over
  the last 1,500 to 6,000 blocks before the scan. An entry P, with counterpart C, needs all of: a
  zero-value `Transfer(V -> P)` in a transaction sent by someone other than V (the `transferFrom` that
  moves nothing and needs no allowance); an earlier `Transfer(V -> C)` of the same token of at least one
  whole token, where C never received a zero-value transfer in the window; C != P and the two share their
  first 4 and last 4 hex digits; and no contract code at P. At most 12 per chain, one per P and per C.
- `impostor_token`: Robinhood Chain tokens found by a GeckoTerminal pool search for each official ticker
  (the search only finds candidates; the label rests on the list and the chain). A token counts when its
  on-chain `symbol()` is an official ticker of 3 or more characters, its `name()` contains the company's
  first word of 3 or more letters (`Microsoft`, `Palo`, `Lam`), and its address is not on Robinhood's list.
  A name in Robinhood's own "Company • Robinhood Token" form (possibly a Robinhood deployment missing from
  the list) or with another issuer's marker (Backpack, xStock, dShares, Dinari, Backed, Ondo) is left out.
  At most 2 per ticker, those with the most GeckoTerminal reserves first; that order put the batch of 31
  with mispriced reserves (Known biases) ahead of the rest wherever it had a token. The 3 seed impostors were
  labelled under the class definition alone (an official ticker as symbol at another address, or the
  company as name) and are kept; their evidence has no `eth_getCode` fact. The label records that a token
  carries an official ticker or company name at another address; it asserts nothing about intent.
- `safe`:
  - the 20 v1 blue chips, re-read on chain;
  - 63 Uniswap contracts from its deployment docs (V2 factory and router, V3 factory, position manager,
    SwapRouter02, UniversalRouter, Permit2, V4 pool and position managers) on the 7 chains the docs cover;
  - 156 tokens on Uniswap's or PancakeSwap's lists whose GeckoTerminal pools hold $250,000 or more
    ($5,000 on opBNB) and whose oldest top pool was created by 2025-09-24, the most liquid first, up to 60 on
    Ethereum, 39 on BNB Chain, 33 on Base, 13 on Arbitrum, 10 on Polygon, 5 on OP Mainnet and 3 on opBNB;
  - 20 of Robinhood's official tokens that Uniswap's list also carries, the tickers impostors copy first.
    These are young, as the chain is.

  No safe address is on Scam Sniffer's or Revoke.cash's list.

## Known biases

- Drainer contracts and approved spenders are mostly not tokens, and poisoning addresses are EOAs. The
  token checks cannot complete on them, so many are expected to score unknown: that shows as the class's
  unknown rate, not as missed recall.
- Approved spenders include protocol contracts that were exploited, not deployed by an attacker. A
  protocol deployed them, often years ago, so the structural penalties for new or unverified contracts may
  not apply to them. One of them, Radiant's BNB Chain lending pool, was on the rescue scan's list of known
  safe spenders (`services/rescue_service.py`) while this set labels it drained; it has been taken off
  that list, so approvals to it are assessed like any other contract's.
- Safe means listed by a major exchange, liquid and at least a year old, not audited. It includes meme and
  fee-on-transfer tokens (BabyDoge, for example) that a tax or honeypot check may flag.
- 65 safe entries are not ERC-20 tokens: the 63 Uniswap deployment contracts and the PancakeSwap and 1inch
  routers. Like drainers, they may score unknown, so the false positive rate's denominator may be nearer
  the 194 safe tokens than all 259 entries. Some of these routers are on ShieldBot's router allowlist or
  `utils/scam_db.py`'s protected set, but neither reaches the benchmark scan: the allowlist is read only
  when a transaction's calldata is decoded, and `eval/live_scorer.py` passes none; the protected set only
  refuses community blacklisting.
- 31 impostor tokens look like one deployment: the same bytecode, no owner, a fixed supply (1,000,000 for
  30 of them), pools created 2026-07-11 to 2026-07-14. GeckoTerminal reports reserves of $2 million to $1
  billion for them, which look mispriced; the evidence quotes them as GeckoTerminal reports them.

## Classes without entries, and what was tried

- `honeypot`: the evidence must be sells by real holders that reverted. Reverted transactions emit no
  logs, so finding them needs every receipt of a block range, and publicnode refuses receipts a few
  thousand blocks back on BNB Chain. Simulators (honeypot.is, GoPlus, TokenSniffer) are scoring inputs.
- `rug_pull`: the evidence must be the liquidity removal by the deployer or owner. Revoke.cash's incidents
  in which the team itself took the funds (402bridge, Harvest Keeper, StableMagnet) name approved
  spenders, filed under that class, not liquidity removals; naming a token's deployer needs an explorer,
  which is a scoring input. Forta's datasets were rejected above.
- `fake_claim`: Scam Sniffer lists 355,248 domains and 4,607 addresses with nothing tying a page to the
  contract it asks users to sign, and finding that means opening the phishing page, which this work does
  not do.

## Re-checking the on-chain facts

```bash
python -m eval.verify_onchain --dataset eval/data/benchmark_v2.json
```

It re-reads every fact the `onchain` sources state (code size, `symbol()` and `name()`, Transfer logs, and
for each poisoning transfer the transaction's sender, which must not be the tokens' owner), prints each
one that differs or that the RPC would not answer, and exits non-zero if there is any. On 2026-09-24 it
read 1,377 facts for all 650 entries: none differed. `1rpc.io/matic` refused the 10 Polygon transaction
reads (HTTP 410, 429, then "You've reached the usage limit for your current plan"); with
`--rpc 137=https://polygon-bor-rpc.publicnode.com` all 1,377 were read and none differed. Run it before
recording scores, and mark an entry whose facts no longer hold as stale. Free RPCs refuse old logs:
publicnode calls a `getLogs` a few thousand blocks back an archive request. The poisoning logs therefore
cite RPCs that served old logs on 2026-09-24 (`rpc.mevblocker.io`, `rpc-bsc.48.club`, `mainnet.base.org`,
`1rpc.io/matic`, `arb1.arbitrum.io/rpc`); if one stops, point the chain at an archive node with
`--rpc 56=https://...`.

## Classes and the evidence each needs

A malicious label must rest on evidence that ShieldBot's score does not already use.

- `honeypot`: a token whose holders cannot sell. Evidence: reverted sell transactions by real holders on
  chain. A simulator's verdict (honeypot.is, GoPlus, or ShieldBot's own simulation) does not qualify.
- `rug_pull`: liquidity pulled by the deployer or owner. Evidence: the transaction that removed or
  burned the liquidity.
- `drainer_contract`: a contract on a public drainer or phishing address list. Evidence: the list entry
  and contract code at the address.
- `approval_drainer_spender`: an address victims approved (`approve`, `permit`, Permit2) that then pulled
  their funds. Evidence: a victim's approval and the transfer that used it, or a curated incident list
  that names the address.
- `address_poisoning`: an address made to look like one its victim uses. The entry's `counterpart` names
  the imitated address. Evidence: the poisoning transfer and the real transfer it imitates.
- `impostor_token`: a token carrying an official asset's symbol or name at another address. Evidence: the
  issuer's official list and the token's `symbol()` and `name()`.
- `fake_claim`: the contract behind a fake airdrop or claim page. Evidence: a phishing list entry for the
  page and the call it asks users to sign.
- `safe`: widely used, long-lived contracts.

## Format rules

`eval/dataset.py` enforces these when a v2 file is loaded and refuses the file if any entry breaks them:

- Every entry has a `class`, a `chain_id`, an `address` and a `labeled` date (`YYYY-MM-DD`).
- Every malicious entry has at least one source. Every source has a `provider`, an `https` `url`, a
  `retrieved` date and the `evidence` it gives, and its provider must be on the accepted list
  (`LABEL_PROVIDERS`, compared without regard to case): `onchain` (a direct RPC read), `scamsniffer`,
  `revokecash`, `robinhood`, `uniswap`, `pancakeswap` and `geckoterminal`. Any other provider is refused.
  None of these is read by anything that computes ShieldBot's score (GoPlus, honeypot.is, TokenSniffer,
  DexScreener, Ethos, Tenderly, Etherscan, Blockscout, Sourcify, MetaMask's phishing list); add a provider
  to the list, and to the table above, only after checking that.
- An `address_poisoning` entry needs its `counterpart`. An address appears at most once per chain.
- An entry whose label no longer holds gets `"stale": {"date": ..., "reason": ...}`. It stays in the file
  and is left out when the file is loaded. v1 marks two honeypots this way.

## Recording scores and computing results

1. Record scores (network, the service's API keys):

   ```bash
   python -m eval.live_scorer --dataset eval/data/benchmark_v2.json --output eval/data/live_scores.json
   ```

   Each entry gets `status` `ok` (the scan completed), `unknown` (the scan reported incomplete coverage)
   or `error` (it failed), with its `score` and `risk_level` when the scan gave them. Nothing is filled
   in for a missing score. The file (`shieldbot-scores/1`) names the git revision that ran
   (`git rev-parse HEAD`), whether tracked files had local changes (untracked files do not count), when
   it ran, and the dataset's hash.
   Where the code is not a git checkout, pass `--revision <40-character revision>`; local changes are
   then recorded as unknown (`null`).

2. Compute the results, offline:

   ```bash
   python -m eval.cli --dataset eval/data/benchmark_v2.json --scores eval/data/live_scores.json \
       --out eval/results/<YYYY-MM-DD>-<revision>.json
   ```

   Create `eval/results/` first if it does not exist. The command refuses to run without `--scores`, and
   refuses scores that do not name a revision, that hold a malformed record (a missing or non-finite
   score where the scan completed, for example) or the same address twice on one chain, or that were
   recorded against a different dataset file. The same inputs always give the same file.

The results file (`shieldbot-benchmark-results/1`) carries `scored_at` and `revision` from the scores,
`dirty`, the dataset's path and hash, the scores' hash, the `threshold`, an `overall` block, one block
per class and one `details` row per entry. Hashes are SHA-256 of the JSON with sorted keys and no
whitespace, so they do not depend on line endings.

## What the numbers mean

- **Flagged**: a decided score at or above the threshold (default 50, as in v1).
- **Decided** and **unknown**: an entry is decided when its scan's status is `ok`. An `unknown` or
  `error` scan, or an entry with no record, is unknown. Unknown is never counted as passed or flagged.
- **Recall** (a malicious class): flagged / decided.
- **Precision** (a malicious class): flagged / (flagged + flagged safe entries), the precision the flag
  would have on that class and the safe entries alone. It depends on the size of the safe set, so only
  compare it between results for the same dataset revision.
- **False positive rate** (the safe class): flagged / decided.
- **Unknown rate**: unknown / entries. Read recall next to it: a high recall over few decided entries
  says little.
- `null` means the rate has no denominator (no entries, or none decided).

## Extending the dataset

1. Add entries to `data/benchmark_v2.json` that follow the rules above, each with the evidence you
   checked and the date you checked it. Prefer sources that name a transaction or a list revision.
2. State every new `onchain` fact in a form `verify_onchain.py` reads, and run it.
3. Update `version`, the `description`'s counts (the tests check them against the file) and the size
   table above. `tests/test_benchmark_v2.py` holds each class's minimum and the safe share (35 to 45%).
4. Re-check labels when you add entries, and mark any that no longer hold as stale rather than
   deleting them.
5. Run `python -m pytest tests/test_benchmark_v2.py tests/test_benchmark_verify_onchain.py tests/test_evaluation.py`.

No CI job runs the benchmark itself: recording scores needs the network and API keys. The format and
results tests run offline with the main suite.
