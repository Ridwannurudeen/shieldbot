# ShieldBot accuracy benchmark

This folder measures how ShieldBot's risk score separates labelled malicious addresses from safe ones.
It has no published result yet: the v2 dataset below is a seed, and no scores have been recorded
against it.

| File | What it is |
|---|---|
| `data/benchmark_v2.json` | The v2 dataset (`shieldbot-benchmark/2`): one class per entry, independent sources, dates. |
| `data/benchmark_v1.json` | The v1 dataset: 34 addresses, 2 of them marked stale. Its 14 honeypot labels came from honeypot.is, a provider ShieldBot scores with, so v1 measures agreement with that provider, not accuracy. |
| `live_scorer.py` | Scans every entry with the real analysis pipeline (network and API keys) and records the scores. |
| `cli.py` | Computes the results file from recorded scores, offline. |

## Size on 2026-09-24

The v2 seed holds **38 entries, and 3 of its 8 classes have entries**. That is far too few for its
rates to mean much: with 3 impostor tokens, one miss moves that class's recall by 33 points.

| Class | Entries | Where the labels come from |
|---|---|---|
| `honeypot` | 0 | |
| `rug_pull` | 0 | |
| `drainer_contract` | 15 | Scam Sniffer's open blacklist of addresses associated with phishing (pinned to commit `929fe790`), and `eth_getCode` on Ethereum showing contract code |
| `approval_drainer_spender` | 0 | |
| `address_poisoning` | 0 | |
| `impostor_token` | 3 | Robinhood's official stock token list, `symbol()` and `name()` read on Robinhood Chain, and GeckoTerminal's listing |
| `fake_claim` | 0 | |
| `safe` | 20 | The v1 blue-chip tokens and routers on BNB Chain, Ethereum and Base, labelled 2026-02-18 |

The drainer entries are every contract among the first 120 addresses of Scam Sniffer's list on
2026-09-24 (`eth_getCode` on Ethereum at block 26,046,855; EOAs and EIP-7702 delegations left out).
Scam Sniffer describes the list as "addresses associated with phishing activities", published with a
7-day delay; the class records that the listed address is a contract.

## Classes and the evidence each needs

A malicious label must rest on evidence that ShieldBot's score does not already use.

- `honeypot`: a token whose holders cannot sell. Evidence: reverted sell transactions by real holders on
  chain. A simulator's verdict (honeypot.is, GoPlus, or ShieldBot's own simulation) does not qualify.
- `rug_pull`: liquidity pulled by the deployer or owner. Evidence: the transaction that removed or
  burned the liquidity.
- `drainer_contract`: a contract on a public drainer or phishing address list. Evidence: the list entry
  and contract code at the address.
- `approval_drainer_spender`: an address victims approved (`approve`, `permit`, Permit2) that then pulled
  their funds. Evidence: a victim's approval and the transfer that used it.
- `address_poisoning`: an address made to look like one its victim uses. The entry's `counterpart` names
  the imitated address. Evidence: the poisoning transfer.
- `impostor_token`: a token carrying an official asset's symbol or name at another address. Evidence: the
  issuer's official list and the token's `symbol()` and `name()`.
- `fake_claim`: the contract behind a fake airdrop or claim page. Evidence: a phishing list entry for the
  page and the call it asks users to sign.
- `safe`: widely used, long-lived contracts.

## Format rules

`eval/dataset.py` enforces these when a v2 file is loaded and refuses the file if any entry breaks them:

- Every entry has a `class`, a `chain_id`, an `address` and a `labeled` date (`YYYY-MM-DD`).
- Every malicious entry has at least one source, and every source has a `provider`, an `https` `url`, a
  `retrieved` date and the `evidence` it gives. No source may be a provider ShieldBot scores with:
  goplus, honeypot.is, tokensniffer, dexscreener, ethos, tenderly, etherscan, blockscout or shieldbot
  (`SCORING_PROVIDERS`). Provider `onchain` means a direct RPC read.
- An `address_poisoning` entry needs its `counterpart`. An address appears at most once per chain.
- An entry whose label no longer holds gets `"stale": {"date": ..., "reason": ...}`. It stays in the file
  and is left out when the file is loaded. v1 marks two honeypots this way.

ShieldBot's Robinhood Chain impostor check, where it is deployed, reads the same official Robinhood list.
It labels a scan and does not change the score, so the score measured here stays independent of it; a
future metric of the impostor label itself would not be.

## Recording scores and computing results

1. Record scores (network, the service's API keys):

   ```bash
   python -m eval.live_scorer --dataset eval/data/benchmark_v2.json --output eval/data/live_scores.json
   ```

   Each entry gets `status` `ok` (the scan completed), `unknown` (the scan reported incomplete coverage)
   or `error` (it failed), with its `score` and `risk_level` when the scan gave them. Nothing is filled
   in for a missing score. The file (`shieldbot-scores/1`) names the git revision that ran
   (`git rev-parse HEAD`), whether the tree had local changes, when it ran, and the dataset's hash.
   Where the code is not a git checkout, pass `--revision <40-character revision>`; local changes are
   then recorded as unknown (`null`).

2. Compute the results, offline:

   ```bash
   python -m eval.cli --dataset eval/data/benchmark_v2.json --scores eval/data/live_scores.json \
       --out eval/results/<YYYY-MM-DD>-<revision>.json
   ```

   Create `eval/results/` first if it does not exist. The command refuses to run without `--scores`,
   refuses scores that do not name a revision, and refuses scores recorded against a different dataset
   file. The same inputs always give the same file.

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
2. Update `version`, the `description`'s counts, the size table above and the counts in
   `tests/test_benchmark_v2.py`, which pins them so the file, this page and the tests agree.
3. Re-check labels when you add entries, and mark any that no longer hold as stale rather than
   deleting them.
4. Run `python -m pytest tests/test_benchmark_v2.py tests/test_evaluation.py`.

No CI job runs the benchmark itself: recording scores needs the network and API keys. The format and
results tests run offline with the main suite.
