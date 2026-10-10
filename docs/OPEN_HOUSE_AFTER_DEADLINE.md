# Arbitrum Open House: changes after the submission deadline

## What was submitted

The HackQuest submission is the [`open-house-submission`](https://github.com/Ridwannurudeen/shieldbot/tree/open-house-submission) tag, commit `a580654`, committed on 4 October 2026 at 14:37 UTC. The submission window closed on 4 October 2026 at 15:59 UTC. The submission is the tag; everything listed below came after it.

## Production since the deadline

| Revision | Date (UTC) | Change |
|---|---|---|
| `2315085` | 2026-10-04 | Skips market and honeypot checks that do not apply to exact official tokens, avoiding an UNKNOWN verdict caused by that coverage gap. |
| `6d5df88` | 2026-10-04 | Corrects the grammar in the official token coverage note. |
| `c3554ac` | 2026-10-04 | Deploys hookless USDG pool support, Telegram's not applicable wording, pinned simulator outcomes, and one RPC batch for a token's pools. |
| `dd47f2f` | 2026-10-04 | Prints rescue alert hints one per line and removes an unavailable revoke hint; the other merged pull request changes documentation. |
| `3dea0aa` | 2026-10-04 | Reverts three simulator changes after a measured Robinhood RPC rate limit regression. |
| `f1c2af7` | 2026-10-05 | Restores hookless USDG simulation without pool batching, including official stock tokens when a pool resolves. |
| `302eb66` | 2026-10-05 | Adds a five second timeout for optional second node simulations, then falls back to the official node. |

Production has run `302eb66` since 5 October 2026 and has not been redeployed. The next deployment will follow the Open House result on 12 October 2026. Deployment notes are in [SUBMISSION.md](SUBMISSION.md).

## Every commit on main after the deadline

The first-parent history of `origin/main` contains 33 commits after the submission tag. The first is `2315085` at 16:01 UTC, two minutes after the close. No first-parent commit fell between the tag and the close.

### Live in production (20)

| Time (UTC) | SHA | Area | Subject |
|---|---|---|---|
| 2026-10-04 16:01 | `2315085` | backend, tests, docs | fix(4663): judge official Robinhood Chain tokens by the checks that apply to them |
| 2026-10-04 16:35 | `0f1c326` | docs | docs: production runs 2315085, known Robinhood Chain tokens judged by the checks that apply |
| 2026-10-04 17:21 | `6d5df88` | backend, tests | fix(4663): say 'market-pair checks do not apply', not 'does' |
| 2026-10-04 17:23 | `15af2e6` | docs | docs: production runs 6d5df88, the official-token note's verb corrected |
| 2026-10-04 17:52 | `83c4fd7` | backend, tests, docs | feat(4663): support hookless USDG pools |
| 2026-10-04 17:54 | `2fc0392` | backend, tests | fix(telegram): show skipped categories as not applicable |
| 2026-10-04 18:23 | `2e160d1` | tests | test(4663): pin simulator outcomes before batching |
| 2026-10-04 18:36 | `c3554ac` | backend, tests | perf(4663): simulate a token's pools in one RPC batch |
| 2026-10-04 19:07 | `fb5c3d3` | docs, extension | Merge pull request #16 from Ridwannurudeen/docs/judge-navigation |
| 2026-10-04 19:07 | `dd47f2f` | backend, tests | Merge pull request #15 from Ridwannurudeen/fix/rescue-hint-list |
| 2026-10-04 19:25 | `d9b923c` | docs | docs: production runs dd47f2f, with the c3554ac deployment noted |
| 2026-10-04 19:32 | `79746b3` | backend, tests | Revert "perf(4663): simulate a token's pools in one RPC batch" |
| 2026-10-04 19:32 | `74acc77` | tests | Revert "test(4663): pin simulator outcomes before batching" |
| 2026-10-04 19:32 | `3dea0aa` | backend, tests, docs | Revert "feat(4663): support hookless USDG pools" |
| 2026-10-04 20:03 | `d92c389` | docs | docs: production runs 3dea0aa, the simulator revert, with the measured rate-limit regression |
| 2026-10-04 21:29 | `c8aac19` | backend, tests, docs | feat(4663): support hookless USDG pools |
| 2026-10-04 21:29 | `f1c2af7` | tests | test(4663): pin simulator outcomes before batching |
| 2026-10-05 07:06 | `03720cf` | docs | docs: production runs f1c2af7, hookless USDG pools back without the batched simulation |
| 2026-10-05 12:50 | `0ad9c17` | backend, tests, deploy | feat(4663): send simulations to an optional faster node, falling back to the official one |
| 2026-10-05 12:52 | `302eb66` | backend, tests | fix(4663): give the simulation node a 5 s timeout so a hang falls back fast |

### On main only, not deployed (13)

| Time (UTC) | SHA | Area | Subject |
|---|---|---|---|
| 2026-10-05 13:54 | `86e4dd6` | docs | docs: production runs 302eb66, simulations on a second node with an official fallback |
| 2026-10-05 17:43 | `21e2869` | extension, tests | fix(extension): report a stopped request as EIP-1193 4001, and say incomplete once |
| 2026-10-05 21:44 | `e23ac00` | extension, tests | fix(extension): say an unsupported network in plain words, not the API's refusal |
| 2026-10-05 21:54 | `f1a0d5c` | docs | docs: the store disclosure describes 3.1.0, which reads the wallet's chain |
| 2026-10-05 22:19 | `9d2efc1` | docs | docs: 3.1.0 is in Chrome Web Store review, name the submission tag, and state hookless USDG support |
| 2026-10-05 22:27 | `12a5d63` | docs | docs(store): drop the chain-name list from the store description after the keyword-spam rejection |
| 2026-10-06 06:32 | `84f8b6a` | docs | docs: link the extension 3.1.0 release zip from the README and the judge guide |
| 2026-10-06 07:05 | `b6ee1a4` | docs | docs: 3.1.0 has been tested with Rabby; MetaMask is still untested |
| 2026-10-07 17:24 | `2acebf2` | deploy, site, tests | feat(site): serve a custom 404 page |
| 2026-10-07 17:24 | `cfb4624` | site | feat(site): add link preview tags to the policy pages |
| 2026-10-08 11:38 | `bbd48dd` | deploy, tests | test(site): tighten the 404 checks and give the 404 note its own section |
| 2026-10-10 12:17 | `c7a90cb` | backend, docs, site, tests | Merge pull request #17 from Ridwannurudeen/docs/colosseum-accuracy |
| 2026-10-10 12:17 | `cad9130` | backend, tests | Merge pull request #18 from Ridwannurudeen/fix/robinhood-usdg-sell-revert |

The `services/robinhood_assets.py` change in `c7a90cb` is a docstring edit. Its substantive changes are documentation and website source. `cad9130` adds `v4-usdg` to `TOKEN_REFUSED` and its regression test; it is not deployed.

## Browser extension

The Chrome Web Store has served version 3.1.0 since about 7 October 2026, built from the `extension-v3.1.0` tag at `12a5d63`. Compared with the submitted tag, that build includes two post-deadline code fixes: `21e2869` reports a stopped request as EIP-1193 4001 and says incomplete once; `e23ac00` explains an unsupported network in plain words. The extension log also shows `3bbf0dc`, which changes only `extension/README.md`. Someone who installs from the store runs the two post-deadline code fixes.

## Check it yourself

Run with `TZ=UTC` in the worktree. For each SHA from the first command, the ancestry check identifies whether it is included in production. The path diff shows the files used to assign areas.

```bash
export TZ=UTC
git log --first-parent --reverse --format='%cd %h %s' --date=format-local:'%Y-%m-%d %H:%M' open-house-submission..origin/main
for sha in $(git rev-list --first-parent --reverse open-house-submission..origin/main); do
  if git merge-base --is-ancestor "$sha" 302eb66; then
    printf '%s live in production\n' "$(git rev-parse --short "$sha")"
  else
    printf '%s on main only\n' "$(git rev-parse --short "$sha")"
  fi
  git diff --name-only "$sha^1" "$sha"
done
git diff --stat open-house-submission extension-v3.1.0 -- extension/
git log --format='%h %s' open-house-submission..extension-v3.1.0 -- extension/
```
