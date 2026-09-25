# Local test results and reproduction

Measured on **2026-09-22**. Start with [JUDGE_GUIDE.md](JUDGE_GUIDE.md) for the offline honeypot replay and real-contract transfer demonstration.

## Measured results

| Check | Command / scope | Result |
|---|---|---|
| Integrated Python baseline | `python -m pytest tests/ -q -p no:cacheprovider --ignore=tests/test_bot_app.py` | **2917 passed, 1 skipped**, 4 warnings, 111.80 s |
| Hunter/rescan regression subset | `tests/test_guard_rescan.py tests/test_hunter.py tests/test_hunter_rpc_guard.py tests/test_hunter_verdicts.py tests/test_verdict_hunter_path.py` with `python -m pytest ... -q -p no:cacheprovider` | **93 passed**, 1 warning, 5.10 s |
| Robinhood simulation and USDG | `python -m pytest tests/test_robinhood_simulation.py tests/test_robinhood_simulation_usdg.py -q -p no:cacheprovider` | **192 passed**, 1 warning, 2.44 s |
| Judge-guide proven honeypot | `test_live_honeypot_is_proven_unsellable` and `test_4663_proven_honeypot_is_flagged_through_the_analyzer` in `tests/test_robinhood_simulation.py` | **2 passed**, 1 warning, 1.97 s |
| Python SDK | `python -m pytest sdk/python/tests/ -q -p no:cacheprovider` | **21 passed**, 3.17 s; separate from baseline |
| Foundry full suite | From `contracts/base`: `forge test --offline -vv` | **114 passed, 0 failed, 0 skipped**, 39.42 s |
| Judge-guide transfer cases | Exact Foundry command in [the guide](JUDGE_GUIDE.md#on-chain-transfer-demonstration-offline) | **4 passed, 0 failed, 0 skipped** |
| Contract size build | `forge build --offline --sizes` | **Exit 0**; guard runtime 1,048 B, transfer runtime 1,616 B |
| Touched Solidity formatting | `forge fmt --check src/ShieldBotVerdictGuard.sol src/ShieldBotGuardedTransfer.sol test/ShieldBotVerdictGuard.t.sol test/ShieldBotGuardedTransfer.t.sol` | **Exit 0** |

Real full-suite summaries:

```text
2917 passed, 1 skipped, 4 warnings in 111.80s (0:01:51)
Ran 7 test suites in 39.42s (71.02s CPU time): 114 tests passed, 0 failed, 0 skipped (114 total tests)
```

Both unchanged allowed-iff fuzz properties passed **10,000 runs each**. Both registry invariants passed **256 runs / 128,000 calls / zero reverts each**. The three reason-precedence regressions and fee/excess-delivery regressions failed against the old implementation before passing with the fixes. The LOW expiry/future denial tests remain unchanged and pass. New tests also cover exact credit to an already funded recipient and rejection of self-transfer with zero net credit.

Both per-contract gas snapshots were regenerated: `check_cold_registry = 6985`, `check_warm_registry = 2985`, and `transfer_low_cold = 58013`. These are local Cancun callee-gas measurements under the existing test setup, not live USDG gas or Orbit fees. The guard's registry account is warm in both measurements; its record slots are cold then warm. The transfer measurement cools all four accounts and starts with a zero recipient balance and finite allowance.

Do not add subset counts to the baseline. The baseline explicitly selects `tests/`, excluding `sdk/python/tests/` even though both are default paths in `pytest.ini`. Add Foundry to PATH before running its commands: Bash `export PATH="$HOME/.foundry/bin:$PATH"`; PowerShell `$env:PATH = "$HOME/.foundry/bin;$env:PATH"`.

## Static analysis across all five contracts

Slither **0.11.5**, `--exclude-informational --fail-high`, with Solidity **0.8.24** for the verifier and **0.8.28** for the other four. Every invocation exited **0**.

| Contract | Actual analyzer summary | Findings |
|---|---|---|
| `ShieldBotVerifier.sol` | 1 contract, 80 detectors, 0 results | None |
| `ShieldBotAttestor.sol` | 8 contracts, 80 detectors, 3 results | LOW OpenZeppelin `missing-zero-check`; two preexisting LOW `reentrancy-events` findings in `attest` and `revoke` |
| `ShieldBotVerdictRegistry.sol` | 4 contracts, 80 detectors, 1 result | Known LOW OpenZeppelin `missing-zero-check` |
| `ShieldBotVerdictGuard.sol` | 5 contracts, 80 detectors, 1 result | Same known OpenZeppelin finding |
| `ShieldBotGuardedTransfer.sol` | 12 contracts, 80 detectors, 1 result | Same known OpenZeppelin finding |

The OpenZeppelin finding is `Ownable2Step.transferOwnership(address).newOwner` lacking a zero check; zero cancels a pending ownership transfer. No new findings were introduced. The verifier, attestor and registry sources are unchanged from `fff633f`. The all-five run does **not** support a claim that the entire project has only the OpenZeppelin finding: the attestor's two LOW event-reentrancy findings also exist. They were not suppressed or changed.

The CI workflow explicitly analyzes both new contracts. To run the same check locally, with the same remaps and severity gate, from the repository root:

```bash
slither contracts/base/src/ShieldBotGuardedTransfer.sol --compile-force-framework solc --solc-remaps "@openzeppelin/=contracts/base/lib/openzeppelin-contracts/ forge-std/=contracts/base/lib/forge-std/src/" --exclude-informational --fail-high
```

Guard and registry use the same pattern. Attestor additionally maps `@eas/=contracts/base/lib/eas-contracts/contracts/`. The verifier uses `contracts/ShieldBotVerifier.sol`, the installed 0.8.24 compiler and no remaps.

## Qualifications

The requested Python selection excludes `tests/test_bot_app.py`; Telegram is absent locally, and the separate bot import case is skipped. This is not a passing claim for the excluded Telegram suite. Real Telegram delivery, live wallets and browser behavior were not tested.

Installed tools checked in this pass: Python **3.12.10**, pytest **8.3.3**, pytest-asyncio **1.3.0**, web3 **7.16.0**, eth-utils **6.0.0**, eth-abi **5.2.0**, httpx **0.28.1**, Forge **1.7.1**, Solidity **0.8.28**, Slither **0.11.5**. Several Python versions differ from `requirements.txt`; this is not a clean pinned-environment installation result. Python reports existing deprecation/configuration warnings. The touched-file formatting result does not assert an unqualified whole-checkout format pass across preexisting Windows line endings.

No live-chain test is part of these suites. The existing Python tests use fabricated cryptographic fixtures, including fixture-only signing; transport is mocked. Foundry deployment-script tests run only in its local VM.

The timing figures and the Paxos USDG exact-delivery observation were recorded earlier and were not re-probed live. The judge-guide Python classifier and Solidity consumer examples are separate offline checks; they do not establish a deployed end-to-end publication. The earlier synthetic receipt-verifier exercise is historical and was not rerun here.

## Manual checks still required

The owner must verify deployment addresses, source revision, a confirmed publication and the served evidence document before presenting the online judge path. Live `GET /api/stats` figures require an owner-supplied snapshot and timestamp. Familiar token names or addresses are not fixed expected-safe test cases: provider coverage can change the result.

The unreleased extension chain-identification repair still needs real MetaMask, Rabby and EIP-6963 tests, including chain switching and provider errors, followed by Chrome Web Store review. It is not part of the shipped-extension claim for this submission.
