# WP4: guard-gated USDG transfer

Original WP4 implementation: `3c589276b17de5b9a9e8bd09c62d2a851af8751f` on `build/oh-usdg`.
WP9 adds exact-credit enforcement on `build/oh-integration`.

`ShieldBotGuardedTransfer` pins the guard, subject token, USDG token and recipient at construction.
Its sole state-changing entry point is `transfer(uint256 amount, uint64 maxAge)`. The caller first
approves this contract on the pinned USDG token, then requests a positive amount and a publication-age
tolerance. The contract checks `guard.requireAllowed(subject, maxAge)` before calling
`usdg.safeTransferFrom(msg.sender, recipient, amount)`. Immediately before and after that transfer it
reads the recipient's balance; only an increase of exactly `amount` permits `GuardedTransfer` emission.

An allowed verdict means the latest recorded LOW or MEDIUM meets the caller's publication-age
tolerance at this transaction's timestamp. It does not establish token safety or observation freshness.
The registry sets `Record.timestamp = block.timestamp` when the recording transaction executes.
The publisher's observation-age cutoff only controls broadcast; an already broadcast transaction can
land arbitrarily later. Observation age is not bounded on-chain. The guard,
registry/recorder, timestamp assumptions and USDG implementation remain trusted dependencies. The
constructor rejects zero addresses; it does not authenticate those dependencies.

Use **600 seconds for the demo only with `GUARD_WATCH_MAX_SUBJECTS=1`**: `subject` is a single immutable
address, and the demo watches exactly that address. Use **900 seconds as the production minimum at the
default four subjects**. Coordinator measurements: healthy ages typically **320–360 s**, healthy worst
**~437 s**, four subjects bunched after restart **~625 s**, one lost interval **~740 s**. `maxAge = 300`
would deny a perfectly healthy token for roughly **6–30% of wall time**; Foundry's `MAX_AGE = 300` is a
test fixture, not guidance. These supplied measurements were not repeated live in WP9. Neither window
is a proven availability bound; repeated failures or delayed inclusion can exceed it. Only actively
watched subjects receive recurring refreshes; see the
[bounded watched set and exact trust model](VERDICT_GUARD.md#publication-freshness-and-the-watched-set).
Uninterrupted permission is not promised.

There is no routing, swap, Permit2, owner, upgrade mechanism, payable entry point, receive/fallback,
or recovery function. Transfers go directly from the caller to the recipient. Unsolicited balances
cannot be claimed through this contract. The caller cannot supply another source wallet or destination.

## External calls and exact-credit semantics

The guard call is a STATICCALL. The ERC-20 transfer is an external call that can execute callbacks.
The OpenZeppelin 5.6.1 storage-based `ReentrancyGuard` explicitly rejects nested transfer executions.
It is not strictly required to protect shared custody accounting here: there is none, every invocation
checks the guard first, and the token source is that invocation's `msg.sender`. A direct callback from
the token therefore cannot name the original caller as its source. This reasoning does not make
arbitrary token code honest; the lock blocks reentry, not malicious token balance manipulation.

Non-exact delivery reverts with `ShortDelivery(uint256 requested, uint256 delivered)`. `amount` means
the same units in the call and event, and an indexer summing events cannot count a successful short
delivery. The 1% fee mock now proves reversion, unchanged balances/allowance and no `GuardedTransfer`
event. Excess delivery is rejected too. SafeERC20 rejects false returns atomically and accepts
successful empty returns only if the recipient-credit invariant also passes. A balance decrease or
zero net increase reports `delivered = 0` and reverts; the unsigned error field never wraps.

The recipient must be an **EOA or passive contract**. A recipient hook that forwards funds onward
during the transfer reduces its measured net credit and trips the check. The invariant trusts the
pinned token's `balanceOf`; it cannot make a dishonest token report truthful balances.

The coordinator supplied a live Paxos USDG observation on chain 4663: funding a fresh address through
the `balanceData` slot and transferring 500,000 units credited exactly 500,000, with no transfer fee.
WP9 did not repeat that live probe. The check closes non-exact behavior in third-party deployments
that pin another token while preserving exact-credit transfers for the intended pin.

## Historical WP4 local validation

The results below describe the original transfer implementation, before WP9's exact-credit change.
For current tests, sizes, Slither and regenerated gas snapshots, see [TESTING.md](../../docs/TESTING.md).

Tools: Forge 1.7.1, Solidity 0.8.28, optimizer 200 runs, Cancun; Slither 0.11.5.
Verified dependency revisions: OpenZeppelin `5fd1781b` (package version 5.6.1), forge-std `620536fa`,
EAS `d223e172`. The real guard and registry are used in every integration test; only ERC-20s are mocked.

The unchanged baseline completed with 83 passing tests. Final command, from `contracts/base`:

```text
forge test --offline -vv

[PASS] testFuzz_Transfer_MovesIfAndOnlyIfGuardAllows(uint8,uint64,uint64,uint256,bool,bool) (runs: 10000, μ: 107721, ~: 60072)
[PASS] test_Transfer_ExpiredDeniesBeforeTokenCall() (gas: 145298)
[PASS] test_Transfer_FutureTimestampDeniesBeforeTokenCall() (gas: 145063)
[PASS] test_Transfer_HighDeniesBeforeTokenCall() (gas: 144862)
[PASS] test_Transfer_HoneypotDeniesBeforeTokenCall() (gas: 144937)
[PASS] test_Transfer_NoRecordDeniesBeforeTokenCall() (gas: 51178)
[PASS] test_Transfer_UnknownDeniesBeforeTokenCall() (gas: 144893)
[PASS] test_Transfer_ReentrancyBlockedWithoutDoubleTransferOrDrain() (gas: 1307295)
Suite result: ok. 26 passed; 0 failed; 0 skipped; finished in 501.66ms (572.97ms CPU time)

[PASS] invariant_EvidenceExistsIfAndOnlyIfSubjectWasRecorded() (runs: 256, calls: 128000, reverts: 0)
[PASS] invariant_TotalRecordsEqualsSumOfSubjectCounts() (runs: 256, calls: 128000, reverts: 0)
Ran 6 test suites in 84.69s (150.02s CPU time): 109 tests passed, 0 failed, 0 skipped (109 total tests)
forge test exit: 0
```

The 26 added tests cover all six denial reasons, zero tolerance/amount, exact expiry, fresh LOW/MEDIUM,
immutable values, each zero constructor address, insufficient balance/allowance, caller isolation,
stranded balances, reentrancy, fees, false/empty ERC-20 returns, event fields and nonpayable/fallback
rejection. Fuzzing varies verdict, age, tolerance, amount, record existence and future publication.
The iff invariant is explicitly scoped to positive, funded, approved amounts and an ordinary ERC-20;
zero amounts and token-side failures have separate tests.

Every denial test asserts unchanged caller/recipient/contract balances and allowance **and zero
`transferFrom` calls**. Reverted balances alone cannot prove call ordering. Two temporary mutations
were tested and then fully restored:

- Moving the guard after the transfer: all seven denial-order tests failed with
  `expected ... to be called 0 times, but was called 1 time`; restored code passed all seven.
- Removing `nonReentrant`: the attacker test failed; restored code passed all 26 added tests.
  The malicious token funds and approves its nested sender, so the lock is what stops that transfer.

`forge fmt --check src/ShieldBotGuardedTransfer.sol test/ShieldBotGuardedTransfer.t.sol` exited 0.
`git diff --cached --check` passed. Formatting was checked on the new files as requested; protected
existing sources were not normalized.

`forge build --offline --sizes` exited 0 with no compiler warnings:

```text
Compiling 2 files with Solc 0.8.28
Solc 0.8.28 finished in 1.70s
Compiler run successful!

| Contract                 | Runtime Size (B) | Initcode Size (B) | Runtime Margin (B) | Initcode Margin (B) |
| ShieldBotGuardedTransfer | 1,140            | 1,543             | 23,436             | 47,609              |
```

The LOW permitted-path measurement is persisted in `snapshots/ShieldBotGuardedTransferTest.json`:

```text
permitted LOW transfer (cold callee gas): 55906
```

`vm.snapshotGasLastCall` measures the transfer callee, including the nested guard/registry and ERC-20
calls, after cooling all four contract accounts/storage. The recipient starts with zero tokens and
the caller has a finite allowance. This excludes outer-call overhead and transaction intrinsic gas;
it is local Cancun execution with the ordinary mock ERC-20, not live USDG gas or an Orbit fee estimate.

## Slither

From the repository root, the same forced-solc command was used on the unchanged guard and registry,
then on the new transfer:

```powershell
& C:/Users/gudma/AppData/Roaming/Python/Python312/Scripts/slither.exe contracts/base/src/ShieldBotGuardedTransfer.sol --compile-force-framework solc --solc C:/Users/gudma/AppData/Roaming/svm/0.8.28/solc-0.8.28 --solc-remaps '@openzeppelin/=contracts/base/lib/openzeppelin-contracts/ forge-std/=contracts/base/lib/forge-std/src/' --exclude-informational --fail-high
```

All three invocations exited 0. The new contract's output:

```text
Detector: missing-zero-check
Ownable2Step.transferOwnership(address).newOwner
(contracts/base/lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol#43)
lacks a zero-check on:
  _pendingOwner = newOwner (#44)

contracts/base/src/ShieldBotGuardedTransfer.sol analyzed (12 contracts with 80 detectors), 1 result(s) found
```

That is the unchanged low-severity pending-ownership cancellation finding. No new findings or
suppressions were introduced.

## Execution boundary and remaining uncertainty

No deployment, transaction broadcast, signing, private-key access, push or PR was performed. The
existing deployment-script tests ran only in Foundry's local test VM. Registry/guard sources and
Python files were not edited; the deployment-output file was never read.

The first `forge test --offline` unexpectedly initiated a remote Git dependency clone because this
worktree's dependencies were absent. It was stopped; this was a deviation from the no-remote-access
instruction. Dependencies were subsequently populated from the adjacent local worktree at the exact
pinned revisions, and their Git metadata was repaired locally. No further network access was used.

Live USDG bytecode, token fees, deployment addresses and actual mainnet transaction fees were not
verified. The local permitted/refused integration is complete; a mainnet demonstration remains a
separately authorized task. This record also serves as the session handoff within the permitted
`contracts/base/` write scope.
