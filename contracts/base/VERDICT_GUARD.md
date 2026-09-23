# Verdict guard: consumer policy and local validation

`ShieldBotVerdictGuard` lets a consuming contract enforce the registry's latest verdict in the
same transaction as its own action. It is ownerless, non-upgradeable and nonpayable, with an immutable
registry and no mutable storage. Each check makes exactly one `latestRecord(subject)` call.

## Consumer contract

- `check(address subject, uint64 maxAge) returns (bool allowed, uint8 reason)` is a view.
- `requireAllowed(address subject, uint64 maxAge)` is a view that reverts with
  `NotAllowed(address subject, uint8 reason)` on a policy denial.
- `registry()` returns the immutable registry. Construction rejects its zero address with `ZeroAddress()`.
- Registry read/ABI failures propagate as reverts. The constructor assumes the supplied nonzero address
  is the intended, trusted registry; it does not authenticate its code or recorder.

The consumer supplies `maxAge` in seconds on every call. There is no owner or default because a central
administrator should not choose or relax each consumer's publication-freshness tolerance. The scanner cannot promise
a chain-wide refresh cadence.

`maxAge == 0` **always denies**. For an existing non-adverse, non-future record it returns `EXPIRED`,
including at age zero. Missing, adverse and future reasons retain precedence. This keeps an unset
tolerance from silently accepting indefinitely old verdicts. Positive limits are
inclusive: publication age equal to `maxAge` passes the age check; `maxAge + 1` is expired.

Reasons are evaluated in this order: `NO_RECORD → HIGH/HONEYPOT → FUTURE_TIMESTAMP → EXPIRED → LOW/MEDIUM allowed → UNKNOWN`.
Reason precedence is informational on denial and does not change what is allowed. Expired LOW reports
EXPIRED because its permission lapsed; expired HONEYPOT still reports HONEYPOT rather than suggesting
that retrying later could resolve known adverse evidence. UNKNOWN has no adverse content and stays after expiry.

| Code | Reason | Meaning |
|---|---|---|
| 0 | ALLOWED | Recorded, non-future LOW or MEDIUM within the publication-age limit |
| 1 | NO_RECORD | Zero evidence hash; includes the zero subject |
| 2 | UNKNOWN | Recorded incomplete scan within the publication-age limit |
| 3 | HIGH | HIGH verdict regardless of publication age |
| 4 | HONEYPOT | HONEYPOT verdict regardless of publication age |
| 5 | EXPIRED | Non-adverse publication too old, or zero maxAge |
| 6 | FUTURE_TIMESTAMP | Non-adverse publication timestamp ahead of the check clock |

## Publication freshness and the watched set

Age is **publication age, not observation age**. `Record.timestamp` is `block.timestamp` when the
recording transaction executes. The publisher rejects observations older than 300 seconds before
broadcast, but an already broadcast transaction can land arbitrarily later. Observation age is not
bounded on-chain. Both the registry and the guard use the same sequencer-set `block.timestamp`. The
specified Arbitrum tolerance (roughly 24 hours past / 1 hour future) is an explicit trust assumption in
NatSpec, not a wall-clock publication-freshness guarantee. `observedBlock` and `block.number` never
participate in age arithmetic.

`core/database.py:update_verdict_onchain()` automatically admits qualifying confirmed chain-4663
subjects with a registry set and valid observation provenance, only while watch capacity remains.
`GUARD_WATCH_MAX_SUBJECTS` defaults to **4**. This deliberately small, bounded set shares the RPC
budget with discovery and launch scans; it is not chain-wide freshness coverage. Four subjects at the
300-second rescan target consume about 0.293 requests/second of the shared 1 request/second budget.

Inside the actively watched set, subjects are rescanned and verdicts re-published, allowing a finite
`maxAge` to keep being satisfied when publication succeeds in time. Outside it, a subject recorded
once eventually remains **denied for any finite `maxAge`**, unless a new record is
published or the subject is admitted and successfully refreshed. Sustained satisfaction of `maxAge`
depends on active watching; an initial confirmation alone does not provide it. Watch membership also
does not guarantee `ALLOWED`: rescans can produce UNKNOWN or adverse verdicts. Old LOW/MEDIUM/UNKNOWN
records report EXPIRED; HIGH/HONEYPOT retain their adverse reason. Admission and operator
controls are documented in [guard-rescans.md](../../docs/guard-rescans.md).

**Demo: `maxAge = 600` seconds requires `GUARD_WATCH_MAX_SUBJECTS=1`; production minimum: 900 seconds
at the default four subjects.** The demo watches exactly the guarded transfer's single immutable subject.
The timing figures are calculations, not on-chain observations. They use
`age = I + s + d(N+1) - d(N)`, with the 300 second rescan interval plus measured scan and publication
delays. Live scan p90 was about 5.4 seconds. The resulting ages are typically **320 to 360 seconds**,
about **437 seconds** in a healthy worst case, about **625 seconds** when four subjects bunch after a
restart, and about **740 seconds** after one lost interval. A `maxAge` of 300 seconds would deny a healthy
token for about **6 to 30 percent of wall time**. The Foundry `MAX_AGE = 300` constant is a test fixture,
not operating guidance. Confirm these calculations against live records after the registry, guard and
transfer contracts are deployed on Robinhood Chain. Neither window is an availability bound: delayed
inclusion and repeated failures can exceed it.
The [rescan notes](../../docs/guard-rescans.md#structural-denial-windows) explain lost pending intervals
and UNKNOWN publication after a scan overrun; choose a demo subject whose scans complete reliably.

## What ALLOWED means and who is trusted

For a positive `maxAge`, `ALLOWED` means exactly: some address holding the recorder role at the time
submitted LOW or MEDIUM with a nonzero 32-byte value for this subject; no later record exists; and the
sequencer clock says that publication was between zero and `maxAge` seconds ago. The publication time
is execution time, not the time the recorder broadcast the transaction. It does **not** mean that the
evidence document exists or hashes to `evidenceHash`, that the scan was recent, that the token's code
or state is unchanged since observation, that the token is safe, or that the recorder key was
uncompromised.

Accepting MEDIUM is a deliberate policy choice to tolerate moderate reported risk while denying
incomplete, HIGH and HONEYPOT verdicts. Consumers requiring LOW only must enforce that stricter verdict
policy separately; `maxAge` changes only the publication-age tolerance.

`Record` carries **no recorder identity and no epoch**. A compromised recorder key writes records
indistinguishable from honest ones to this guard. Rotating the recorder does not invalidate anything
already written: recovery means overwriting each affected subject with a new record from the trusted
recorder. The immutable registry address and its recorder authority remain trust dependencies.

## Historical validation on build/oh-guard

The measurements below describe the original guard implementation. For WP9 adverse-first validation,
regenerated gas snapshots and the integrated suite, see [current results](../../docs/TESTING.md).

Implementation commit: `6a6541dbe82825ddceb12cd982bf890eb027fe47`.

Local tools: Forge 1.7.1, Solidity 0.8.28, optimizer 200 runs, Cancun, Slither 0.11.5.
Dependencies were initialized from clean local copies at the repository's exact gitlink revisions:
forge-std 1.16.1 (`620536fa`), OpenZeppelin 5.6.1 (`5fd1781b`), EAS (`d223e172`).
No remote access, signing, or broadcast was used. Existing deployment-script tests execute only in
Foundry's local test VM. The registry source and Python files were not modified.

Baseline before implementation: 65 tests passed. Full-suite command: `forge test --offline -vv`.
Actual output excerpts:

```text
[PASS] testFuzz_Check_AllowedOnlyForFreshRecordedLowOrMedium(uint8,uint64,uint64,bool,bool) (runs: 10000, μ: 72589, ~: 118373)
[PASS] invariant_EvidenceExistsIfAndOnlyIfSubjectWasRecorded() (runs: 256, calls: 128000, reverts: 0)
[PASS] invariant_TotalRecordsEqualsSumOfSubjectCounts() (runs: 256, calls: 128000, reverts: 0)
Ran 5 test suites in 75.42s (76.37s CPU time): 83 tests passed, 0 failed, 0 skipped (83 total tests)
forge test exit: 0
```

The final comment-only lint annotations were followed by another guard-suite run:

```text
Ran 1 test suite in 195.81ms (192.81ms CPU time): 18 tests passed, 0 failed, 0 skipped (18 total tests)
```

All 18 new tests use the real registry. Future timestamps are tested by rewinding the test clock after
publication; no mock or storage patch is needed. Coverage includes every verdict at fresh/expired ages,
missing versus UNKNOWN, exact boundaries, zero maxAge, zero addresses, publication at timestamp zero,
independent consumer tolerances, latest-record replacement, both block-number domains, single registry
reads, no storage writes and rejection of value. The 10,000-case fuzz property additionally varies whether
the subject was recorded and whether its publication is in the future.

`forge build --offline --sizes` exited 0 with no warnings after local dependency initialization and the
documented timestamp lint annotations. Actual output excerpt:

```text
No files changed, compilation skipped
| Contract                 | Runtime Size (B) | Initcode Size (B) | Runtime Margin (B) | Initcode Margin (B) |
| ShieldBotAttestor        | 2,970            | 3,512             | 21,606             | 45,640              |
| ShieldBotVerdictGuard    | 1,048            | 1,218             | 23,528             | 47,934              |
| ShieldBotVerdictRegistry | 2,417            | 2,820             | 22,159             | 46,332              |
```

Measured LOW-path `check` gas using `vm.snapshotGasLastCall`:

```text
check cold registry (callee gas): 6881
check warm registry (callee gas): 2881
```

The registry **account is warm in both cases**; the two record slots are cold on the first call and warm
on the second. These are guard-callee measurements, including the nested registry read, excluding the
outer consumer call overhead and transaction intrinsic gas. They are local Cancun EVM gas, not an Orbit
fee estimate. The test asserts the 4,000-gas storage-access difference and persists the measured values
in `snapshots/ShieldBotVerdictGuardTest.json`.

## Formatting and static-analysis caveats

Actual formatting exits:

```text
Windows checkout forge fmt --check exit: 1
New files forge fmt --check exit: 0
LF verification copy forge fmt --check exit: 0
```

The nine pre-existing Solidity files are LF in Git and CRLF in the Windows checkout, confirmed with
`git ls-files --eol`. The unqualified check fails solely on those line endings. An LF-only verification
copy of all `src`, `test` and `script` files, with the same `foundry.toml`, passes the complete check.
The protected registry file was not normalized or otherwise edited. The two new Solidity files pass
directly in the working tree.

Slither was run separately on both the unchanged registry and the new guard with the CI flags:

```text
--compile-force-framework solc
--solc-remaps "@openzeppelin/=contracts/base/lib/openzeppelin-contracts/ forge-std/=contracts/base/lib/forge-std/src/"
--exclude-informational --fail-high
```

Both exited 0. Guard result:

```text
Detector: missing-zero-check
Ownable2Step.transferOwnership(address).newOwner lacks a zero-check
contracts/base/src/ShieldBotVerdictGuard.sol analyzed (5 contracts with 80 detectors), 1 result(s) found
Guard Slither exit: 0
```

That is the existing low-severity pending-transfer cancellation finding. An initial unsuppressed guard
run also reported intentional timestamp comparisons. Only that detector is suppressed on `check`, with
the clock trust assumption documented immediately above; Foundry's corresponding warning is suppressed
on the two comparisons. No blanket detector exclusion was added.

WP9 closes the CI follow-up: `.github/workflows/security.yml` now runs Slither on the verifier, attestor,
registry, guard and guarded transfer, each with `--exclude-informational --fail-high`. Foundry also
discovers the guard and transfer tests. No live transaction fee was checked.
