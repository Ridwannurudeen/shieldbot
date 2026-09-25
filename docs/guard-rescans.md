# Guard subject rescans

The fast Robinhood Chain launch watch also remeasures a small, durable set of guard-relevant
subjects. A confirmed on-chain verdict with observation provenance automatically admits its
subject while capacity remains. Pending, off-chain and failed records do not admit subjects.
Existing historical confirmations can be registered explicitly; startup does not fill the set
arbitrarily from old records.

Admission, automatic or explicit, needs a verdict confirmed on the configured registry
(`ROBINHOOD_VERDICT_REGISTRY`). After the registry address changes, subjects admitted under the old
registry stay in the watch on purpose: their rescans publish to the new registry, so they qualify on it
again as soon as a rescan is confirmed there. A confirmation that arrives late for a transaction sent to
the old registry never admits a new subject.

`GUARD_WATCH_MAX_SUBJECTS` in `core/database.py` defaults to **4**, overridden by the environment
variable of the same name. Zero disables the set. Lowering it and restarting disables excess
members; increasing it does not silently reenable them. `GUARD_RESCAN_INTERVAL_SECONDS` in
`agent/hunter.py` imports the publisher's `VERDICT_REFRESH_SECONDS` as its **300-second** interval,
so the rescan and unchanged-verdict refresh thresholds cannot drift independently. Four subjects require 48 scans/hour: at 23 requests/scan,
that is 0.307 rps. From the shared 1 rps budget, discovery consumes approximately 0.15 rps,
leaving approximately 0.543 rps for launch scans and general rechecks. Raising the cap spends
that remaining capacity and can make the refresh target unattainable.

Discovery runs before scan selection in each fast-watch cycle. Launches receive at least
alternate scan slots under contention. Guard subjects run oldest complete measurement first,
with attempt rotation so a failing oldest subject cannot monopolize the set. General rechecks
get a background slot after at most one capped set of guard attempts. Scans reserve the same
22-request budget as launch scans and obey the same breaker. Failed, incomplete or reused
measurements preserve the last complete observation and become retryable after 30 seconds.
An incomplete scan is published as UNKNOWN and cannot leave an earlier cleared launch outcome
displayed as the latest scan. Guard membership never depends on `tracked_pairs` status.

Administrative operations use the existing `X-Admin-Secret` authentication:

- `POST /api/admin/guard-subjects/4663/{address}` registers or reenables a subject with a verdict
  confirmed on the configured registry. HTTP 409 means capacity is exhausted or no qualifying
  confirmed verdict exists.
- `DELETE /api/admin/guard-subjects/4663/{address}` persists an opt-out. Later confirmations do not
  re-add it. A queued rescan checks membership again after its budget wait.
- `GET /api/admin/stats` includes `guard_watch`: members, each last complete measurement's age
  (null when unknown), retry time, due count, configured cap/period, watch running state, and the
  RPC budget's rate, breaker state and reservation wait. `saturated` means the budget currently
  has an outstanding reservation; it is an instantaneous signal, not historical utilization.

## Operating windows

Use **`maxAge = 600` seconds for the demo only with `GUARD_WATCH_MAX_SUBJECTS=1`**. The
`ShieldBotGuardedTransfer.subject` address is immutable; the demo watches exactly that one subject.
Use **900 seconds as the production minimum at the default four watched subjects**. Neither window
guarantees uninterrupted permission or bounds observation age; the guard measures publication age.

These figures are calculations, not on-chain observations. They use
`age = I + s + d(N+1) - d(N)`, with the 300 second rescan interval plus measured scan and
publication delays. Live scan p90 was about 5.4 seconds.

| Scenario | Record age |
|---|---:|
| Typical healthy refresh | 320 to 360 s |
| Healthy worst | ~437 s |
| Four subjects bunched after restart | ~625 s |
| One lost interval | ~740 s |

`maxAge = 300` would deny a healthy token for about **6 to 30 percent of wall time**. Confirm these
calculations against live records after the registry, guard and transfer contracts are deployed on
Robinhood Chain. The Foundry
`MAX_AGE = 300` fixtures exercise policy boundaries; they are not configuration recommendations.
Repeated failures, rate limits and delayed inclusion can exceed any finite operating window.

## Structural denial windows

**A lost interval is structural.** In [agent/hunter.py](../agent/hunter.py#L210), `rescan_guard_subject` accepts a complete
scan whose publication status is `pending` (lines 210–213) and persists its `observed_at` through
`update_guard_subject_measurement` (lines 222–224). This advances `last_observed_at` before the drain
confirms publication. The next due check uses that observation clock (lines 165–167), not the last
on-chain confirmation. If the drain later drops the queued row, no replacement from the guard-rescan
loop lands until the next interval; the old chain record keeps aging. The publisher's observation
validation can drop stale or superseded rows before broadcast ([services/verdict_publisher.py](../services/verdict_publisher.py#L589),
`_drop_ineligible`, lines 589–611). This explains why a lost interval can exceed the 600-second demo window.

**Publication precedes completeness validation.** The [hunter calls `_publish_verdict` at line 187](../agent/hunter.py#L187),
then computes `complete` at lines 190–196. A scan overrun returning incomplete evidence can therefore
queue UNKNOWN, which replaces earlier permission if the drain records it. The incomplete scan does
not advance the complete-observation clock and can retry after 30 seconds, but scan, scheduling and
publication add latency: the calculated scenario incurs **60 to 150 seconds of content denial**.
Increasing `maxAge` cannot permit a fresh UNKNOWN. This is intentional fail-closed behavior, not a
scheduler defect to hide. Choose a demo subject whose scans complete reliably. A proven honeypot
still maps to HONEYPOT even with unrelated missing fields.

These source line numbers were checked on 2026-09-22. See the
[guard policy](../contracts/base/VERDICT_GUARD.md) and
[exact-credit worked consumer](../contracts/base/GUARDED_TRANSFER.md).

`tests/test_guard_rescan.py` verifies a cleared LOW launch is confirmed, admitted, remeasured
at 300 seconds and confirmed again with a newer observation/block and changed evidence hash.
It runs the real database, launch watch, hunter and publisher drain; transaction preparation
and RPC transport are in-memory fakes, with no signing or network access.
