# Judge guide: inspect the evidence in ten minutes

**Limits first.** This checkout does not establish released Robinhood browser protection: the shipped extension's chain-identification limitation remains, and the branch fix will not ship before the deadline. Simulation covers selected routes and amounts, not every launch. USDG support is Doppler-hooked v4 only; hookless USDG is unsupported and V2 USDG pairs are not covered. There is no stock-issuer authenticity check. Unknown data can produce a user-overridable warning in human interfaces; it is not a blanket transaction block.

The RPC proxy only sees requests routed through it; contract creation bypasses analysis, and raw transactions are already signed. On-chain enforcement is explicit: `ShieldBotVerdictGuard` reads the registry, and `ShieldBotGuardedTransfer` requires an allowed verdict before moving funds.

Sections 1–2 work **offline, without an API key**, once dependencies are installed. Section 3 is a **read-only online check pending deployment**, not a live proof supplied by this checkout. Allow about three minutes each for replay, decision semantics and hash verification, excluding dependency installation.

## Preparation

Run from the repository root with Python and the project dependencies available. For a fresh virtual environment, dependency installation requires network access:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The commands below use Bash heredocs (Linux, macOS or Git Bash on Windows). For a Windows-created environment, activate with `source .venv/Scripts/activate` instead. The measured local results and installed-version differences are in [TESTING.md](TESTING.md); a clean installation of the pinned environment was not verified in this documentation pass.

## 1. Replay the recorded honeypot offline

Open [v2_honeypot_sell_reverts.json](../tests/fixtures/robinhood_simulation/v2_honeypot_sell_reverts.json). Its token is `0xab09be58b6db998dc7b5770f106ed6de6cf17ba1`, on chain **4663**, at simulated block **65,554,454**. The fixture says it was recorded on 2026-09-17. Call results are unmodified; block-header fields other than `number` were trimmed.

```bash
python -m pytest tests/test_robinhood_simulation.py::test_request_matches_live_verified_calldata tests/test_robinhood_simulation.py::test_live_honeypot_is_proven_unsellable tests/test_robinhood_simulation.py::test_4663_proven_honeypot_is_flagged_through_the_analyzer -v -p no:cacheprovider
```

The request test covers six fixtures, including this honeypot. It rebuilds each `eth_simulateV1` request and asserts equality with the saved request. The honeypot tests evaluate the recorded response and pass it through the analyzer. To inspect the actual result:

```bash
python - <<'PY'
import json
from pathlib import Path
from services.robinhood_simulation import Pool, build_simulation_request, evaluate_simulation

f = json.loads(Path('tests/fixtures/robinhood_simulation/v2_honeypot_sell_reverts.json').read_text())
pool = Pool(f['route'], f['numeraire'], pair=f['pair'])
request = build_simulation_request(pool, f['token'], f['amount'], f['buyer'], f['receiver'])
assert [request, 'latest'] == f['request']
result = evaluate_simulation(pool, f['token'], f['amount'], f['buyer'], f['response']['result'])
assert result['block'] == 65554454
assert result['can_buy'] is True and result['can_sell'] is False
assert result['is_honeypot'] is True and result['sell_tax'] is None
print(json.dumps(result, indent=2))
PY
```

Look for `TransferHelper: TRANSFER_FROM_FAILED` and the successful plain transfer. The token can move between addresses but refuses the simulated sell transfer. Sell tax remains `null` because the sell did not complete.

**What replay proves:** today's encoder matches the recording and today's classifier reaches that outcome from those call results. It does not re-execute historical EVM state or independently authenticate the RPC recording. The saved request used `latest` at capture time; resubmitting it today is a different experiment.

For all seven recordings, USDG funding layout, and failure-attribution regressions:

```bash
python -m pytest tests/test_robinhood_simulation.py tests/test_robinhood_simulation_usdg.py -q -p no:cacheprovider
```

Measured on **2026-09-22**: **192 passed**. In particular, an unattributed sell revert stays unknown; only the route-specific transfer refusal, no-credit error, or that pool's own hook failure qualifies in the reverted-sell branch. The separate zero-output branch also requires payout evidence and a minimum buy cost.

## 2. See all three decisions

This is a **synthetic consumer-model demonstration**, not three live token scans or published chain records. It uses the real Python SDK model and demonstrates a caller that only proceeds when `allowed` is true:

```bash
python - <<'PY'
import sys
sys.path.insert(0, 'sdk/python')
from shieldbot.models import Verdict

cases = [
    ('covered and allowed', Verdict(verdict='ALLOW', score=5, status='ok', coverage={'honeypot': 1})),
    ('adverse and denied', Verdict(verdict='BLOCK', score=91, status='ok', coverage={'honeypot': 1}, flags=['honeypot'])),
    ('unknown and denied', Verdict(verdict='ALLOW', score=0, status='unknown', coverage={'honeypot': 0}, coverage_reasons={'honeypot': 'No supported simulation route'})),
]
assert [v.allowed for _, v in cases] == [True, False, False]
for label, v in cases:
    print(f'{label}: {v.verdict}, allowed={v.allowed}, status={v.status}')
PY
```

Expected output:

```text
covered and allowed: ALLOW, allowed=True, status=ok
adverse and denied: BLOCK, allowed=False, status=ok
unknown and denied: WARN, allowed=False, status=unknown
```

**UNKNOWN is the correct answer when a required observation is missing.** A zero placeholder score with no sell simulation is not a low-risk measurement. It should not authorize an autonomous caller to proceed. The model changes an incomplete `ALLOW` to `WARN`, so `allowed` is false. This is denial of automatic permission, not a claim that the SDK blocks a wallet by itself. Explicit SDK fail-open configuration can allow unavailable analysis; human interfaces can offer overrides.

The on-chain enum expresses evidence, not these client actions: `UNKNOWN=0`, `LOW=1`, `MEDIUM=2`, `HIGH=3`, `HONEYPOT=4`. Incomplete scans map to `UNKNOWN`, except a simulation-proven honeypot remains `HONEYPOT` even with unrelated missing fields. The registry stores those assertions; `ShieldBotVerdictGuard` turns them into an enforceable policy, and `ShieldBotGuardedTransfer` applies that policy atomically to transfers.

### What the on-chain guard enforces

`ShieldBotVerdictGuard` allows the latest recorded LOW or MEDIUM within the caller's `maxAge`; accepting MEDIUM deliberately tolerates moderate reported risk and does not mean the token is safe. `ShieldBotGuardedTransfer` applies that policy before its pinned USDG transfer. These are separate contracts from the registry and from the SDK example above.

`check(address subject, uint64 maxAge)` returns `(bool allowed, uint8 reason)` for inspection. `requireAllowed(address subject, uint64 maxAge)` reverts with `NotAllowed(subject, reason)` on denial, so a consumer can enforce the check in the same transaction as its action.

| Code | Reason | Meaning |
|---|---|---|
| 0 | `ALLOWED` | Recorded LOW/MEDIUM, non-future and within a positive `maxAge` |
| 1 | `NO_RECORD` | No evidence hash recorded; includes the zero subject |
| 2 | `UNKNOWN` | Fresh but incomplete evidence |
| 3 | `HIGH` | High risk regardless of publication age |
| 4 | `HONEYPOT` | Recorded simulation-proven sell trap regardless of publication age |
| 5 | `EXPIRED` | Non-adverse record too old, or zero `maxAge` |
| 6 | `FUTURE_TIMESTAMP` | Non-adverse publication timestamp ahead of the check clock |

Precedence is `NO_RECORD → HIGH/HONEYPOT → FUTURE_TIMESTAMP → EXPIRED → LOW/MEDIUM allowed → UNKNOWN`. The numeric codes are unchanged. Adverse-first changes only the explanation: an expired LOW loses permission with `EXPIRED`, while an expired HONEYPOT reports `HONEYPOT`, not an apparent invitation to retry. UNKNOWN has no adverse content, so expiry takes precedence over it.

### On-chain transfer demonstration (offline)

With Foundry and the pinned Solidity dependencies already installed, run these from the repository root in Bash/Git Bash. The first command reproduces the proven honeypot classifier from section 1; the Foundry command separately records each verdict into the real registry and exercises the real guard and transfer with a mock ERC-20. It is an offline composition of classifier evidence and consumer enforcement, not a live scan-to-publication transaction.

```bash
python -m pytest tests/test_robinhood_simulation.py::test_live_honeypot_is_proven_unsellable tests/test_robinhood_simulation.py::test_4663_proven_honeypot_is_flagged_through_the_analyzer -v -p no:cacheprovider
export PATH="$HOME/.foundry/bin:$PATH"
cd contracts/base
forge test --offline --match-contract ShieldBotGuardedTransferTest --match-test 'test_Transfer_(FreshLow|HoneypotDeniesBeforeTokenCall|UnknownDeniesBeforeTokenCall|ExpiredDeniesBeforeTokenCall)' -vv
```

Expected: both Python cases and all four Foundry cases pass. `FreshLow` proves the approved caller loses exactly the requested amount, the pinned recipient receives it, and `GuardedTransfer(subject, caller, amount, maxAge)` matches. The other cases prove `NotAllowed` with `HONEYPOT`, `UNKNOWN` and `EXPIRED`, unchanged balances/allowance, and **zero token transfer calls**. UNKNOWN and expired are two forms of the third outcome: no current permission. The tests use `MAX_AGE = 300` solely to exercise boundaries; use the operating values below for the demo.

The [worked consumer](../contracts/base/GUARDED_TRANSFER.md) pins one guard, subject, USDG token and recipient at construction. Callers approve it and call `transfer(amount, maxAge)`. It checks permission, measures the recipient's balance immediately before and after `safeTransferFrom`, and reverts with `ShortDelivery(requested, delivered)` unless the increase equals `amount` exactly. The event is emitted only after exact credit is established. Fee tokens are rejected atomically; a recipient must be an EOA or passive contract because forwarding in a hook trips this check.

### Freshness operating conditions

The guard enforces **publication freshness, not observation freshness**. `Record.timestamp` is `block.timestamp` when the recording transaction executes. The publisher's 300-second observation-age cutoff only gates broadcast: a transaction already broadcast can land arbitrarily later. Observation age is not bounded on-chain. Both publication and checking trust the sequencer clock, and `observedBlock` does not determine age.

**The watched set is bounded and small: `GUARD_WATCH_MAX_SUBJECTS` defaults to 4.** `update_verdict_onchain()` auto-admits qualifying confirmed chain-4663 subjects with a registry set and valid observation provenance only while capacity remains. This limit deliberately preserves the shared RPC budget for discovery and launch scans. Inside the actively watched set, rescans and re-publication can keep a finite `maxAge` satisfied when publication succeeds in time. Outside it, a subject recorded once eventually remains denied for any finite `maxAge` unless another record is published: LOW/MEDIUM/UNKNOWN report `EXPIRED`; HIGH/HONEYPOT retain their adverse reason. Sustained satisfaction depends on active watching; there is no chain-wide freshness service or guarantee of an allowed verdict.

**Demo: `maxAge = 600` seconds requires `GUARD_WATCH_MAX_SUBJECTS=1`. Production: 900 seconds minimum at the default four subjects.** The demo watches exactly the transfer's single immutable `subject`; the one-subject cap is a condition of the 600-second figure. Coordinator measurements: typical healthy record age **320–360 s**, healthy worst **~437 s**, four subjects bunched after restart **~625 s**, and one lost interval **~740 s**. `maxAge = 300` would deny a perfectly healthy token for roughly **6–30% of wall time**. These are supplied measurements, not live probes repeated by this local-only validation.

Both figures are operating guidance, not availability bounds. A lost interval is structural: the hunter advances its observation clock after a complete scan is queued as `pending`, before drain confirmation; a later dropped row leaves the old on-chain record until the next interval. Also, `rescan_guard_subject` publishes before checking completeness. A scan overrun can therefore publish UNKNOWN and cause **60–150 s** of content denial in the measured scenario. That fail-closed behavior is intentional; choose a demo subject whose scans complete reliably. See [source-linked rescan behavior and watch operations](guard-rescans.md). Repeated failures, rate limits and delayed inclusion can exceed either window.

An allowed result does not check that the evidence document exists or matches its hash, that the scan was recent, that token code/state is unchanged, or that the recorder key was uncompromised. `Record` contains no recorder identity or epoch; rotating the recorder does not invalidate old records, and recovery requires overwriting each affected subject. See the [exact trust model](../contracts/base/VERDICT_GUARD.md#what-allowed-means-and-who-is-trusted) and [watch operations](guard-rescans.md).

## 3. Verify a verdict without trusting the API

**Pending owner deployment.** Fill this table before using the online portion; the placeholders are not addresses or evidence of deployment.

| Item | Owner must supply |
|---|---|
| Chain | Robinhood Chain, 4663 |
| `ShieldBotVerdictRegistry` | **OWNER TODO: registry address** |
| Deployment provenance | **OWNER TODO: deployment transaction, explorer/source-verification link, deployed source revision** |
| API serving that revision | **OWNER TODO: verified API base URL** |
| Published example | **OWNER TODO: token address with a confirmed verdict and its recording transaction hash** |
| Independent read RPC | **OWNER TODO: chain-4663 RPC URL** |

Pin the registry address from the deployment record, independently of the API response. The commands fetch the served evidence document, hash its exact `canonical` UTF-8 string, then retrieve the receipt from the chosen RPC and match its event. They require no API key, wallet, signing or broadcast.

```bash
export API_BASE='OWNER_FILL_VERIFIED_API_BASE'
export RPC_URL='OWNER_FILL_INDEPENDENT_4663_RPC'
export REGISTRY='OWNER_FILL_REGISTRY_ADDRESS'
export SUBJECT='OWNER_FILL_PUBLISHED_TOKEN_ADDRESS'
export RECORD_TX='OWNER_FILL_RECORDING_TRANSACTION_HASH'
python - <<'PY'
import json
import os
import re
from urllib.request import Request, urlopen
from eth_abi import decode
from eth_utils import keccak

api, rpc_url = os.environ['API_BASE'], os.environ['RPC_URL']
registry, subject, tx = (os.environ[k].lower() for k in ('REGISTRY', 'SUBJECT', 'RECORD_TX'))
assert all(re.fullmatch(r'0x[0-9a-f]{40}', a) for a in (registry, subject)), 'Fill deployment addresses first'
assert re.fullmatch(r'0x[0-9a-f]{64}', tx), 'Fill the recording transaction hash first'
assert api.startswith(('https://', 'http://')) and rpc_url.startswith(('https://', 'http://'))
with urlopen(api.rstrip('/') + '/api/verdict/4663/' + subject, timeout=30) as response:
    doc = json.load(response)
canonical = doc['canonical']
evidence = json.loads(canonical)
digest = '0x' + keccak(canonical.encode('utf-8')).hex()
assert digest == doc['evidence_hash'].lower(), 'Served evidence hash mismatch'
assert evidence == doc['evidence'], 'Parsed evidence differs from canonical document'
assert evidence['chain_id'] == doc['chain_id'] == 4663
assert evidence['subject'].lower() == doc['subject'].lower() == subject
codes = {'UNKNOWN': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'HONEYPOT': 4}
code = codes[evidence['verdict']]
assert evidence['verdict'] == doc['verdict'] and code == doc['verdict_code']
assert doc['onchain_status'] == 'confirmed', 'API does not report a confirmed publication'
assert doc['registry'].lower() == registry and doc['tx_hash'].lower() == tx

def rpc(method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    request = Request(rpc_url, data=body, headers={'Content-Type': 'application/json'})
    with urlopen(request, timeout=30) as response:
        result = json.load(response)
    assert 'error' not in result, result.get('error')
    return result['result']

assert int(rpc('eth_chainId', []), 16) == 4663, 'Wrong RPC chain'
receipt = rpc('eth_getTransactionReceipt', [tx])
assert receipt and int(receipt['status'], 16) == 1, 'Transaction absent or reverted'
assert receipt['transactionHash'].lower() == tx
assert receipt['to'].lower() == registry
signature = 'VerdictRecorded(address,uint8,bytes32,uint64,uint64)'
topics = ['0x' + keccak(text=signature).hex(), '0x' + subject[2:].zfill(64), '0x' + format(code, '064x'), digest]
matches = [log for log in receipt['logs'] if log['address'].lower() == registry and [t.lower() for t in log['topics']] == topics and not log.get('removed', False)]
assert matches, 'Matching registry event absent'
assert any(decode(['uint64', 'uint64'], bytes.fromhex(log['data'][2:]))[0] == evidence['observed_block'] for log in matches), 'Observed block mismatch'
print('MATCH: canonical evidence, chain 4663, registry, subject, verdict, evidenceHash and observed block')
print('evidenceHash:', digest)
PY
```

Hash the **served string**, not a freshly serialized `evidence` object: JSON numbers such as `1.0` can serialize differently across languages. Use Ethereum keccak256, not SHA3-256. The event comparison remains useful after `latestRecord(subject)` changes; if the latest API document has changed since the pinned example, obtain its new recording transaction from the owner and repeat.

A match establishes that the designated recorder committed those bytes. It does not establish scanner accuracy, issuer authenticity or future sellability. RPC receipt inclusion is also not independent verification of parent-chain finality. `off`, `pending`, `sending`, `submitted`, `unconfirmed`, `failed` and `reverted` do not satisfy this check; a 404 means no stored verdict for that address.

The verification block was checked locally against synthetic evidence and receipts, including mismatch cases. **No live endpoint, deployment or registry event was verified in this documentation pass.**
