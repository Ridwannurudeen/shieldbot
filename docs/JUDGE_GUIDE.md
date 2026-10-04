# Judge guide: inspect the evidence in ten minutes

**Limits first.** This checkout does not establish released Robinhood browser protection: the extension on the Chrome Web Store is 3.0.1 and keeps its chain-identification limitation. The fix is in 3.1.0 in this repository, which section 4 below loads unpacked; that build has not been through Web Store review and has not been tested against MetaMask or Rabby. Simulation covers selected routes and amounts, not every launch. USDG support is Doppler-hooked v4 only; hookless USDG is unsupported and V2 USDG pairs are not covered. There is no stock-issuer authenticity check. Unknown data can produce a user-overridable warning in human interfaces; it is not a blanket transaction block.

The RPC proxy only sees requests routed through it; contract creation bypasses analysis, and raw transactions are already signed. On-chain enforcement is explicit: `ShieldBotVerdictGuard` reads the registry, and `ShieldBotGuardedTransfer` requires an allowed verdict before moving funds.

Sections 1–2 work **offline, without an API key**, once dependencies are installed. Section 3 is a **read-only online check against the live Robinhood Chain deployment**; run it rather than trusting the values it starts from. Allow about three minutes each for replay, decision semantics and hash verification, excluding dependency installation.

## Preparation

Run from the repository root. **Use Python 3.11**, the version CI tests (`.github/workflows/security.yml`). The pinned `web3==6.15.1` requires `lru-dict` below 1.3.0, and `lru-dict` 1.2.0 publishes prebuilt wheels only up to Python 3.11, so on Python 3.12 or newer `pip install` tries to compile it and fails without a C compiler. Dependency installation requires network access:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Debian or Ubuntu, `python3.11 -m venv` also needs the `python3.11-venv` package. Without Python 3.11, [uv](https://docs.astral.sh/uv/) fetches one for this environment only and leaves the system Python alone:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv --python 3.11 .venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

The commands below use Bash heredocs (Linux, macOS or Git Bash on Windows). For a Windows-created environment, activate with `source .venv/Scripts/activate` instead. Keep this environment active for every section. Python commands may print `UserWarning`s from `eth_utils` about networks 345 and 12611; they are harmless. On **2026-10-02** a fresh clone of `main` installed cleanly with the uv commands above on Python 3.11.16 (about ten seconds), and sections 1 to 3 then passed as described, with the Foundry cases run on Forge 1.7.1. The measured local results and installed-version differences are in [TESTING.md](TESTING.md).

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

Measured on **2026-10-04** at `15af2e6`: **201 passed**. In particular, an unattributed sell revert stays unknown; only the route-specific transfer refusal, no-credit error, or that pool's own hook failure qualifies in the reverted-sell branch. The separate zero-output branch also requires payout evidence and a minimum buy cost.

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

This needs Foundry. If `forge` is not installed, install it with `curl -L https://foundry.paradigm.xyz | bash`, open a new shell and run `foundryup`; these cases were checked with Forge 1.7.1. Then run these from the repository root in Bash/Git Bash. The pinned Solidity dependencies are git submodules; the `git submodule` line fetches them into `contracts/base/lib/` when the clone was made without `--recursive`. The first command reproduces the proven honeypot classifier from section 1; the Foundry command separately records each verdict into the real registry and exercises the real guard and transfer with a mock ERC-20. It is an offline composition of classifier evidence and consumer enforcement, not a live scan-to-publication transaction.

```bash
python -m pytest tests/test_robinhood_simulation.py::test_live_honeypot_is_proven_unsellable tests/test_robinhood_simulation.py::test_4663_proven_honeypot_is_flagged_through_the_analyzer -v -p no:cacheprovider
export PATH="$HOME/.foundry/bin:$PATH"
git submodule update --init --recursive
cd contracts/base
forge test --offline --match-contract ShieldBotGuardedTransferTest --match-test 'test_Transfer_(FreshLow|HoneypotDeniesBeforeTokenCall|UnknownDeniesBeforeTokenCall|ExpiredDeniesBeforeTokenCall)' -vv
```

Expected: both Python cases and all four Foundry cases pass. `FreshLow` proves the approved caller loses exactly the requested amount, the pinned recipient receives it, and `GuardedTransfer(subject, caller, amount, maxAge)` matches. The other cases prove `NotAllowed` with `HONEYPOT`, `UNKNOWN` and `EXPIRED`, unchanged balances/allowance, and **zero token transfer calls**. UNKNOWN and expired are two forms of the third outcome: no current permission. The tests use `MAX_AGE = 300` solely to exercise boundaries; use the operating values below for the demo.

The [worked consumer](../contracts/base/GUARDED_TRANSFER.md) pins one guard, subject, USDG token and recipient at construction. Callers approve it and call `transfer(amount, maxAge)`. It checks permission, measures the recipient's balance immediately before and after `safeTransferFrom`, and reverts with `ShortDelivery(requested, delivered)` unless the increase equals `amount` exactly. The event is emitted only after exact credit is established. This rejects transfers that deduct a fee from the recipient's credit. A token that debits the sender by more than `amount` while crediting the recipient exactly `amount` would pass this check. A recipient must be an EOA or passive contract because forwarding in a hook trips the check.

### Freshness operating conditions

The guard enforces **publication freshness, not observation freshness**. `Record.timestamp` is `block.timestamp` when the recording transaction executes. The publisher's 300-second observation-age cutoff only gates broadcast: a transaction already broadcast can land arbitrarily later. Observation age is not bounded on-chain. Both publication and checking trust the sequencer clock, and `observedBlock` does not determine age.

**The watched set is bounded and small: `GUARD_WATCH_MAX_SUBJECTS` defaults to 4.** `update_verdict_onchain()` auto-admits qualifying chain-4663 subjects confirmed on the configured registry with valid observation provenance only while capacity remains. This limit deliberately preserves the shared RPC budget for discovery and launch scans. Inside the actively watched set, rescans and re-publication can keep a finite `maxAge` satisfied when publication succeeds in time. Outside it, a subject recorded once eventually remains denied for any finite `maxAge` unless another record is published: LOW/MEDIUM/UNKNOWN report `EXPIRED`; HIGH/HONEYPOT retain their adverse reason. Sustained satisfaction depends on active watching; there is no chain-wide freshness service or guarantee of an allowed verdict.

**Demo: `maxAge = 600` seconds requires `GUARD_WATCH_MAX_SUBJECTS=1`. Production: 900 seconds minimum at the default four subjects.** The demo watches exactly the transfer's single immutable `subject`; the one-subject cap is a condition of the 600-second figure. The timing figures are calculations, not on-chain observations. They use `age = I + s + d(N+1) - d(N)`, with the 300 second rescan interval plus measured scan and publication delays. Live scan p90 was about 5.4 seconds. The resulting ages are typically **320 to 360 seconds**, about **437 seconds** in a healthy worst case, about **625 seconds** when four subjects bunch after a restart, and about **740 seconds** after one lost interval. A `maxAge` of 300 seconds would deny a healthy token for about **6 to 30 percent of wall time**. The contracts were deployed on Robinhood Chain on 2026-09-27; this guide records no comparison of these calculations with the live records.

Both figures are operating guidance, not availability bounds. A lost interval is structural: the hunter advances its observation clock after a complete scan is queued as `pending`, before drain confirmation; a later dropped row leaves the old on-chain record until the next interval. Also, `rescan_guard_subject` publishes before checking completeness. A scan overrun can therefore publish UNKNOWN and cause **60 to 150 seconds** of content denial in the calculated scenario. That fail-closed behavior is intentional; choose a demo subject whose scans complete reliably. See [source-linked rescan behavior and watch operations](guard-rescans.md). Repeated failures, rate limits and delayed inclusion can exceed either window.

An allowed result does not check that the evidence document exists or matches its hash, that the scan was recent, that token code/state is unchanged, or that the recorder key was uncompromised. `Record` contains no recorder identity or epoch; rotating the recorder does not invalidate old records, and recovery requires overwriting each affected subject. See the [exact trust model](../contracts/base/VERDICT_GUARD.md#what-allowed-means-and-who-is-trusted) and [watch operations](guard-rescans.md).

## 3. Verify a verdict without trusting the API

Values from the deployment on **2026-09-27**:

| Item | Value |
|---|---|
| Chain | Robinhood Chain, 4663 |
| `ShieldBotVerdictRegistry` | [`0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138`](https://robin.etherscan.io/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138) |
| Deployment provenance | transaction [`0x14275435a6f9cff13681b15b230f69c7c40579a4e308a7cc503d25ff1b731fef`](https://robin.etherscan.io/tx/0x14275435a6f9cff13681b15b230f69c7c40579a4e308a7cc503d25ff1b731fef) (block 74,214,980); source [exact match](https://sourcify.dev/server/v2/contract/4663/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138) on Sourcify and [verified source](https://robinhoodchain.blockscout.com/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138?tab=contract) on Blockscout; built from `main` at `c9ae9c9` |
| API serving that revision | `https://api.shieldbotsecurity.online` (the owner deployed `6d5df88` on 2026-10-04, which keeps the registry wiring `c9ae9c9` added; the API does not report its revision) |
| Published example | WOOD `0xf8bc08092c06db6148114dcf82af881f1085f92b`, recorded in transaction [`0xe5fc0372f7b0665208b817ddb3ea5d4b6b293a9d53658dc644a7542599849581`](https://robin.etherscan.io/tx/0xe5fc0372f7b0665208b817ddb3ea5d4b6b293a9d53658dc644a7542599849581) |
| Independent read RPC | `https://rpc.mainnet.chain.robinhood.com`, Robinhood's own node, which the firewall's contract reads do not use; any chain-4663 RPC works |

The example token is outside the guard watch, so the watcher does not republish it, but scanning it again does. The transaction pinned above was re-recorded on 2026-10-03 after a fresh scan, and the value here is the current one. If the check below fails on the registry or transaction assertion, that is why: `/api/verdict/4663/0xf8bc08092c06db6148114dcf82af881f1085f92b` serves the newer document: when it reports `onchain_status: confirmed`, use its `tx_hash` as `RECORD_TX`; until then the check fails.

Because WOOD is outside the guard watch, `check(WOOD, maxAge)` on the guard answers `EXPIRED` (reason 5) once its record is older than `maxAge`. That is the freshness rule at work; the registry event below still verifies.

Run the block with the Preparation environment active: it needs `eth_abi` and `eth_utils`. Pin the registry address from the deployment record, independently of the API response. The commands fetch the served evidence document, hash its exact `canonical` UTF-8 string, then retrieve the receipt from the chosen RPC and match its event. They require no API key, wallet, signing or broadcast.

```bash
export API_BASE='https://api.shieldbotsecurity.online'
export RPC_URL='https://rpc.mainnet.chain.robinhood.com'
export REGISTRY='0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138'
export SUBJECT='0xf8bc08092c06db6148114dcf82af881f1085f92b'
export RECORD_TX='0xe5fc0372f7b0665208b817ddb3ea5d4b6b293a9d53658dc644a7542599849581'
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
    request = Request(rpc_url, data=body, headers={'Content-Type': 'application/json', 'User-Agent': 'shieldbot-verify/1.0'})
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

Hash the **served string**, not a freshly serialized `evidence` object: JSON numbers such as `1.0` can serialize differently across languages. Use Ethereum keccak256, not SHA3-256. The event comparison remains useful after `latestRecord(subject)` changes; if the latest API document has changed since the pinned example, read its new recording transaction from `/api/verdict` as above and repeat.

A match establishes that the designated recorder committed those bytes. It does not establish scanner accuracy, issuer authenticity or future sellability. RPC receipt inclusion is also not independent verification of parent-chain finality. `off`, `deduplicated`, `dropped`, `pending`, `sending`, `submitted`, `unconfirmed`, `failed` and `reverted` do not satisfy this check; a 404 means no stored verdict for that address.

The verification block was checked locally against synthetic evidence and receipts, including mismatch cases. **On 2026-09-27 this block, run from a fresh shell with the values above, printed `MATCH: canonical evidence, chain 4663, registry, subject, verdict, evidenceHash and observed block`.** On **2026-10-02** it printed the same line again from a fresh clone of `main`. On **2026-10-03** it printed the same line again against the `fb68f80` deployment, and again after each later deployment, against `760036d`, `abe28c1`, `350da0f`, `0bd9810`, `1216d95`, `3a7394e`, `99a6b32`, `2315085` and `6d5df88`, all run from the pinned environment. The exception is `29360c5`, whose record in the submission was written after the fact and notes no `MATCH` run.

## 4. Run the browser extension, unpacked

The published extension is 3.0.1 and predates the chain-identification fix. Version 3.1.0 lives in `extension/` in this repository and loads without a build step:

1. Open `chrome://extensions` and turn on Developer mode.
2. Choose Load unpacked and select the `extension/` directory of this checkout.
3. The card reads **ShieldAI Transaction Firewall 3.1.0** with no Errors button. Chrome warns that it cannot verify where an unpacked extension comes from; that applies to any unpacked extension.

It needs no API key and no account. Open any HTTPS page that talks to an injected wallet and ask it to sign a message or send a transaction: the firewall's decision appears **before** the wallet prompt, and declining it rejects the request so the wallet is never asked. A signature request is the cheapest thing to try, because it moves no value.

What it covers, and what it does not: it hooks nine methods on a wallet injected into the page, through `window.ethereum` or EIP-6963. WalletConnect sessions and anything begun inside the wallet are not seen. Switching the firewall off in its settings forwards every request to the wallet untouched, with two exceptions the extension's README records: a document the content script cannot reach, such as a same-origin frame or `about:blank`, is never told the setting and keeps refusing, and a request made in the moment before the first settings message is still chain-bound.

This build has not been through Chrome Web Store review, and it has not been exercised against real MetaMask or Rabby installations; its behaviour is covered by the repository's extension tests and by a run in Chrome against a synthetic provider at `1216d95`. The popup, side panel and content script changed after that run (`958c166`, `b47f2c2`, `a580654`); this guide records no later run against a synthetic provider. Released browser protection for Robinhood Chain is not claimed.
