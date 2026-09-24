# Deploy ShieldBotVerdictRegistry on Robinhood Chain (4663)

Runbook for the owner. Every command that sends a transaction is marked **OWNER-ONLY**. Nothing here passes a
raw private key on the command line: transactions are signed with a Foundry keystore (`--account`).

## What it is

`src/ShieldBotVerdictRegistry.sol` is a small, non-upgradeable registry. It has no payable functions and makes
no external calls.

- **Owner** (the deploying account, `Ownable2Step`) can only rotate the recorder and hand over ownership.
- **Recorder** (a hot wallet on the server) can only call `record` and `recordBatch` (at most `MAX_BATCH` = 50 entries).
- Each record stores the latest `(verdict, observedBlock, timestamp, evidenceHash)` per token, plus a per-token
  count and a total count, and emits:

```
VerdictRecorded(address indexed subject, uint8 indexed verdict, bytes32 indexed evidenceHash, uint64 observedBlock, uint64 timestamp)
```

Verdict codes: `0 UNKNOWN` (incomplete scan, never a safety claim), `1 LOW`, `2 MEDIUM`, `3 HIGH`,
`4 HONEYPOT` (a buy-then-sell simulation proved holders cannot sell). A token never recorded reads as `UNKNOWN`.

`evidenceHash` is the keccak256 of the canonical evidence JSON that ShieldBot serves at
`GET /api/verdict/4663/<token>`. `observedBlock` is the Robinhood Chain block of the sell simulation, or 0 when
the evidence has no simulation block.

## Prerequisites

- Foundry (`forge`, `cast`). Run everything below from `contracts/base`.
- Two wallets:
  - **Owner**: your cold or identity wallet. It deploys and owns the registry. Import it once as a keystore:
    ```bash
    cast wallet import robinhood-owner --interactive
    ```
    This writes an encrypted keystore to `~/.foundry/keystores/robinhood-owner`. The plaintext key never touches disk.
  - **Recorder**: a fresh hot wallet used only by the server's API process. Do NOT run a bare `cast wallet new`:
    it prints the private key to the terminal and its scrollback. Create an encrypted keystore instead; it asks for
    a password and prints only the address:
    ```bash
    cast wallet new ~/.foundry/keystores robinhood-recorder
    ```
    The plaintext key is needed once, to write the API's environment file in step 8. Decrypt it there with
    `cast wallet decrypt-keystore robinhood-recorder` in a private terminal, and clear the screen afterwards. It
    goes into that file and nowhere else.
- A little ETH on Robinhood Chain in the owner wallet for the deployment (the dry run below prints the estimate).

```bash
export RH_RPC=https://rpc.mainnet.chain.robinhood.com
export ROBINHOOD_RPC_URL=$RH_RPC   # foundry.toml's robinhood RPC alias
export OWNER=0x<owner address>
export RECORDER=0x<recorder address>
```

## 1. Build and test

```bash
forge build --sizes
forge test -vv
forge fmt --check
forge snapshot --check --no-match-test 'testFuzz|invariant_'
```

The committed `.gas-snapshot` uses Foundry 1.7.1 and the 55 deterministic tests. Fuzz gas summaries varied even
with a fixed seed, so fuzz and invariant tests run in the full `forge test` suite rather than the gas snapshot.
The full suite passes 65 tests, including two invariants with 256 runs of 500 calls each and zero unexpected
reverts. Test-harness gas in the snapshot is distinct from contract-call gas in `forge test --gas-report`.
With Solidity 0.8.28, optimizer 200 and Cancun, hoisting the
global counter update out of the loop reduced a 50-new-subject `recordBatch` from 3,617,479 to 3,606,945 reported
gas: **10,534 saved (0.291%)**. Reproduce with:

```bash
forge test --match-test test_RecordBatch_AcceptsMaxBatch --gas-report
```

The standalone `record` report still peaks at 116,795 and has a 24,740 median across the registry unit suite
(including reverting calls); that median is not a successful-repeat benchmark. Runtime is 2,417 bytes versus
the original 2,394, a 23-byte increase for the renunciation guard and separate counter updates.

The stateful tests exercise individual records, repeated subjects within batches, rejected batches and recorder
rotation. The runtime test disassembles deployed bytecode, skipping PUSH operands and compiler metadata, and
rejects CALL, CALLCODE, DELEGATECALL, STATICCALL, CREATE, CREATE2 and SELFDESTRUCT.

Local Slither 0.11.5 with the CI flags `--exclude-informational --fail-high` exits 0 but reports one low-severity
`missing-zero-check` in OpenZeppelin's `Ownable2Step.transferOwnership`. The unchanged baseline produces the same
finding: zero deliberately cancels a pending transfer without changing the owner, as covered by the ownership
tests. No detector is suppressed; the previously reported zero-result baseline was not reproduced locally.

## 2. Dry run against Robinhood Chain (no transaction is sent)

Without `--broadcast`, `forge script` only simulates. No key is needed; `--sender` sets the simulated owner.

```bash
INITIAL_RECORDER=$RECORDER \
  forge script script/DeployVerdictRegistry.s.sol:DeployVerdictRegistry \
    --rpc-url $RH_RPC \
    --sender $OWNER
```

Check the output before going further:
- `Chain id: 4663`
- `owner():` is `$OWNER` and `recorder():` is `$RECORDER`
- it ends with `SIMULATION COMPLETE. To broadcast these transactions, add --broadcast ...`

The script rejects any chain id other than 4663 before creating the registry. A local rehearsal must therefore
use `anvil --chain-id 4663`; the default local chain id 31337 is deliberately rejected.

## 3. Deploy (OWNER-ONLY)

```bash
INITIAL_RECORDER=$RECORDER \
  forge script script/DeployVerdictRegistry.s.sol:DeployVerdictRegistry \
    --rpc-url $RH_RPC \
    --account robinhood-owner --sender $OWNER \
    --broadcast
```

Forge asks for the keystore password. Copy the `Deployed at: 0x...` address:

```bash
export REGISTRY=0x<deployed address>
```

The deployment transaction hash is in `broadcast/DeployVerdictRegistry.s.sol/4663/run-latest.json`
(the `broadcast/` directory is gitignored).

## 4. Verify the source on all three explorers (chain 4663)

Use the exact deployment source and compiler settings in `foundry.toml` (Solidity 0.8.28, optimizer 200 runs,
Cancun). `$RECORDER` below must be the **initial constructor recorder**, even if it has since been rotated.
Submit to each explorer separately: a Sourcify match does not verify the contract on Etherscan.

### Etherscan

Set `ETHERSCAN_V2_API_KEY` in the owner's environment. The `robinhood` entry in `foundry.toml` selects
`https://api.etherscan.io/v2/api?chainid=4663`. Etherscan requires ABI-encoded constructor arguments:

```bash
forge verify-contract $REGISTRY src/ShieldBotVerdictRegistry.sol:ShieldBotVerdictRegistry \
  --chain 4663 \
  --verifier etherscan \
  --constructor-args "$(cast abi-encode 'constructor(address)' "$RECORDER")" \
  --watch
```

Open `https://robin.etherscan.io/address/$REGISTRY#code` and confirm the verified source and constructor argument.

### Blockscout

Verify on the explorer linked by ShieldBot as well, using its Etherscan-compatible API:

```bash
forge verify-contract $REGISTRY src/ShieldBotVerdictRegistry.sol:ShieldBotVerdictRegistry \
  --chain 4663 \
  --verifier blockscout \
  --verifier-url https://robinhoodchain.blockscout.com/api/ \
  --constructor-args "$(cast abi-encode 'constructor(address)' "$RECORDER")" \
  --watch
```

Open `https://robinhoodchain.blockscout.com/address/$REGISTRY?tab=contract` and confirm that the source is verified.
Do not treat a successful submission as a completed verification; wait for the result on all three explorers.

### Sourcify

Sourcify verification needs no API key or `--constructor-args`:

```bash
forge verify-contract $REGISTRY src/ShieldBotVerdictRegistry.sol:ShieldBotVerdictRegistry \
  --chain 4663 \
  --verifier sourcify \
  --watch
```

If Sourcify asks for the creation transaction, add `--creation-transaction-hash <deployment tx hash>`.
Confirm the match:

```bash
curl -s https://sourcify.dev/server/v2/contract/4663/$REGISTRY
# expect "match":"match" (or "exact_match")
```

## 5. Read-only sanity checks

```bash
cast call $REGISTRY "owner()(address)"         --rpc-url $RH_RPC   # $OWNER
cast call $REGISTRY "recorder()(address)"      --rpc-url $RH_RPC   # $RECORDER
cast call $REGISTRY "totalRecords()(uint256)"  --rpc-url $RH_RPC   # 0
cast call $REGISTRY "MAX_BATCH()(uint256)"     --rpc-url $RH_RPC   # 50
```

Check once that `record()` fits the server's gas cap. Robinhood Chain is an Arbitrum chain, so `eth_estimateGas`
includes the L1 data fee as gas. The server signs with the estimate plus 20% and defers anything above 1,000,000
gas, so the estimate must be well under 833,334. This is a read-only simulation from the recorder's address;
nothing is sent:

```bash
cast estimate $REGISTRY "record(address,uint8,bytes32,uint64)" \
  0x0000000000000000000000000000000000000001 1 "$(cast keccak shieldbot)" 0 \
  --from $RECORDER --rpc-url $RH_RPC
```

The Foundry gas report measured 116,795 gas for the first standalone `record` on a fresh registry.
This includes initializing the global count; the roughly 72k per new subject quoted for a warm
batch is a different measurement, with call overhead and the global counter shared across entries.
If the estimate is near 833,334 or above it, stop and raise `MAX_GAS_LIMIT` in `services/verdict_publisher.py`
before configuring the server. If the node refuses the estimate because the recorder has no ETH yet, run it
again after funding it in step 7.

## 6. Set or rotate the recorder (OWNER-ONLY)

The recorder is set at deployment. To replace it (key rotation, or if the server key may be compromised):

```bash
cast send $REGISTRY "setRecorder(address)" 0x<new recorder address> \
  --rpc-url $RH_RPC --account robinhood-owner
cast call $REGISTRY "recorder()(address)" --rpc-url $RH_RPC
```

The old recorder loses access in the same transaction. Then put the new recorder key in the API service's environment file and restart the API (step 8).

Ownership moves in two steps: the owner calls `transferOwnership(<new owner>)`, and nothing changes until the new
owner calls `acceptOwnership()`.

`renounceOwnership()` is disabled by a custom-error revert. The contract enforces retaining an owner so the
recorder can still be rotated after a compromise; use the two-step ownership transfer to change that owner.

## 7. Fund the recorder (OWNER-ONLY)

The recorder pays gas for every `record()`. The Foundry gas report measured 116,795 gas for the first standalone
record on a fresh registry, rather than a per-subject cost inside a warm batch. The successful overwrite in
`test_Record_LatestIsOverwrittenAndCountsAccumulate` measured 48,299; the full-suite median of 24,740 includes
reverting calls and must not be used to budget successful repeat records. Use `.gas-snapshot` for local regression
checks and the live estimate in step 5, with current fees, for funding.
A saturated launch watch is mostly first records, so fund for those. This example sends 0.05 ETH; its duration
depends on the live estimate and recording rate:

```bash
cast send $RECORDER --value 0.05ether --rpc-url $RH_RPC --account robinhood-owner
cast balance $RECORDER --rpc-url $RH_RPC --ether
```

Spend limits in the server (`services/verdict_publisher.py`). Only the API process sends, so they are global:
- at most 180 records per hour; further verdicts wait in the queue as `pending`;
- reusing the same observation returns its existing row. After a confirmed verdict, a newer unchanged
  observation is `deduplicated` while the confirmed observation is under the 300 second refresh interval.
  Once it is at least 300 seconds old, a newer unchanged observation is queued and published again. Each
  published refresh costs gas. A newer observation can supersede pending work. Changed evidence is queued;
- a gas limit of `eth_estimateGas` + 20%, deferred above 1,000,000 gas;
- `maxFeePerGas` = 2 x base fee, capped at 1 gwei, and deferred while the base fee itself is above 1 gwei;
- deferred while the recorder's balance cannot cover gas limit x `maxFeePerGas`.

The 180 per hour comes from the watch: one 4663 scan reserves 23 requests of the shared 1 request per second
RPC budget (`services/rpc_guard.py`, `agent.hunter.SCAN_REQUEST_COST`), so at most about 156 scans an hour can
produce a verdict, and discovery draws on the same budget, so the real number is lower. An unchanged verdict can
be published again after the refresh interval when a newer observation exists, so budget for those refresh
transactions as well as first scans and changed verdicts.
Local Foundry measurements do not include Robinhood Chain's L1 data fee. On this Arbitrum chain it is charged as
extra gas and comes on top. Size the float from the `cast estimate` in step 5, which includes it. At the caps
a single record could cost at most 1,000,000 gas x 1 gwei = 0.001 ETH. The drain's own requests are outside
the watch's budget: about three per record, 540 an hour, which is 0.15 requests per second beside the watch's
1. Insufficient funds returns an eligible row to `pending`. Before a later broadcast, the drain checks eligibility
again. If the observation is then older than 300 seconds, it becomes `dropped` with `StaleObservation` and is not
broadcast. Funding late does not publish old pending rows. Recovery is a fresh scan.

## 8. Configure the server

Exactly one process sends transactions: the API service. On the server the API unit is `shieldbot` (it runs
`uvicorn api:app`) and the Telegram bot unit is `shieldbot-bot`. The API's lifespan starts the verdict drain. The
bot, and every other path, only stores evidence and queues Robinhood Chain verdicts as `pending` in the shared
SQLite database; the bot code never reads the key.

**The API must run as a single uvicorn process: no `--workers` and no `--reload`** (as in `shieldbot-api.service`
in this repository). Two API processes would be two senders racing for the recorder's nonces.

**Only the API service's environment gets `ROBINHOOD_RECORDER_PRIVATE_KEY`.** The API and bot units both load
`/opt/shieldbot/.env`, so do NOT put the key there. Put it in a separate file that only the API unit loads:

```bash
sudo install -d -m 755 -o root -g root /etc/shieldbot   # the directory must exist first
sudo install -m 600 -o root -g root /dev/null /etc/shieldbot/recorder.env
sudo nano /etc/shieldbot/recorder.env        # one line: ROBINHOOD_RECORDER_PRIVATE_KEY=0x...
sudo systemctl edit shieldbot                # the API unit; `systemctl cat shieldbot` must show uvicorn api:app
```

In the editor, add:

```
[Service]
EnvironmentFile=/etc/shieldbot/recorder.env
```

Add to the shared `/opt/shieldbot/.env` (both services may read these; neither is secret):

```
ROBINHOOD_VERDICT_REGISTRY=0x...          # $REGISTRY from step 3
ROBINHOOD_RPC_URL=https://rpc.mainnet.chain.robinhood.com   # optional; this is the default
```

**Hard stop: before restarting anything, check that only the API unit can see the key.** Each command must print
what its comment says. If any does not, stop and fix the configuration first:

```bash
sudo grep -c ROBINHOOD_RECORDER_PRIVATE_KEY /opt/shieldbot/.env   # 0: the shared file has no key
systemctl cat shieldbot-bot | grep -c recorder.env              # 0: the bot does not load the key file
systemctl cat shieldbot | grep -c recorder.env                  # 1: the API loads it
systemctl cat shieldbot | grep ExecStart                        # uvicorn api:app, no --workers, no --reload
```

Restart both services. The logs show:
- API: `Robinhood verdict registry: sending as recorder 0x...`
- bot: `Robinhood verdict registry: verdicts queued for 0x...`, and never `sending`.

With `ROBINHOOD_VERDICT_REGISTRY` missing, evidence is still stored and served at `/api/verdict/...` but nothing
is queued. With the key missing from the API, verdicts are queued as `pending`. When the key is added, the drain
checks each row before broadcast. An observation older than 300 seconds becomes `dropped` and is not broadcast.
Adding the key late does not publish old pending rows. Recovery is a fresh scan. The key is never logged.

Each verdict's `onchain_status` moves through:

| Status | Meaning |
|---|---|
| `pending` | queued; the API's drain records queued verdicts oldest-first |
| `deduplicated` | newer unchanged observation retained while the confirmed anchor remains within the refresh interval; not queued for broadcast |
| `dropped` | observation missing, future-dated, older than 300 seconds or superseded, or queued for another registry (`RegistryChanged`); not broadcast again |
| `sending` | claimed by the drain; the signed transaction's hash is stored before it is broadcast |
| `confirmed` / `reverted` | the receipt of `tx_hash` shows success (sequencer, soft finality) / a revert |
| `submitted` | the node accepted `tx_hash`, but no receipt arrived yet; reconciled later |
| `failed` | the node rejected the signed transaction and no receipt was found; reconciled later |
| `unconfirmed` | the broadcast outcome is unknown and no receipt was found; reconciled later |
| `off` | stored only (another chain, or no registry configured) |

`confirmed` means the sequencer included the transaction (soft finality). It becomes final on the parent chain
(Ethereum) once the sequencer posts the batch that contains it.

Every transaction a verdict has broadcast is kept, with its nonce, signed bytes and fee. At start and whenever the queue
is empty, the drain looks up the receipts of every transaction of up to 5 `submitted`, `failed` or `unconfirmed`
verdicts that are at least 2 minutes old, in one request. A mined transaction makes the verdict `confirmed` or
`reverted`. Otherwise the verdict is queued again until it has signed 5 transactions (sending the same signed
bytes again does not count, because it cannot record twice); after that it is still looked up every 2 minutes, so a
transaction that lands late is reported.

An outbox row is never recorded twice. Before anything is broadcast again, in the same request as the nonce reads, the
drain looks up the receipts of all of the verdict's transactions:
- if any of them is mined, the verdict is finished with it and nothing is sent;
- if the verdict's last nonce is still unused, the drain waits while something else is pending there. Otherwise
  it sends the same signed bytes again or, when those bytes were never stored or their `maxFeePerGas` no longer
  covers the base fee, a replacement at that same nonce at the current fee. Only one transaction per nonce can be
  mined, and every hash is checked, so this never records twice;
- only when every nonce the verdict used has been taken by a transaction that is not one of its own, so none of
  them can ever be mined, does it sign a new transaction at the next nonce.

Sending the same bytes again is not counted as one of the 5, because it cannot record twice. After three such
broadcasts the log warns that a verdict `has re-sent` that transaction: the node is taking those bytes without
sequencing them, so check the RPC endpoint in `ROBINHOOD_RPC_URL`.

Stopping the API waits up to 30 seconds for a send under way to record its outcome before the database closes. If
the process is killed first, or the send takes longer, the verdict stays `sending`. The drain resolves it once it is 2
minutes old (which gives a lagging read replica time to show a mined transaction): at start, after a drain error, and
whenever the queue is empty. A mined transaction finishes it; otherwise it is queued again and the rules above decide
what, if anything, is sent. At 5 signed transactions it is left `unconfirmed`.

**Changing the registry address** (after a redeploy): set the new address in `ROBINHOOD_VERDICT_REGISTRY` in
`/opt/shieldbot/.env`, then restart both units (`shieldbot` and `shieldbot-bot`). Each verdict is bound to the
registry it was queued for, and the drain only ever sends a verdict there. Any verdict still queued for the other
address, including those the bot queues between the two restarts, becomes `dropped` with `RegistryChanged` and is
never sent, so expect a burst of `Verdict record <id> dropped: RegistryChanged` WARNING lines in the API log right
after the restarts. A dropped verdict is visible in that WARNING and at `GET /api/verdict/4663/<token>` (as
`onchain_status: dropped`, `onchain_error: RegistryChanged`) until the next scan of that token stores a newer
verdict. A verdict dropped after it had broadcast a transaction keeps its `tx_hash`, and its receipts are still
looked up every 2 minutes: if that transaction lands, the verdict becomes `confirmed` on the old registry, which its
`registry` field still names. Deduplication only compares verdicts queued for the new registry, so the next scan of
each token is queued for it. Guard watch subjects carry over (see `docs/guard-rescans.md`).

## 9. Smoke test and independent verification

Scan a Robinhood Chain token in the Telegram bot (`rh:0x...`). The bot queues the verdict; the API's drain
checks the queue at least every 10 seconds and records it. Then:

```bash
curl -s https://<api host>/api/verdict/4663/<token> | jq '{verdict, evidence_hash, onchain_status, tx_hash}'
# onchain_status goes pending -> confirmed within a few seconds of the drain picking it up
```

Anyone can check a verdict without trusting ShieldBot's server:

```bash
# 1. Re-hash the canonical evidence document exactly as served.
cast keccak "$(curl -s https://<api host>/api/verdict/4663/<token> | jq -r .canonical)"
# 2. It must equal evidence_hash, and match the on-chain record.
cast call $REGISTRY "latestRecord(address)((uint8,uint64,uint64,bytes32))" <token> --rpc-url $RH_RPC
cast receipt <tx_hash> --rpc-url $RH_RPC
```

The `VerdictRecorded` log in the receipt carries the token (topic 1), the verdict code (topic 2) and the evidence
hash (topic 3), with the observed block and timestamp in the data.

## 10. Guard and guarded transfer: deployment and verification

`script/DeployGuardAndTransfer.s.sol:DeployGuardAndTransfer` deploys both consumers together. The guard's
registry and the transfer's guard, subject, USDG and recipient are immutable. Confirm the intended registry's
verified source and deployment address before proceeding; matching a recorder address alone does not authenticate
a registry's code. Use public addresses only:

```bash
export REGISTRY=0x<verified registry address>
export EXPECTED_RECORDER=0x<current trusted recorder address>
export SUBJECT=0x<subject whose verdict gates the payment>
export USDG=0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168
export RECIPIENT=0x<sole payment recipient>

# Dry run only: no key or transaction is needed.
forge script script/DeployGuardAndTransfer.s.sol:DeployGuardAndTransfer \
  --rpc-url $RH_RPC --sender $OWNER
```

The script rejects chains other than 4663 with `WrongChain`. After its broadcast section, it prints both
deployed addresses and every asserted value, then asserts the registry pin, current recorder, guard pin,
subject, recipient, USDG pin and the canonical Paxos USDG proxy. The proxy literal matches
`services/robinhood_simulation.py`. Require a successful dry run and inspect every printed address.

These assertions execute in the script's local simulation; they are not an atomic on-chain deployment
invariant and cannot undo transactions already included. Repeat the read-only checks below against the
deployed contracts, including the recorder check in case it changed since simulation.

**OWNER-ONLY**, after approval of the dry-run addresses:

```bash
forge script script/DeployGuardAndTransfer.s.sol:DeployGuardAndTransfer \
  --rpc-url $RH_RPC --account robinhood-owner --sender $OWNER --broadcast
```

Save the printed `Guard deployed at` and `Transfer deployed at` addresses. Their creation transaction hashes
are in `broadcast/DeployGuardAndTransfer.s.sol/4663/run-latest.json`.

```bash
export GUARD=0x<deployed guard address>
export TRANSFER=0x<deployed guarded transfer address>

cast call $GUARD "registry()(address)"     --rpc-url $RH_RPC   # $REGISTRY
cast call $REGISTRY "recorder()(address)"  --rpc-url $RH_RPC   # $EXPECTED_RECORDER
cast call $TRANSFER "guard()(address)"    --rpc-url $RH_RPC   # $GUARD
cast call $TRANSFER "subject()(address)"  --rpc-url $RH_RPC   # $SUBJECT
cast call $TRANSFER "recipient()(address)" --rpc-url $RH_RPC  # $RECIPIENT
cast call $TRANSFER "usdg()(address)"     --rpc-url $RH_RPC   # canonical $USDG above
```

Verify **both contracts on all three explorers**, using the same source and `foundry.toml` compiler settings
as deployment. The guard constructor takes `(REGISTRY)`; the transfer constructor takes
`(GUARD, SUBJECT, USDG, RECIPIENT)` in that order. Use the actual deployment arguments throughout.

### Verify the deployment from a clean checkout

With the repository's Python requirements installed, run this from `contracts/base` using the public
addresses above. `OWNER` and `EXPECTED_RECORDER` must be the intended **current** authority addresses:

```bash
python ../../scripts/verify_deployment.py \
  --rpc-url "$RH_RPC" \
  --registry "$REGISTRY" --guard "$GUARD" --transfer "$TRANSFER" \
  --subject "$SUBJECT" --usdg "$USDG" --recipient "$RECIPIENT" \
  --owner "$OWNER" --recorder "$EXPECTED_RECORDER" --max-age 900
```

The script uses `eth_chainId` to verify 4663, then only `eth_getCode` and read-only `eth_call` requests.
It reads no keys, keystores or application configuration and sends no transactions. Every check prints
PASS or FAIL, each contract's runtime size is reported, and any failed check produces a nonzero exit.
The canonical USDG proxy is read directly from `services/robinhood_simulation.py`.

A decodable `check(subject, maxAge)` denial is a successful read, not permission to transfer; an empty
registry normally denies. The 900-second publication-age policy is useful only for actively watched
subjects (see the policy below). Reads use `latest` sequentially, so this is not an atomic snapshot.
Matching getters and nonempty bytecode do not authenticate contract source: complete the explorer
source verification below and use a trusted RPC.

### Guard and transfer on Etherscan

Reuse the `ETHERSCAN_V2_API_KEY` environment and chain-4663 configuration from step 4:

```bash
forge verify-contract $GUARD src/ShieldBotVerdictGuard.sol:ShieldBotVerdictGuard \
  --chain 4663 --verifier etherscan \
  --constructor-args "$(cast abi-encode 'constructor(address)' "$REGISTRY")" --watch

forge verify-contract $TRANSFER src/ShieldBotGuardedTransfer.sol:ShieldBotGuardedTransfer \
  --chain 4663 --verifier etherscan \
  --constructor-args "$(cast abi-encode 'constructor(address,address,address,address)' "$GUARD" "$SUBJECT" "$USDG" "$RECIPIENT")" --watch
```

Confirm verified source and constructor arguments at both `https://robin.etherscan.io/address/$GUARD#code`
and `https://robin.etherscan.io/address/$TRANSFER#code`.

### Guard and transfer on Blockscout

```bash
forge verify-contract $GUARD src/ShieldBotVerdictGuard.sol:ShieldBotVerdictGuard \
  --chain 4663 --verifier blockscout --verifier-url https://robinhoodchain.blockscout.com/api/ \
  --constructor-args "$(cast abi-encode 'constructor(address)' "$REGISTRY")" --watch

forge verify-contract $TRANSFER src/ShieldBotGuardedTransfer.sol:ShieldBotGuardedTransfer \
  --chain 4663 --verifier blockscout --verifier-url https://robinhoodchain.blockscout.com/api/ \
  --constructor-args "$(cast abi-encode 'constructor(address,address,address,address)' "$GUARD" "$SUBJECT" "$USDG" "$RECIPIENT")" --watch
```

Confirm verified source and constructor arguments at both
`https://robinhoodchain.blockscout.com/address/$GUARD?tab=contract` and
`https://robinhoodchain.blockscout.com/address/$TRANSFER?tab=contract`.

### Guard and transfer on Sourcify

```bash
forge verify-contract $GUARD src/ShieldBotVerdictGuard.sol:ShieldBotVerdictGuard \
  --chain 4663 --verifier sourcify --watch

forge verify-contract $TRANSFER src/ShieldBotGuardedTransfer.sol:ShieldBotGuardedTransfer \
  --chain 4663 --verifier sourcify --watch

curl -s https://sourcify.dev/server/v2/contract/4663/$GUARD
curl -s https://sourcify.dev/server/v2/contract/4663/$TRANSFER
# Both must report a match, as in step 4.
```

If requested, add `--creation-transaction-hash` with the creation hash for the corresponding contract.
A submitted verification request is not a completed verification. Confirm all six results separately;
a Sourcify match does not establish Etherscan or Blockscout verification.

Before using the transfer, review the [publication-age policy and bounded watched set](VERDICT_GUARD.md)
and [transfer behavior](GUARDED_TRANSFER.md). Use `maxAge = 600` seconds for the demo **only with
`GUARD_WATCH_MAX_SUBJECTS=1`**, watching exactly the transfer's immutable subject. The production minimum
is **900 seconds at the default four subjects**. Neither is an availability guarantee or observation-age
bound. `MAX_AGE = 300` in Foundry is a test fixture, not guidance: it would deny a healthy token for
roughly 6 to 30 percent of wall time from calculations using the 300 second cadence and measured scan and
publication delays. Confirm the calculation against live records after deployment. See [calculated ages and structural
denial windows](../../docs/guard-rescans.md#structural-denial-windows).
