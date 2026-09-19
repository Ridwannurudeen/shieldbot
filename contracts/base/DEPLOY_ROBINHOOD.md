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
export OWNER=0x<owner address>
export RECORDER=0x<recorder address>
```

## 1. Build and test

```bash
forge build --sizes
forge test -vv
```

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

The same command against a local `anvil` (no fork, chain id 31337) was run during development and printed
`owner(): 0xf39F...2266`, `recorder(): 0x7099...79C8` and `SIMULATION COMPLETE`; anvil's block number stayed 0.

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

## 4. Verify the source on Sourcify (chain 4663)

Sourcify lists chain 4663 as supported. Verification needs no API key:

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

The Foundry gas report measured about 117k execution gas for a first record. If the estimate is near 833,334 or
above it, stop and raise `MAX_GAS_LIMIT` in `services/verdict_publisher.py` before configuring the server. If the
node refuses the estimate because the recorder has no ETH yet, run it again after funding it in step 7.

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

Never call `renounceOwnership()` (inherited from OpenZeppelin). It removes the owner permanently, so the recorder
could never be rotated again, not even after the recorder key is compromised.

## 7. Fund the recorder (OWNER-ONLY)

The recorder pays gas for every `record()`. The first record for a token measured 116,795 execution gas in the
Foundry gas report; with the 21,000 base cost and calldata, a `record()` transaction is at most about 140k gas.
The base fee on a recorded Robinhood Chain block (65,526,359) was 0.056 gwei, which makes one record about
0.0000079 ETH. Send a small float, for example:

```bash
cast send $RECORDER --value 0.002ether --rpc-url $RH_RPC --account robinhood-owner
cast balance $RECORDER --rpc-url $RH_RPC --ether
```

Spend limits in the server (`services/verdict_publisher.py`). Only the API process sends, so they are global:
- at most 60 records per hour; further verdicts wait in the queue as `pending`;
- a gas limit of `eth_estimateGas` + 20%, deferred above 1,000,000 gas;
- `maxFeePerGas` = 2 x base fee, capped at 1 gwei, and deferred while the base fee itself is above 1 gwei;
- deferred while the recorder's balance cannot cover gas limit x `maxFeePerGas`.

At the full 60 records per hour and the fee above, the recorder spends about 0.0005 ETH per hour. At the caps a
single record could cost at most 1,000,000 gas x 1 gwei = 0.001 ETH. When the recorder runs out of ETH, nothing
is lost: verdicts stay `pending` and are recorded once it is funded again.

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
is queued. With the key missing from the API, verdicts are queued as `pending` and wait until it is added. The key
is never logged.

Each verdict's `onchain_status` moves through:

| Status | Meaning |
|---|---|
| `pending` | queued; the API's drain records queued verdicts oldest-first |
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

A verdict is never recorded twice. Before anything is broadcast again, in the same request as the nonce reads, the
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
