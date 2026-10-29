# Deploy ShieldBotVerdictRegistry on BOT Chain (677)

Owner runbook for the BOT Chain registry. Run the commands from `contracts/base` unless a step says otherwise. The runbook uses a Foundry keystore for the owner and a separate recorder keystore for the server. Do not deploy or send a transaction until the code release and all required gates are approved.

## Before starting

The registry is not deployed yet. The deploy script accepts chain 677 and chain 4663 only. The 677 publisher uses legacy transactions with the node's gas price. The Blockscout verification flow has not been tried for this registry and remains unverified until the owner completes step 5.

Set the public addresses after creating the recorder and confirming the owner address:

```bash
export BOTCHAIN_RPC_URL=https://rpc.botchain.ai
export OWNER=<robinhood-owner address>
export RECORDER=<botchain-recorder address>
export USDT=0xaBabc7Ddc03e501d190C676BF3d92ef0e6e87a3C
```

Use the full addresses in the owner's terminal. The placeholders above are not addresses.

## 0. Confirm the sender topology

Before deploying, the owner checks which unit runs the one verdict drain and reads the `BACKGROUND_WORKERS` mode from the server environment file:

```bash
systemctl is-active shieldbot-workers
grep '^BACKGROUND_WORKERS=' /opt/shieldbot/.env
```

If `shieldbot-workers` is active, it is the only sender. Put the 677 recorder key in the existing root-owned recorder environment file loaded by that unit. When running `--cutover` or `--rollback`, stop and start the workers unit around the command:

```bash
SHA=<commit>
if systemctl is-active --quiet shieldbot-workers; then
  sudo systemctl stop shieldbot-workers
  bash /root/shieldbot-deploy.sh --cutover "$SHA"
  sudo systemctl start shieldbot-workers
else
  bash /root/shieldbot-deploy.sh --cutover "$SHA"
fi
```

For a rollback, use the backup directory printed by the deploy command. A rollback restores the database saved at that cutover and loses every row written since; to keep the data, run `--cutover` with the previous release instead (see Rollback of P3 configuration):

```bash
BACKUP=<backup-directory>
if systemctl is-active --quiet shieldbot-workers; then
  sudo systemctl stop shieldbot-workers
  bash /root/shieldbot-deploy.sh --rollback "$BACKUP"
  sudo systemctl start shieldbot-workers
else
  bash /root/shieldbot-deploy.sh --rollback "$BACKUP"
fi
```

If the workers unit is not active, the API unit follows the existing Robinhood sender pattern. Only the one active sender unit may load either recorder key. If the topology is unclear or more than one sender would load a key, stop here.

## 1. Create and install the recorder keystore

Create the encrypted keystore and capture only the address it prints:

```bash
cast wallet new ~/.foundry/keystores botchain-recorder
```

Never run a bare `cast wallet new`. Use the existing root-owned, mode 600 environment file loaded by the active sender. Do not recreate that file. In a private terminal, decrypt the keystore directly into it. The pipeline below writes the environment variable name and the decrypted key without printing the key or putting it in shell history:

```bash
sudo -v
sudo grep -c '^ROBINHOOD_RECORDER_PRIVATE_KEY=' /etc/shieldbot/recorder.env
sudo grep -c '^BOTCHAIN_RECORDER_PRIVATE_KEY=' /etc/shieldbot/recorder.env || true
sudo awk -F= '/^ROBINHOOD_RECORDER_PRIVATE_KEY=/{print length($2)}' /etc/shieldbot/recorder.env
```

Before continuing, the expected values are Robinhood key count `1`, Robinhood value length `66`, and BOT Chain key count `0`. Stop if any value differs. Ensure the existing file ends with a newline without rewriting it, then append the BOT Chain key:

```bash
sudo sh -c 'tail -c1 /etc/shieldbot/recorder.env | od -An -tu1 | tr -d " " | grep -qx "10" || echo >> /etc/shieldbot/recorder.env'
cast wallet decrypt-keystore botchain-recorder | sed -n 's/^.*private key is: \(0x[0-9a-fA-F]*\)$/BOTCHAIN_RECORDER_PRIVATE_KEY=\1/p' | sudo tee -a /etc/shieldbot/recorder.env >/dev/null
sudo grep -c '^ROBINHOOD_RECORDER_PRIVATE_KEY=' /etc/shieldbot/recorder.env
sudo grep -c '^BOTCHAIN_RECORDER_PRIVATE_KEY=' /etc/shieldbot/recorder.env
sudo awk -F= '/^ROBINHOOD_RECORDER_PRIVATE_KEY=/{print length($2)}' /etc/shieldbot/recorder.env
sudo awk -F= '/^BOTCHAIN_RECORDER_PRIVATE_KEY=/{print length($2)}' /etc/shieldbot/recorder.env
sudo chown root:root /etc/shieldbot/recorder.env
sudo chmod 600 /etc/shieldbot/recorder.env
```

Enter the keystore password only at the prompt. Clear the terminal after the command. Do not copy the key into chat, shell history, `/opt/shieldbot/.env`, or any other file. The recorder key belongs only in the environment file loaded by the single active sender.
After appending, both key counts must be `1` and both private key value lengths must be `66`. Stop otherwise. Do not display the key value.

## 2. Fund the owner and recorder

On Thu 29, send 0.05 BOT to the `robinhood-owner` address. Confirm that address with:

```bash
cast wallet address --account robinhood-owner
```

Immediately after step 1, send 0.25 BOT to the recorder address. Both transfers come from the demo wallet `0xF150...fC5F` in the browser wallet on BOT Chain. The team offered mainnet gas on 2 Oct if more funding is needed.

Measured at 20 gwei, deployment uses 638,314 gas, about 0.0128 BOT, and a record uses 99,431 gas, about 0.002 BOT. BOT was about $12.40 in the live check dated 25 Oct 2026. These are estimates, not a promise of future fees or price.

## 3. Dry run

From `contracts/base`, set the initial recorder and simulate the deploy. This command does not broadcast:

```bash
export BOTCHAIN_RPC_URL=https://rpc.botchain.ai
export INITIAL_RECORDER=$RECORDER
~/.foundry/bin/forge script script/DeployVerdictRegistry.s.sol --rpc-url botchain --sender "$OWNER" --legacy -vvvv
```

Confirm that the script accepts chain 677, shows the expected owner and recorder, and estimates about 638,000 gas. Stop if the chain, addresses, or estimate differ materially.

## 4. Deploy (owner only)

Broadcast only after the dry run and release gates are approved. The command signs with the `robinhood-owner` keystore and does not put a plaintext key on the command line:

```bash
~/.foundry/bin/forge script script/DeployVerdictRegistry.s.sol --rpc-url botchain --account robinhood-owner --legacy --broadcast
```

Save the deployed registry address and deployment transaction hash. The broadcast output and `broadcast/DeployVerdictRegistry.s.sol/677/run-latest.json` contain these values. Fill them into [docs/DEPLOYMENTS.md](../../docs/DEPLOYMENTS.md).

Set the registry address from the deployment output before continuing:

```bash
export REGISTRY=<deployed registry address>
```

## 5. Verify on Blockscout

Try the Etherscan-compatible Blockscout verifier first. `foundry.toml` reads `ETHERSCAN_V2_API_KEY` for its Etherscan entries, so set it to any value; Blockscout needs no key:

```bash
ETHERSCAN_V2_API_KEY=blockscout ~/.foundry/bin/forge verify-contract "$REGISTRY" src/ShieldBotVerdictRegistry.sol:ShieldBotVerdictRegistry --chain-id 677 --verifier blockscout --verifier-url https://scan.botchain.ai/api/ --constructor-args "$(cast abi-encode 'constructor(address)' "$RECORDER")"
```

This verification path is unverified until tried. A successful submission is not a verified result. Confirm the contract source and constructor argument on `https://scan.botchain.ai/address/$REGISTRY?tab=contract`.

If that command does not verify the source, use the standard JSON input form with the Blockscout UI. Generate the input from the exact source and compiler settings in `foundry.toml`:

```bash
~/.foundry/bin/forge verify-contract "$REGISTRY" src/ShieldBotVerdictRegistry.sol:ShieldBotVerdictRegistry --chain-id 677 --show-standard-json-input
```

Submit the resulting standard JSON input through the Blockscout contract verification form and confirm its result there.

To check the registry without trusting the explorer, compare it with the source from the repo root. The command compares the code on BOT Chain and on Robinhood Chain with a fresh build and reads Sourcify's match for the Robinhood Chain copy, and exits 0 only when all three agree:

```bash
(cd contracts/base && forge build) && python -m scripts.check_botchain_registry_code
```

## 6. Check the deployment before configuring the server

Every chain read in this step uses the BOT Chain RPC explicitly. Confirm nonempty code, the keystore owner, and the funded recorder:

```bash
cast code "$REGISTRY" --rpc-url https://rpc.botchain.ai
cast call "$REGISTRY" 'owner()(address)' --rpc-url https://rpc.botchain.ai
cast call "$REGISTRY" 'recorder()(address)' --rpc-url https://rpc.botchain.ai
```

The code result must not be `0x`. `owner()` must equal the address from `cast wallet address --account robinhood-owner`; `recorder()` must equal the funded recorder address.

Estimate a `record` call from the recorder. Replace the descriptive bytes32 placeholder with the 32 byte value `0x` followed by 62 zeros and `01`. It is a 32 byte value, not a literal to paste as written:

```bash
cast estimate "$REGISTRY" 'record(address,uint8,bytes32,uint64)' "$USDT" 0 <32-byte-value> 1 --from "$RECORDER" --rpc-url https://rpc.botchain.ai
```

The estimate must be below 833,334 gas. Stop if any read or estimate fails or returns a different authority.

## 7. Configure the active sender

Add these lines to `/opt/shieldbot/.env`, with no inline comments:

```text
BOTCHAIN_VERDICT_REGISTRY=<registry address>
BOTCHAIN_RPC_URL=https://rpc.botchain.ai
```

The `BOTCHAIN_RECORDER_PRIVATE_KEY` line stays in the root-owned, mode 600 recorder environment file loaded only by the active sender unit. Restart the active sender and the bot because each process reads its registry setting at startup. Read the sender log and the bot log. Confirm the sender shows `BOT Chain verdict registry: recorder ready 0x...`, look for `sending as recorder` for both chains, and confirm there are no repeated restarts for 20 seconds. In the bot log, confirm `BOT Chain verdict registry: verdicts queued for 0x...`:

```bash
if systemctl is-active --quiet shieldbot-workers; then
  sudo systemctl restart shieldbot-workers
  sudo journalctl -u shieldbot-workers -n 100 --no-pager
else
  sudo systemctl restart shieldbot
  sudo journalctl -u shieldbot -n 100 --no-pager
fi
sudo systemctl restart shieldbot-bot
sudo journalctl -u shieldbot-bot -n 100 --no-pager
```

## 8. Smoke check

In Telegram, run `/token bot:<USDT address>` as the first scan in the bot's cache window. Locate the resulting transaction hash in the publisher log, then check its receipt and the latest registry value:

```bash
cast receipt <transaction hash> --rpc-url https://rpc.botchain.ai
cast call "$REGISTRY" 'latestRecord(address)((uint8,uint64,uint64,bytes32))' "$USDT" --rpc-url https://rpc.botchain.ai
```

The receipt must contain `VerdictRecorded`. Its evidence hash must match `/api/verdict/677/<USDT address>`, and `latestRecord` must agree with that verdict and evidence hash. A failed check is not a recorded smoke result.

## Guard and guarded transfer

After the registry, the owner deploys `ShieldBotVerdictGuard` and `ShieldBotGuardedTransfer` with `script/DeployGuardAndTransfer.s.sol`, the script used on Robinhood Chain. On BOT Chain it pins Tether USD as the transfer's stablecoin, and it refuses any other address in `USDG`. The guard reads the registry above. The transfer moves a caller's USDT to `RECIPIENT` only while the guard allows `SUBJECT`.

`SUBJECT` is COW (`0x5aF9A0E7472134A6A5ad02a7D327e83ddD24b337`): it has BDEX V2 pools with WBOT and USDT, and its latest registry verdict was LOW when this section was written. Check that before deploying, because the transfer refuses every call while the subject has no allowed verdict:

```bash
export REGISTRY=0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138
export SUBJECT=0x5aF9A0E7472134A6A5ad02a7D327e83ddD24b337
cast call "$REGISTRY" 'latestRecord(address)((uint8,uint64,uint64,bytes32))' "$SUBJECT" --rpc-url https://rpc.botchain.ai
```

The first field must be `1` (LOW) or `2` (MEDIUM).

Dry run, which sends nothing:

```bash
export BOTCHAIN_RPC_URL=https://rpc.botchain.ai
export EXPECTED_RECORDER=$RECORDER
export USDG=$USDT
export RECIPIENT=$OWNER
~/.foundry/bin/forge script script/DeployGuardAndTransfer.s.sol:DeployGuardAndTransfer --rpc-url botchain --sender "$OWNER" --legacy
```

On 2026-10-28 the dry run showed chain 677, every pinned address equal to its input, the guard at `0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e` and the transfer at `0x336254bA85406D9af39357101b688E2B757751b3` (the owner's nonces 1 and 2, so the same addresses as on Robinhood Chain), and 923,790 gas, about 0.0185 BOT at 20 gwei. Stop if the chain, an address or the estimate differs materially.

Deploy (owner only). The command signs with the `robinhood-owner` keystore:

```bash
~/.foundry/bin/forge script script/DeployGuardAndTransfer.s.sol:DeployGuardAndTransfer --rpc-url botchain --account robinhood-owner --legacy --broadcast
```

The script's assertions run in its simulation before anything is sent; the reads below check the deployed contracts. Save both addresses and transaction hashes from `broadcast/DeployGuardAndTransfer.s.sol/677/run-latest.json` into [docs/DEPLOYMENTS.md](../../docs/DEPLOYMENTS.md), then read them back:

```bash
export GUARD=<deployed guard address>
export TRANSFER=<deployed transfer address>
cast call "$GUARD" 'registry()(address)' --rpc-url https://rpc.botchain.ai
cast call "$GUARD" 'check(address,uint64)(bool,uint8)' "$SUBJECT" 2592000 --rpc-url https://rpc.botchain.ai
cast call "$TRANSFER" 'guard()(address)' --rpc-url https://rpc.botchain.ai
cast call "$TRANSFER" 'usdg()(address)' --rpc-url https://rpc.botchain.ai
```

`registry()` must be the registry, `check` must return `true` and `0` while the subject's verdict is allowed and at most 30 days old, `guard()` must be the guard and `usdg()` must be USDT.

Verify both on Blockscout the same way as the registry (on 2026-10-29 both returned `Pass - Verified`):

```bash
ETHERSCAN_V2_API_KEY=blockscout ~/.foundry/bin/forge verify-contract "$GUARD" src/ShieldBotVerdictGuard.sol:ShieldBotVerdictGuard --chain-id 677 --verifier blockscout --verifier-url https://scan.botchain.ai/api/ --watch --constructor-args "$(cast abi-encode 'constructor(address)' "$REGISTRY")"
ETHERSCAN_V2_API_KEY=blockscout ~/.foundry/bin/forge verify-contract "$TRANSFER" src/ShieldBotGuardedTransfer.sol:ShieldBotGuardedTransfer --chain-id 677 --verifier blockscout --verifier-url https://scan.botchain.ai/api/ --watch --constructor-args "$(cast abi-encode 'constructor(address,address,address,address)' "$GUARD" "$SUBJECT" "$USDT" "$OWNER")"
```

A wallet uses the transfer by approving USDT to it and calling `transfer(amount, maxAge)`, where `amount` is in USDT's 6 decimal units and `maxAge` is the oldest verdict, in seconds, the caller accepts. The call reverts with `NotAllowed` when the guard refuses the subject. The guard itself only reads, so calls to it are not transactions.

## Five token checks recorded

Before scanning, choose and name one snapshot block. At that block, calculate each candidate token's total depth as its WBOT reserves summed across every BDEX V2 pair plus its WBOT balance summed across every V3 pool. Exclude WBOT and USDT. Require deployed code and valid token metadata. Sort candidates by total depth descending, then by lowercase token address ascending. Record the snapshot block, all candidate inputs, and the five selected tokens in this file before scanning.

Fill this table for every candidate before scanning. Add rows when there are more candidates than shown, and mark exactly five selected tokens after sorting:

| Snapshot block | Candidate token address | Code present | Metadata valid | V2 WBOT reserves | V3 WBOT balances | Total depth | Selected |
|---|---|---|---|---|---|---|---|
| To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | Rank 1 |
| To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | Rank 2 |
| To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | Rank 3 |
| To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | Rank 4 |
| To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | To be recorded | Rank 5 |

Scan each selected token with `/token bot:<address>` as its first scan inside the bot's cache window. Count only five distinct successful registry receipts from the expected registry whose evidence hashes match the corresponding `/api/verdict/677/<address>` responses. Describe the result as **five token checks recorded**. Do not claim that it meets the team's requirement until the team confirms.

All five records are separate `record()` transactions (the publisher sends `RECORD_SELECTOR`, `services/verdict_publisher.py:100`; it never calls `recordBatch`), and because of `onlyRecorder` (`contracts/base/src/ShieldBotVerdictRegistry.sol:91,117-119`) every one of them comes from the single recorder wallet. If the team requires interactions from different user wallets, these records do not satisfy it. ShieldBot never fakes users with its own wallets; the honest option is then a contract that users call themselves, for example a guarded action, written up as a follow up after the team answers.

## Rollback of P3 configuration

Turning BOT Chain publishing off needs no code rollback: remove the 677 settings below and restart, and the P3 code keeps 4663 publishing on with 677 off. Do not use `--rollback <backup-directory>` for this. It restores the database saved at the P3 cutover, so every 4663 verdict evidence and transaction row written since then is lost, and verdicts already recorded on Robinhood Chain lose their documents.

Remove only the 677 registry and RPC settings from `/opt/shieldbot/.env` and only the BOTCHAIN key line from the recorder environment file:

```bash
sudo sed -i '/^BOTCHAIN_VERDICT_REGISTRY=/d; /^BOTCHAIN_RPC_URL=/d' /opt/shieldbot/.env
sudo sed -i '/^BOTCHAIN_RECORDER_PRIVATE_KEY=/d' /etc/shieldbot/recorder.env
```

Do not remove or recreate `/etc/shieldbot/recorder.env`. Restart the active sender as shown in step 7, then restart the bot and read its log:

```bash
sudo systemctl restart shieldbot-bot
sudo journalctl -u shieldbot-bot -n 100 --no-pager
```

Confirm 4663 publishing remains on and 677 publishing is off. The bot log should show `BOT Chain verdict registry: disabled (set BOTCHAIN_VERDICT_REGISTRY to enable)`. The 677 registry remains onchain. Its deployment is not reversible.

To also revert the P3 code, P3 changed no database schema, so go back on code only and keep the data, using the release that ran before P3 (the deploy command prints it as the rollback point). Use the step 0 workers pattern if the workers unit is active:

```bash
bash /root/shieldbot-deploy.sh --cutover <previous release sha>
```

Use `--rollback <backup-directory>` only for a failure found right at the P3 cutover, before new verdict rows matter.
