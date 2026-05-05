# Deploy ShieldBotAttestor on Base mainnet

End-to-end runbook. Total time: ~10 minutes once the keystore is set up. Total cost: <$5 in Base ETH.

## Prerequisites

- Foundry installed (`curl -L https://foundry.paradigm.xyz | bash && foundryup`)
- The Base identity wallet `0xB2Fae83de08b285cB3D6A77Ff520F6AD669D5f33` funded with ~0.005 ETH on Base
- BaseScan API key from https://basescan.org/myapikey
- (Recommended) Alchemy/QuickNode Base archive endpoint for `BASE_LOGS_RPC_URL`

## 1. Import the deployer key

```bash
cd contracts/base
cast wallet import base-deployer --interactive
# paste private key for 0xB2Fae83…D5f33 when prompted, set a password
```

This creates an encrypted keystore at `~/.foundry/keystores/base-deployer`. The plaintext key never touches disk.

## 2. Set env

```bash
export BASE_RPC_URL=https://mainnet.base.org
export BASESCAN_API_KEY=<your basescan key>
```

## 3. Register the EAS schema (one-time, ~80k gas ≈ $0.05)

```bash
forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts ethereum-attestation-service/eas-contracts
forge build
forge script script/RegisterSchema.s.sol --rpc-url base --broadcast --account base-deployer
```

Output will print `Registered schema UID: 0x...`. **Copy that UID** — you'll need it next. Schema UID is deterministic from the schema string + resolver + revocability flag, so re-running this script reverts (which is expected; you only register once).

Schema string:
```
address scannedAddress,uint8 riskLevel,string scanType,uint64 sourceChainId,bytes32 evidenceHash,string evidenceURI
```

## 4. Generate the bot verifier wallet

Don't reuse `0xB2Fae83…` for hot signing — that's the identity wallet for credentials. Generate a fresh keypair for the bot:

```bash
cast wallet new
# prints: Address: 0x...   Private key: 0x...
```

**Save the private key in a password manager.** Add `BASE_VERIFIER_PRIVATE_KEY=0x...` to the VPS `.env`. The address is the `INITIAL_VERIFIER` for the next step.

## 5. Deploy + verify the attestor (~250k gas ≈ $0.20)

```bash
SCHEMA_UID=<from step 3> \
INITIAL_VERIFIER=<verifier address from step 4> \
  forge script script/DeployAttestor.s.sol \
    --rpc-url base --broadcast --account base-deployer \
    --verify --etherscan-api-key $BASESCAN_API_KEY
```

Output prints `Deployed at: 0x...`. **Copy that address** — set `BASE_ATTESTOR_ADDRESS=0x...` on the VPS `.env`.

## 6. Sanity check

```bash
# Read totalAttestations (should be 0 right after deploy)
cast call <BASE_ATTESTOR_ADDRESS> "totalAttestations()(uint256)" --rpc-url base

# Verify contract is verified on BaseScan
echo "https://basescan.org/address/<BASE_ATTESTOR_ADDRESS>#code"
```

## 7. Fund the verifier wallet

Send ~0.001 ETH to the verifier address (step 4) on Base. Each `attest()` call costs ~150k gas (~$0.10), so this funds ~10 attestations to start.

## 8. Wire VPS

SSH to `root@75.119.153.252`, edit `/opt/shieldbot/.env`:
```
BASE_RPC_URL=https://mainnet.base.org
BASE_ATTESTOR_ADDRESS=0x...           # from step 5
BASE_ATTESTOR_SCHEMA_UID=0x...        # from step 3 (defense-in-depth filter on indexer reads)
BASE_VERIFIER_PRIVATE_KEY=0x...       # from step 4
BASE_LOGS_RPC_URL=https://...         # paid archive endpoint
```

Restart: `systemctl restart shieldbot.service`. Tail logs to confirm:
```
Base EAS Attestor: enabled
```

## 9. Smoke test

Run a scan via Telegram bot or `/api/scan`. Within ~5s, check the attestor's stats:
```bash
cast call <BASE_ATTESTOR_ADDRESS> "totalAttestations()(uint256)" --rpc-url base
# should be 1
```

Find the attestation on EAS:
```
https://base.easscan.org/attestations?attester=<BASE_ATTESTOR_ADDRESS>
```

## 10. Lock down

- Verify the deployer (`0xB2Fae83…`) is `owner()` on the attestor.
- Verifier wallet should hold only operating gas (~0.005 ETH max).
- If the verifier key is ever compromised: from `0xB2Fae83…`, call `setVerifier(<compromised>, false)` and `setVerifier(<new>, true)`.

## What this gives you

- **Base Builder Talent credential** — verified contract from `0xB2Fae83…` auto-mints it.
- **Real Base integration** — every ShieldBot scan now produces a permanent EAS attestation, queryable on `base.easscan.org`.
- **Cross-chain attestations** — `sourceChainId` field means BSC scans are now Base-verifiable too.
- **Same primitive Coinbase Verifications uses** — EAS schema `0xf8b05c79...0de9` (Verified Account) lives on the same contract.
