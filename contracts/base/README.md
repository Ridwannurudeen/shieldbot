# ShieldBot on Base

Threat-attestation contract for ShieldBot scans, posted to the Ethereum Attestation Service on Base mainnet.

## Architecture

`ShieldBotAttestor.sol` wraps the EAS predeploy at `0x4200000000000000000000000000000000000021`. Authorized verifier wallets call `attest()` on the contract; the contract forwards to EAS, which writes a permanent on-chain attestation. EAS is the same primitive Coinbase Verifications uses on Base.

**Schema**

```
address scannedAddress, uint8 riskLevel, string scanType, uint64 sourceChainId, bytes32 evidenceHash, string evidenceURI
```

`sourceChainId` lets ShieldBot publish cross-chain attestations — e.g. attest on Base about a contract on BSC, so the BSC scan history becomes Base-verifiable.

## Setup

Foundry required (`curl -L https://foundry.paradigm.xyz | bash && foundryup`).

```bash
cd contracts/base
forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts ethereum-attestation-service/eas-contracts
forge build
forge test
```

## Deploy (Base mainnet)

```bash
# 1. Register schema once (one-time, gas ~80k)
forge script script/RegisterSchema.s.sol --rpc-url base --broadcast --account base-deployer

# 2. Deploy attestor with the returned schema UID
SCHEMA_UID=0x... INITIAL_VERIFIER=0x... \
  forge script script/DeployAttestor.s.sol --rpc-url base --broadcast --account base-deployer --verify
```

Required env:
- `BASE_RPC_URL` — e.g. `https://mainnet.base.org`
- `BASESCAN_API_KEY` — from basescan.org/myapikey

## Risk levels

| Code | Meaning |
|------|---------|
| 0 | LOW |
| 1 | MEDIUM |
| 2 | HIGH |
| 3 | SAFE |
| 4 | WARNING |
| 5 | DANGER |

## Access control

- **Owner** — can add/remove verifiers and transfer ownership. Initially the deployer.
- **Verifiers** — bot wallets authorized to `attest()` and `revoke()`. Initially set in the constructor; multiple verifiers supported.
- **Public** — read-only access to stats and EAS attestation queries.

EAS contract and schema UID are immutable after deploy.
