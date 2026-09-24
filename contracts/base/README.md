# ShieldBot contracts: Robinhood Chain and Base

## Robinhood Chain verdict registry

`src/ShieldBotVerdictRegistry.sol` records token verdicts and evidence hashes directly on Robinhood Chain
(chain 4663). It is non-upgradeable, holds no funds and makes no external calls. One recorder writes verdicts;
the owner can rotate the recorder through `Ownable2Step` access control. Ownership renunciation is disabled
to preserve that recovery path.

| Code | Registry verdict |
|------|------------------|
| 0 | UNKNOWN (incomplete scan; also the default for an unrecorded token) |
| 1 | LOW |
| 2 | MEDIUM |
| 3 | HIGH |
| 4 | HONEYPOT |

See [the Robinhood deployment runbook](DEPLOY_ROBINHOOD.md) for deployment, source verification on Etherscan,
Blockscout and Sourcify, recorder rotation, and independently checking an evidence hash.

`src/ShieldBotVerdictGuard.sol` lets consumers require a fresh LOW or MEDIUM verdict on-chain. It is
ownerless and takes each caller's publication-age limit in seconds; zero always denies. See the
[guard policy and validation report](VERDICT_GUARD.md) for reason codes, trust assumptions, tests and gas.

The sections below describe the separate **Base EAS attestor**. Its risk codes are not registry verdict codes.

## Base EAS attestor

Threat-attestation contract for ShieldBot scans, posted to the Ethereum Attestation Service on Base mainnet.

## Architecture

`ShieldBotAttestor.sol` wraps the EAS predeploy at `0x4200000000000000000000000000000000000021`. Authorized verifier wallets call `attest()` on the contract; the contract forwards to EAS, which writes a permanent on-chain attestation. EAS is the same primitive Coinbase Verifications uses on Base.

**Schema**

```
address scannedAddress, uint8 riskLevel, string scanType, uint64 sourceChainId, bytes32 evidenceHash, string evidenceURI
```

`sourceChainId` records the chain of the scanned address, so an attestation on Base can describe a contract on BSC or another chain.

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

## Base EAS risk levels

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
