# Deployed contracts

Every ShieldBot contract deployed to a public chain. Each value below was read from the chain on
**2026-09-24** with read-only calls (`eth_call`, `eth_getCode`, transaction receipts and blocks) on the
public RPCs `https://mainnet.base.org` and `https://bsc-dataseed1.binance.org/`; creation transactions and
event logs of the Base attestor come from base.blockscout.com, and source matches from Sourcify. The two
BSC deployment transactions are the ones the repository already recorded (`docs/DEPLOYMENT.md` for the
verifier, `bsc.address` for the unused second one); their receipts, read from
`https://bsc-dataseed1.binance.org/`, show each creating the contract listed below. A
contract only receives records while the service that writes to it holds its key, so this page says
what can write to each contract, not whether production is doing so.

| Contract | Chain | Address | Deployed (UTC) | Records on 2026-09-24 | Written by |
|---|---|---|---|---|---|
| `ShieldBotAttestor` | Base (8453) | [`0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B`](https://basescan.org/address/0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B) | 2026-05-05 15:23:51 | 1 attestation | `bot.py` through `utils/base_attestor.py` |
| `ShieldBotVerifier` | BNB Smart Chain (56) | [`0x867aE7449af56BB56a4978c758d7E88066E1f795`](https://bscscan.com/address/0x867aE7449af56BB56a4978c758d7E88066E1f795) | 2026-02-12 11:25:33 | 20 scans | `bot.py` through `utils/onchain_recorder.py` |
| `ShieldBotVerifier` (second, unused) | BNB Smart Chain (56) | [`0x0AD4E23f5762CEd4D3278Da958e109F2A09337B2`](https://bscscan.com/address/0x0AD4E23f5762CEd4D3278Da958e109F2A09337B2) | 2026-03-02 13:57:22 | 0 scans | nothing in this repository |
| `ShieldBotVerdictRegistry` | Robinhood Chain (4663) | not deployed | | | |
| `ShieldBotVerdictGuard` | Robinhood Chain (4663) | not deployed | | | |
| `ShieldBotGuardedTransfer` | Robinhood Chain (4663) | not deployed | | | |

Every owner below is an externally owned account (`eth_getCode` returns no code), not a multisig.

## ShieldBotAttestor on Base

- **Address:** `0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B`
  ([Basescan](https://basescan.org/address/0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B),
  [Blockscout](https://base.blockscout.com/address/0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B),
  [EAS explorer](https://base.easscan.org/address/0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B))
- **Source:** [contracts/base/src/ShieldBotAttestor.sol](../contracts/base/src/ShieldBotAttestor.sol);
  Sourcify exact match (creation and runtime bytecode), verified 2026-06-27.
- **Deployed:** transaction [`0xf7da9d8c8736078996e12897f0694c68da2dc02428dd3ce32164708176737cf7`](https://basescan.org/tx/0xf7da9d8c8736078996e12897f0694c68da2dc02428dd3ce32164708176737cf7),
  block 45,602,642, 2026-05-05 15:23:51 UTC, from `0xfE3f3cEAb7266b5de5Ae8738727b6cf82F7Be76c`.
- **Owner:** `owner()` = `0xfE3f3cEAb7266b5de5Ae8738727b6cf82F7Be76c`; `pendingOwner()` is the zero
  address (two-step ownership, no transfer under way).
- **Verifier:** `verifiers(0x2f3EB1Eb5EBDab566aCa7b7bB5e3228846218483)` = true. It is the only address any
  `VerifierUpdated` event has authorized (the constructor's), and it is still authorized. The owner is
  not a verifier.
- **EAS:** `eas()` = `0x4200000000000000000000000000000000000021`, the Base EAS predeploy.
- **Schema UID:** `schemaUID()` = `0xdc6d6de6206816e45413eb5b9e4ff88a6131bc04069c2933fb50f6a807852e9e`
  ([schema on EAS](https://base.easscan.org/schema/view/0xdc6d6de6206816e45413eb5b9e4ff88a6131bc04069c2933fb50f6a807852e9e)). The Base schema registry
  (`0x4200000000000000000000000000000000000020`) holds it with no resolver, revocable, as
  `address scannedAddress,uint8 riskLevel,string scanType,uint64 sourceChainId,bytes32 evidenceHash,string evidenceURI`.
- **Records:** `totalAttestations()` = 1 and `uniqueAddressCount()` = 1. The one attestation,
  UID `0x0f34befeb4b0ed4f17b43d0380c55bf0c2931b35bd0417b8d427922f6f757b47` (transaction [`0xae397beb7a0483c6fbdd79e6d8634d79e97e45d8111980a1a1cac3f8cbdcabe4`](https://basescan.org/tx/0xae397beb7a0483c6fbdd79e6d8634d79e97e45d8111980a1a1cac3f8cbdcabe4)),
  was posted at 2026-05-05 15:43:55 UTC, twenty minutes after deployment, with scan type `approval` and
  source chain 1. No code in this repository sends the scan type `approval`.
- **Risk codes:** 0 = LOW, 1 = MEDIUM, 2 = HIGH, 3 = SAFE, 4 = WARNING, 5 = DANGER.
- **Writes:** `utils/base_attestor.py` (`attest_fire_and_forget`), called from `bot.py` for `/report` and
  for contract and token scans, only when `BASE_ATTESTOR_ADDRESS` and `BASE_VERIFIER_PRIVATE_KEY` are set.
  `services/base_attestation_service.py` reads its attestations through the EAS GraphQL API when
  `BASE_ATTESTOR_ADDRESS` is set.

## ShieldBotVerifier on BNB Smart Chain

- **Address:** `0x867aE7449af56BB56a4978c758d7E88066E1f795`
  ([BscScan](https://bscscan.com/address/0x867aE7449af56BB56a4978c758d7E88066E1f795))
- **Deployed:** transaction [`0x021fb404910c2621497bcda167ffcc70e8ece846d1ade8066ab5ad87f13b6bbd`](https://bscscan.com/tx/0x021fb404910c2621497bcda167ffcc70e8ece846d1ade8066ab5ad87f13b6bbd),
  block 80,777,511, 2026-02-12 11:25:33 UTC, from `0xfE3f3cEAb7266b5de5Ae8738727b6cf82F7Be76c`.
- **Owner and recorder:** `owner()` and `verifier()` are both `0xc62A8ae13a2Ea84F443dA5681501e7aaC43dC6F5`,
  so one key both records scans and owns the contract: if it leaks, no other key can rotate the recorder
  away from it.
- **Records:** `totalScans()` = 20; `getStats()` returns (20, 20).
- **Source:** Sourcify partial match (verified 2026-05-21), not an exact one. The deployed contract is not
  [contracts/ShieldBotVerifier.sol](../contracts/ShieldBotVerifier.sol) as it stands: that source declares
  `uniqueAddressCount()`, and `eth_call` to it reverts on the deployed contract.
- **Risk codes** (in the repository source): 0 = LOW, 1 = MEDIUM, 2 = HIGH, 3 = SAFE, 4 = WARNING,
  5 = DANGER. An address never recorded also reads 0 (LOW) from `latestScans`, so read
  `hasBeenScanned(address)` first.
- **Writes:** `utils/onchain_recorder.py`, which has this address built in, called from `bot.py` for
  `/report` and for contract and token scans, only when `BOT_WALLET_PRIVATE_KEY` is set.

## Second ShieldBotVerifier on BNB Smart Chain (unused)

- **Address:** `0x0AD4E23f5762CEd4D3278Da958e109F2A09337B2`
  ([BscScan](https://bscscan.com/address/0x0AD4E23f5762CEd4D3278Da958e109F2A09337B2))
- **Deployed:** transaction [`0x80774cf3c125bfc9ca719cd05a80793b9be8b403f27ec9a6b4bd1633aad9d00d`](https://bscscan.com/tx/0x80774cf3c125bfc9ca719cd05a80793b9be8b403f27ec9a6b4bd1633aad9d00d),
  block 84,252,849, 2026-03-02 13:57:22 UTC, from `0xfE3f3cEAb7266b5de5Ae8738727b6cf82F7Be76c`.
- **Owner and recorder:** `owner()` and `verifier()` are both `0xfE3f3cEAb7266b5de5Ae8738727b6cf82F7Be76c`.
- **Records:** `totalScans()` = 0.
- **Source:** no Sourcify match. [bsc.address](../bsc.address) (hackathon metadata) lists this address as
  the verifier; no code in this repository writes to it or reads from it.

## Robinhood Chain (4663): not deployed

`ShieldBotVerdictRegistry`, `ShieldBotVerdictGuard` and `ShieldBotGuardedTransfer`
([sources](../contracts/base/src/)) are **not deployed**. No address for them exists in this repository;
`ROBINHOOD_VERDICT_REGISTRY` is empty in [.env.example](../.env.example), and verdict publishing stays
`off` while it is. [DEPLOY_ROBINHOOD.md](../contracts/base/DEPLOY_ROBINHOOD.md) has the deployment steps
and `scripts/verify_deployment.py` checks a deployment. Once deployed, the registry is written only by the
verdict drain (`services/verdict_publisher.py`) with `ROBINHOOD_RECORDER_PRIVATE_KEY`. The drain runs in the
API process, or in `workers.py` with `BACKGROUND_WORKERS=external`, and only the unit that runs it holds the
key ([DEPLOYMENT.md](DEPLOYMENT.md)). Add each contract's address, owner, recorder, deployment transaction and
date here.

## Checking these values

```bash
cast call 0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B "owner()(address)" --rpc-url https://mainnet.base.org
cast call 0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B "totalAttestations()(uint256)" --rpc-url https://mainnet.base.org
cast call 0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B "verifiers(address)(bool)" 0x2f3EB1Eb5EBDab566aCa7b7bB5e3228846218483 --rpc-url https://mainnet.base.org
cast call 0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B "schemaUID()(bytes32)" --rpc-url https://mainnet.base.org
cast call 0x867aE7449af56BB56a4978c758d7E88066E1f795 "owner()(address)" --rpc-url https://bsc-dataseed1.binance.org/
cast call 0x867aE7449af56BB56a4978c758d7E88066E1f795 "verifier()(address)" --rpc-url https://bsc-dataseed1.binance.org/
cast call 0x867aE7449af56BB56a4978c758d7E88066E1f795 "totalScans()(uint256)" --rpc-url https://bsc-dataseed1.binance.org/
```
