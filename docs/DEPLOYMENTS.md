# Deployed contracts

Every ShieldBot contract deployed to a public chain. Each value below was read from the chain on
**2026-09-24** with read-only calls (`eth_call`, `eth_getCode`, transaction receipts and blocks) on the
public RPCs `https://mainnet.base.org` and `https://bsc-dataseed1.binance.org/`; creation transactions and
event logs of the Base attestor come from base.blockscout.com, and source matches from Sourcify. The two
BSC deployment transactions are the ones the repository already recorded (`docs/DEPLOYMENT.md` for the
verifier, the since-removed `bsc.address` metadata file for the unused second one); their receipts, read
from `https://bsc-dataseed1.binance.org/`, show each creating the contract listed below. The Base
attestor and the BNB Smart Chain verifier were retired on 2026-09-26: nothing in this repository writes
to either any more, so no new records are written. The records already on both chains stay. The Robinhood
Chain (4663) rows were read the same way on **2026-09-27** from `https://rpc.mainnet.chain.robinhood.com`.

| Contract | Chain | Address | Deployed (UTC) | Records (when read) | Written by |
|---|---|---|---|---|---|
| `ShieldBotAttestor` | Base (8453) | [`0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B`](https://basescan.org/address/0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B) | 2026-05-05 15:23:51 | 1 attestation (2026-09-24) | nothing: retired on 2026-09-26 |
| `ShieldBotVerifier` | BNB Smart Chain (56) | [`0x867aE7449af56BB56a4978c758d7E88066E1f795`](https://bscscan.com/address/0x867aE7449af56BB56a4978c758d7E88066E1f795) | 2026-02-12 11:25:33 | 20 scans (2026-09-24) | nothing: retired on 2026-09-26 |
| `ShieldBotVerifier` (second, unused) | BNB Smart Chain (56) | [`0x0AD4E23f5762CEd4D3278Da958e109F2A09337B2`](https://bscscan.com/address/0x0AD4E23f5762CEd4D3278Da958e109F2A09337B2) | 2026-03-02 13:57:22 | 0 scans (2026-09-24) | nothing in this repository |
| `ShieldBotVerdictRegistry` | Robinhood Chain (4663) | [`0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138`](https://robin.etherscan.io/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138) | 2026-09-27 20:11:57 | 9 records at block 74,253,938 (2026-09-27 21:17 UTC); the guard watch adds one about every 350 s | the verdict drain, as recorder `0xc68a90dcdfE8FBf770a7f29904B928cA6D00F453` |
| `ShieldBotVerdictGuard` | Robinhood Chain (4663) | [`0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e`](https://robin.etherscan.io/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e) | 2026-09-27 20:43:47 | none (reads the registry) | nothing: it has no state to write |
| `ShieldBotGuardedTransfer` | Robinhood Chain (4663) | [`0x336254bA85406D9af39357101b688E2B757751b3`](https://robin.etherscan.io/address/0x336254bA85406D9af39357101b688E2B757751b3) | 2026-09-27 20:43:47 | none | callers of `transfer(amount, maxAge)` |

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
- **Writes:** none. Retired on 2026-09-26; no new records are written. Until then `bot.py` attested
  contract and token scans through the since-removed `utils/base_attestor.py` when
  `BASE_ATTESTOR_ADDRESS` and `BASE_VERIFIER_PRIVATE_KEY` were set. `services/base_attestation_service.py`
  still reads its attestations through the EAS GraphQL API (`/api/base/attestations`) when
  `BASE_ATTESTOR_ADDRESS` is set.

## ShieldBotVerifier on BNB Smart Chain

- **Address:** `0x867aE7449af56BB56a4978c758d7E88066E1f795`
  ([BscScan](https://bscscan.com/address/0x867aE7449af56BB56a4978c758d7E88066E1f795))
- **Deployed:** transaction [`0x021fb404910c2621497bcda167ffcc70e8ece846d1ade8066ab5ad87f13b6bbd`](https://bscscan.com/tx/0x021fb404910c2621497bcda167ffcc70e8ece846d1ade8066ab5ad87f13b6bbd),
  block 80,777,511, 2026-02-12 11:25:33 UTC, from `0xfE3f3cEAb7266b5de5Ae8738727b6cf82F7Be76c`.
- **Owner and recorder:** `owner()` and `verifier()` are both `0xc62A8ae13a2Ea84F443dA5681501e7aaC43dC6F5`,
  so one key both records scans and owns the contract: if it leaks, no other key can rotate the recorder
  away from it. Since the retirement no service needs that key; whoever holds it can still write records
  that nothing reads.
- **Records:** `totalScans()` = 20; `getStats()` returns (20, 20).
- **Source:** Sourcify partial match (verified 2026-05-21), not an exact one. The deployed contract is not
  [contracts/ShieldBotVerifier.sol](../contracts/ShieldBotVerifier.sol) as it stands: that source declares
  `uniqueAddressCount()`, and `eth_call` to it reverts on the deployed contract.
- **Risk codes** (in the repository source): 0 = LOW, 1 = MEDIUM, 2 = HIGH, 3 = SAFE, 4 = WARNING,
  5 = DANGER. An address never recorded also reads 0 (LOW) from `latestScans`, so read
  `hasBeenScanned(address)` first.
- **Writes:** none. Retired on 2026-09-26; no new records are written. Until then `bot.py` recorded
  contract and token scans through the since-removed `utils/onchain_recorder.py` when
  `BOT_WALLET_PRIVATE_KEY` was set. Nothing in this repository reads the contract either; its records
  are on BscScan.

## Second ShieldBotVerifier on BNB Smart Chain (unused)

- **Address:** `0x0AD4E23f5762CEd4D3278Da958e109F2A09337B2`
  ([BscScan](https://bscscan.com/address/0x0AD4E23f5762CEd4D3278Da958e109F2A09337B2))
- **Deployed:** transaction [`0x80774cf3c125bfc9ca719cd05a80793b9be8b403f27ec9a6b4bd1633aad9d00d`](https://bscscan.com/tx/0x80774cf3c125bfc9ca719cd05a80793b9be8b403f27ec9a6b4bd1633aad9d00d),
  block 84,252,849, 2026-03-02 13:57:22 UTC, from `0xfE3f3cEAb7266b5de5Ae8738727b6cf82F7Be76c`.
- **Owner and recorder:** `owner()` and `verifier()` are both `0xfE3f3cEAb7266b5de5Ae8738727b6cf82F7Be76c`.
- **Records:** `totalScans()` = 0.
- **Source:** no Sourcify match. The since-removed `bsc.address` metadata file listed this address as the
  verifier; no code in this repository writes to it or reads from it.

## Robinhood Chain (4663)

Deployed on 2026-09-27 from `main` at `c9ae9c9` ([sources](../contracts/base/src/), unchanged since `04203be`)
by `0x8d02b6ECffed8A3e1e5C3649AA4670c72C366ae4`, following [DEPLOY_ROBINHOOD.md](../contracts/base/DEPLOY_ROBINHOOD.md).
`scripts/verify_deployment.py` reported `SUMMARY: PASS (13 passed, 0 failed)` the same day.

- **`ShieldBotVerdictRegistry`:** `0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138`, deployed in transaction [`0x14275435a6f9cff13681b15b230f69c7c40579a4e308a7cc503d25ff1b731fef`](https://robin.etherscan.io/tx/0x14275435a6f9cff13681b15b230f69c7c40579a4e308a7cc503d25ff1b731fef),
  block 74,214,980. `owner()` is `0x8d02b6ECffed8A3e1e5C3649AA4670c72C366ae4`; `recorder()` is `0xc68a90dcdfE8FBf770a7f29904B928cA6D00F453`, the verdict drain's key
  (`services/verdict_publisher.py`), held only by the API unit ([DEPLOYMENT.md](DEPLOYMENT.md)).
- **`ShieldBotVerdictGuard`:** `0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e`, deployed in transaction [`0xad4ada88dc23df69351ecd378dcab7033aaec71fd3edca711b9c05962b9565b3`](https://robin.etherscan.io/tx/0xad4ada88dc23df69351ecd378dcab7033aaec71fd3edca711b9c05962b9565b3),
  block 74,233,945. `registry()` is `0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138`.
- **`ShieldBotGuardedTransfer`:** `0x336254bA85406D9af39357101b688E2B757751b3`, deployed in transaction [`0x7ee90d6204f182526870c0323e131b87dd7ad5e15ffafcffaeb1c2f0748e26f7`](https://robin.etherscan.io/tx/0x7ee90d6204f182526870c0323e131b87dd7ad5e15ffafcffaeb1c2f0748e26f7),
  block 74,233,945. `guard()` is the guard above, `subject()` is VIRTUAL (`0xc6911796042b15d7Fa4F6CDe69e245DdCd3d9c31`), `usdg()` is Paxos USDG
  (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`) and `recipient()` is `0x8d02b6ECffed8A3e1e5C3649AA4670c72C366ae4`.
- **Source:** full exact matches on Sourcify (creation and runtime code) for all three. Blockscout shows each contract through its Sourcify lookup; a first page load can show "Verify & publish" before that match appears.
  ([exact match](https://sourcify.dev/server/v2/contract/4663/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138), [exact match](https://sourcify.dev/server/v2/contract/4663/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e), [exact match](https://sourcify.dev/server/v2/contract/4663/0x336254bA85406D9af39357101b688E2B757751b3)).

## Checking these values

```bash
cast call 0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B "owner()(address)" --rpc-url https://mainnet.base.org
cast call 0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B "totalAttestations()(uint256)" --rpc-url https://mainnet.base.org
cast call 0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B "verifiers(address)(bool)" 0x2f3EB1Eb5EBDab566aCa7b7bB5e3228846218483 --rpc-url https://mainnet.base.org
cast call 0xA4A192510FB8Ad1B6C92972a15BfAba73E7a655B "schemaUID()(bytes32)" --rpc-url https://mainnet.base.org
cast call 0x867aE7449af56BB56a4978c758d7E88066E1f795 "owner()(address)" --rpc-url https://bsc-dataseed1.binance.org/
cast call 0x867aE7449af56BB56a4978c758d7E88066E1f795 "verifier()(address)" --rpc-url https://bsc-dataseed1.binance.org/
cast call 0x867aE7449af56BB56a4978c758d7E88066E1f795 "totalScans()(uint256)" --rpc-url https://bsc-dataseed1.binance.org/
cast call 0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138 "owner()(address)" --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call 0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138 "recorder()(address)" --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call 0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138 "totalRecords()(uint256)" --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call 0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e "registry()(address)" --rpc-url https://rpc.mainnet.chain.robinhood.com
cast call 0x336254bA85406D9af39357101b688E2B757751b3 "subject()(address)" --rpc-url https://rpc.mainnet.chain.robinhood.com
```
