# BOT Chain (677) market fixtures

Recorded live on 2026-10-25 between 14:09 and 14:17 UTC with read only requests (curl and urllib, `-m 30` / a 30 s timeout, `User-Agent: shieldbot-r3`). No keys, no signing, no transactions.

Pinned block: `0x1aa49ea` (27,937,258), read with `eth_blockNumber` at 14:10 UTC. The log queries and every `eth_call` use it as their `toBlock` or block tag. The BDEX API takes no block, so its replies are what it served at the recording time.

Sources:
- BDEX API `https://dex-wallet.botchain.ai/api/v1`
- BOT Chain RPC `https://rpc.botchain.ai`

## Files

| File | Request | Body |
|---|---|---|
| `api_pools_page1.json` | `GET /pools?page_num=1&page_size=100&sort_by=tvl&sort_order=desc` | as returned: 53 pools, `meta.total` 53 |
| `api_pools_page2.json` | `GET /pools?page_num=2&page_size=100&sort_by=tvl&sort_order=desc` | as returned: empty `data` |
| `api_pairs_all.json` | `GET /pairs?pool_type=all` | as returned: 53 pairs, the same 53 pools |
| `api_price.json` | `GET /price?token=<token>` for 31 tokens | each reply as returned, keyed by the token asked |
| `logs_pair_created.json` | `eth_getLogs` V2 factory 0x117115f3B72C8d1989178089A67D0C26f8EE0AA3, topic0 `PairCreated(address,address,address,uint256)` (0x0d3648bd...d0e9), `fromBlock` 0x0, `toBlock` 0x1aa49ea | the JSON-RPC reply as returned: 83 logs |
| `logs_pool_created.json` | `eth_getLogs` V3 factory 0x1C51c173323ec11BB4e3C4fD2314c225Dc4b5419, topic0 `PoolCreated(address,address,uint24,int24,address)` (0x783cca1c...7118), `fromBlock` 0x0, `toBlock` 0x1aa49ea | the JSON-RPC reply as returned: 24 logs |
| `eth_call.json` | 528 `eth_call` at 0x1aa49ea, sent as JSON-RPC batches of at most 50 | per call `to`, `data` and the reply row as returned (its `id` removed, since it was the batch position) |
| `blocks.json` | `eth_getBlockByNumber(<n>, false)` for the six creation blocks used in the tests | each reply as returned, keyed by the block number |
| `rpc_unsupported.json` | `debug_traceCall` | the -32601 reply as returned, the shape of an unsupported method |

The prices asked: WBOT, USDT, COW 0x5af9...b337, the newest vanity token LK2E 0x04bb...9999 (price "0", empty path), the zero address (price "0", empty path), every other token in a pool with USDT or COW or in the omitted V3 pool, and the other token of each of the 14 V2 pairs that hold WBOT.

The `eth_call` set: `getReserves()` on all 83 V2 pairs (14 of them hold WBOT; the USDT/WBOT pair is the deepest and the LK2E pair 0xc47b...5221 is empty); `liquidity()` on the V3 pool the API omits, 0x7453...db27 (NQDA/WBOT fee 3000, liquidity 0, both balances 0); `balanceOf(pool)` of both tokens of each of the 24 V3 pools; `decimals()`, `totalSupply()`, `name()` and `symbol()` of every token in any pool. No call failed.

The blocks: 0x104427 (the USDT/WBOT V3 3000 pool), 0xaef0a2 (the USDT/WBOT V2 pair), 0xb7c6d4 (COW/WBOT), 0xc7a6eb (COW/USDT), 0x18944dd (the omitted V3 pool), 0x1a43f3d (the LK2E pair).

## What the recording shows

- The logs hold 83 V2 pairs and 24 V3 pools. The API lists 53 pools: 30 of the 83 V2 pairs and 23 of the 24 V3 pools. The V3 pool it omits is 0x7453...db27.
- In every API pool `baseTokenAddress` is the pool's token0 and `token0Amount` and `token1Amount` are decimal adjusted amounts of token0 and token1.
- The API's `fdvUsd` is a pool value, not a token's fully diluted value: on the USDT/WBOT V3 pool it is 31,222,268 against 15,490,325 USDT plus 1,268,799 WBOT at 12.399 (31,222,145); on COW/WBOT it is 188.998 against 188.191 from the two sides, and COW/USDT gives COW a different figure (148.583). The provider therefore never reads `fdvUsd` as fdv.
- `volumeUsd24` is "0" on 48 of the 53 pools, a measured zero.

## Latency

| Endpoint | Requests | Seconds |
|---|---|---|
| `GET /api/v1/pools` (one page) | 2 | 1.37 to 1.77 |
| `GET /api/v1/pairs?pool_type=all` | 1 | 1.42 |
| `GET /api/v1/price` | 31 | 0.97 to 3.97 |
| `eth_getLogs` V2 factory, full range | 1 | 3.77 |
| `eth_getLogs` V3 factory, full range | 1 | 3.86 |
| `eth_call` batch of 50 | 10 | 2.16 to 2.97 |
| `eth_call` batch of 28 | 1 | 2.44 |
| `eth_call` single `getReserves` | 1 | 2.30 |
| `eth_getBlockByNumber` | 6 | 1.83 to 3.16 |
| `debug_traceCall` (unsupported) | 1 | 1.84 |
| `eth_blockNumber` | 1 | 2.36 |
