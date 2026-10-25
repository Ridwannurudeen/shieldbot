# BOT Chain (677) simulation fixtures

Recorded on 25 Oct 2026 (about 15:25 UTC) from `https://rpc.botchain.ai`, read only, at one base block:

- Base block 27,938,432 (`0x1aa4e80`), timestamp 1792938251.
- Methods sent: `eth_call`, `eth_getBlockByNumber`, `eth_simulateV1` (the recorder) and `eth_getTransactionCount`, `eth_getBalance`, `eth_call` (the empty address proof). Every request is a POST with a 30 s timeout and `User-Agent: shieldbot-r2`. Nothing is signed or sent.

## The three fixed addresses

The simulator draws a fresh random buyer and receiver for every run, and a payer for a confirmation (`_fresh_address`). For recording, and in the tests, `_fresh_address` returns these three in turn, cycling `b001, b002, b003, b001, ...`:

- `0xb07b07b07b07b07b07b07b07b07b07b07b07b001`
- `0xb07b07b07b07b07b07b07b07b07b07b07b07b002`
- `0xb07b07b07b07b07b07b07b07b07b07b07b07b003`

Proof that each is empty at the base block (all answered `0x0`, and every `balanceOf` a zero word):

```
rpc(){ curl -s -m 30 -A shieldbot-r2 -X POST -H 'Content-Type: application/json' --data "$1" https://rpc.botchain.ai; }
B=0x1aa4e80
for a in b001 b002 b003; do
  A=0xb07b07b07b07b07b07b07b07b07b07b07b07$a
  rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionCount\",\"params\":[\"$A\",\"$B\"]}"
  rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\",\"params\":[\"$A\",\"$B\"]}"
  for t in 0x5af9a0e7472134a6a5ad02a7d327e83ddd24b337 0xababc7ddc03e501d190c676bf3d92ef0e6e87a3c \
           0x04bbf9ec920e8996bb96e5c451f621e5df6d9999 0xd5452816194a3784dba983426cce7c122f4abd30; do
    rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"$t\",\"data\":\"0x70a08231000000000000000000000000${A:2}\"},\"$B\"]}"
  done
done
```

(The `balanceOf` checks cover COW, USDT, LK2E and WBOT. `0x1111...1111` is not empty on 677: it holds USDT and native BOT.)

## Recording

From the repository root, in WSL:

```
~/.venvs/shieldbot/bin/python tests/fixtures/botchain_simulation/record.py 0x1aa4e80
```

`record.py` runs `BotChainSimulator.simulate` for each token with its `_post` replaced by a plain POST that sends every `"latest"` as the base block, and writes each JSON-RPC exchange (the calls as the simulator built them, then the node's rows, unmodified) and the simulator's result. It then runs one confirmation on COW's pair directly (`_simulate_pool(..., confirm=True)`), sized to the balance COW's first run delivered. Rerunning it at the same base block reproduces the files.

Hex runs of 64 or more digits are written with an underscore after every 32 digits, so no line holds a 64 digit hex literal; the tests remove the underscores on load.

| File | Token | What it holds |
|---|---|---|
| `cow.json` | COW `0x5af9...b337` | Discovery (five calls: `totalSupply`, three `getPool`, one `getPair`), the depth batch (`getReserves` on pair `0x27bf...6542`, 7.646 WBOT, and the header), the first run (buy of 0.15292 BOT = depth / 50) and the sized run. Result: 1% buy tax, 1% sell tax, sellable |
| `usdt.json` | USDT `0xabab...7a3c` | Discovery, the depth batch over the V3 500, 3000 and 10000 pools and the V2 pair, then a first and a sized run on the V3 3000 pool `0x64f4...ec05` and on the V2 pair `0xdc75...b98d` (0.5 BOT each). The 500 and 10000 pools are under the 0.05 BOT minimum. Result: no tax either way, round trip 0.99401 (V3) and 0.99402 (V2) |
| `lk2e.json` | LK2E `0x04bb...9999` | The newest vanity pair `0xc47b...5221`, zero reserves: skipped, "No supported pool with enough WBOT depth" |
| `no_pool.json` | `0x68ca...7bfc6` | A token paired only on other PairCreated emitters (four of the nine), with no BDEX WBOT pool: "No supported pool found" |
| `cow_confirmation.json` | COW | The confirmation shape: two `blockStateCalls`, the second with `blockOverrides.time` = base + 3600 (1792941851); the node's second block reads that timestamp |

No live trap token is recorded: none is known on BDEX. The trap cases in the tests are built from these replies with a constructed revert, as the Arbitrum tests do.

## Latency measured while recording

Each POST opened a fresh TLS connection from this host. `eth_simulateV1` took 3.2 to 7.2 s per call (11 calls over two recordings), the five call discovery batch 2.5 to 6.8 s, the depth batch 2.5 to 3.8 s. A bare `eth_blockNumber` took 1.8 to 2.6 s, of which TLS setup was 1.0 to 1.8 s, so most of the difference from the 1.8 to 2.4 s reported on 25 Oct earlier is connection setup that a reused `aiohttp` session does not pay again.
