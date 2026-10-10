# Colosseum Crypto World's Fair

## What this is

ShieldBot's entry to the Colosseum Crypto World's Fair Robinhood Chain track. The [judge guide](JUDGE_GUIDE.md) covers the evidence and replay.

## Prior work

The project existed before the contest: the multichain scanner, browser extension and Telegram bot.

The Robinhood Chain work began with 37 commits authored between 23:08 UTC on 13 September and 01:07 UTC on 14 September 2026, before the window opened at 13:00 UTC on 14 September. They were the first 37 of the pull request's 106 commits, with 31 nonmerge commits and 6 merge commits among those 37. The work landed on 17 September through pull request #10 as squash commit `a60fc45`.

Their subjects cover Robinhood Chain registration and adapter routing that fails closed; unknown coverage propagation through analyzers, the API, the bot and SDK; Sourcify and Blockscout explorer enrichment; a resumable Robinhood Chain census collector with eligibility reports, provider probes and read-only reports; and chain ID validation across the API, RPC, MCP and bot entry points.

Everything after that was built inside the window: the sell simulation, launch discovery, the impostor check, evidence publishing, and the registry, guard and transfer contracts deployed on 27 September 2026.

## Check it yourself

1. **The offline replay.** Follow [section 1 of the judge guide](JUDGE_GUIDE.md#1-replay-the-recorded-honeypot-offline).
2. **Verify a verdict.** Follow [section 3 of the judge guide](JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api).
3. **Ask the guard live.** On 9 October 2026 with Foundry 1.7.1, this printed `true` and then `0`, meaning allowed.

   ```bash
   cast call 0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e "check(address,uint64)(bool,uint8)" 0xc6911796042b15d7Fa4F6CDe69e245DdCd3d9c31 900 --rpc-url https://rpc.mainnet.chain.robinhood.com
   ```

   The subject is VIRTUAL, 900 is the maximum record age in seconds, and the reason codes are in the judge guide's [What the on-chain guard enforces table](JUDGE_GUIDE.md#what-the-on-chain-guard-enforces).
4. **The consumer contract.** Follow the judge guide's [Foundry demonstration](JUDGE_GUIDE.md#on-chain-transfer-demonstration).

## Limits

The [README's Scope before the demo section](../README.md#scope-before-the-demo) lists the current limits.
