# ShieldBot Deployment Guide

## Quick Start (Local Testing)

### 1. Setup
```bash
# Clone and navigate to project
cd shieldbot

# Run setup script
chmod +x setup.sh run.sh
./setup.sh

# Edit .env with your credentials
nano .env
```

### 2. Get Telegram Bot Token
1. Open Telegram and search for [@BotFather](https://t.me/BotFather)
2. Send `/newbot`
3. Choose a name (e.g., "ShieldBot")
4. Choose a username (e.g., "your_shieldbot_bot")
5. Copy the token and add to `.env`:
   ```
   TELEGRAM_BOT_TOKEN=your_token_here
   ```

### 3. Get BscScan API Key (Recommended)
1. Go to [BscScan](https://bscscan.com)
2. Sign up and verify email
3. Go to [API Keys](https://bscscan.com/myapikey)
4. Create new API key
5. Add to `.env`:
   ```
   BSCSCAN_API_KEY=your_api_key_here
   ```

### 4. Run the Bot
```bash
./run.sh
```

Test in Telegram:
- Send `/start` to your bot
- Send a contract address to scan

---

## Production

Production is a git checkout in `/opt/shieldbot` on one VPS, run by systemd units: `shieldbot`, the API
(`uvicorn api:app` on 127.0.0.1:8000; `shieldbot-api.service` in this repo), and `shieldbot-bot`, the Telegram
bot, plus `shieldbot-workers` when the background work runs in its own process (below).
[deploy/README.md](../deploy/README.md) covers deploying a commit, rolling back, nginx, nightly backups and
restoring one.

**API sender constraint:** `shieldbot-api.service` runs one uvicorn process without `--workers`. Preserve that topology: the API lifespan starts the verdict publisher, and its nonce lock is process-local. Multiple API processes, workers or replicas can compete for the same recorder.

### Shared rate limits in Redis (opt-in)

By default every rate limiter counts in the API process's memory: a restart forgets the counts, and a second
API process would give each caller a second allowance. With `RATE_LIMIT_BACKEND=redis` the API counts in Redis
at `REDIS_URL` (default `redis://localhost:6379/0`), one count per caller shared by every API process. With the
setting unset or `memory`, nothing changes. Any other value stops the API at startup.

| Limiter | Limit | When Redis cannot answer |
|---|---|---|
| Every request without an API key (health checks aside), per IP | 30 a minute, 10 in 5 s | counted in this API process's memory, error logged |
| RPC proxy `/rpc/{chain_id}` without a key, per IP | 100 a minute | counted in this API process's memory, error logged |
| API key, per key | the key's per-minute limit | minute window counted in this API process's memory, error logged; the daily quota is in SQLite and applies either way |
| `/api/agent/chat` and `/api/agent/explain`, per IP | 50 a minute, 10 in 5 s | refused (429), error logged |
| `/api/report`, per IP | 5 a minute, 3 in 5 s | refused (429), error logged |
| `/api/outcome` without an API key, per IP | 10 a minute, 5 in 5 s | refused (429), error logged |
| `/api/beta-signup`, per IP | 3 a minute, 2 in 5 s | refused (429), error logged |
| `/api/keys/free`, per IP | 3 a minute, 2 in 5 s | refused (429), error logged |
| `/api/watch/alerts`, per IP | 10 a minute, 5 in 5 s | refused (429), error logged |

The first three fall back to counting in the API process's memory, exactly as with `memory`, so a Redis outage
neither takes the scan API or wallets that use the RPC proxy down nor lifts their limits; while it lasts, each API
process counts on its own. The others guard AI spend, email sending and writes, so they refuse. The client gives
Redis 0.5 seconds to connect or reply (redis-py 5.2.1, as pinned, does not retry), so a Redis that hangs costs up
to 0.5 seconds per limiter a request passes: up to about 1 second for a request checked by the general limiter
and a route's own limiter.

Each limiter keeps a sorted set per caller at `shieldbot:ratelimit:<limiter>:<caller>`, where the caller is the
client IP or the API key's id, never the key itself. Every check renews the key's 60 second TTL, so an idle
caller's key expires. The limiters write nothing else to Redis.

To turn it on:

1. Run Redis where only the API host can reach it (bound to 127.0.0.1, or a private network with a password in
   `REDIS_URL`).
2. Add `RATE_LIMIT_BACKEND=redis` and, if Redis is not on localhost, `REDIS_URL=redis://...` to
   `/opt/shieldbot/.env`.
3. Restart the API. Its log says `Rate limits kept in Redis` once Redis answered a PING at startup. If it
   did not, the log says `Rate limits configured for Redis, but it did not answer PING` and the limiters behave
   as in the table until Redis answers. After a few requests,
   `redis-cli --scan --pattern 'shieldbot:ratelimit:*'` lists the callers' keys.

To turn it off, remove the setting and restart the API.

### Background workers in their own process (opt-in)

By default the API process also runs ShieldBot's background work, so API requests wait whenever that work
holds the event loop. With `BACKGROUND_WORKERS=external` the API starts none of it, and `workers.py` runs it as
a service of its own (`deploy/shieldbot-workers.service.example`). With the setting unset or `api`, nothing
changes. Any other value stops the API at startup.

| Background work | `api` (default) | `external` |
|---|---|---|
| Mempool monitor (txpool polling, or pending-block polling where the pool exceeds 8 MB per read) | API | workers.py |
| Robinhood Chain verdict drain (signs and sends registry records) | API | workers.py |
| Hunter sweep | API | workers.py |
| Retention pruning, part of the hunter sweep (chat history, API usage and AI token counts, scan evidence, expired free key requests, expired community blacklist entries) | API | workers.py |
| Launch watch (Robinhood Chain launch discovery and triaged scans) | API | workers.py |
| Deployer indexer | API and bot | API, bot and workers.py |

The deployer indexer stays in every process: its queue is in memory and each process fills it with the contracts
it scans itself. Verdicts the API or the bot publishes are queued in the database as before, and the drain in
workers.py picks them up on its next poll, at most 10 seconds later when it is idle. With `external` the API
rereads the scam blacklist itself every 30 minutes, as the bot does, since the hunter sweep that reloads it runs in
workers.py.

Retention pruning (`docs/TECHNICAL.md`, Data Privacy) is part of the hunter sweep, so with `external` only
workers.py prunes: while the `shieldbot-workers` unit is stopped nothing is deleted, and the API's blacklist
reread prunes nothing. What fell due meanwhile goes at the first sweep after the unit starts again.

With `external` the API holds none of the workers' memory. It says so instead of reporting zeros:

| Where | Field | With `external` |
|---|---|---|
| `GET /api/stats` | `transactions_monitored`, `sandwiches_caught`, `suspicious_approvals`, `chains_protected`, `mempool_chains_observable`, `mempool_chains_unobservable`, `mempool_counting_since` | null, and `background_workers_note` says why |
| `GET /api/stats` | `unknown_ledger` | the API's own lookups only; the hunter's and the launch watch's are counted in workers.py, which does not serve them |
| `GET /api/coverage/{chain_id}` | `public_mempool` | `unobservable`, never `yes`, with `background_workers_note` |
| `GET /api/coverage/{chain_id}` | `provider_health` | the API's own lookups only |
| `GET /api/mempool/alerts`, `GET /api/mempool/stats` | the whole answer | 503 with the reason, never an empty list; the bot's `/threats` then says live mempool data is unavailable |
| `GET /api/threats/feed` | mempool alerts | left out, and `mempool_unavailable` gives the reason |
| `GET /api/admin/stats` | `mempool`, `guard_watch.running`, `guard_watch.rpc_budget` | null, with `background_workers_note` |

Everything the API reads from the database is unchanged: scan and threat counts, launch discovery, evidence and
registry records, guard subjects and verdict permalinks.

**The recorder key moves with the drain.** With `external`, workers.py is the only process that signs verdict
transactions. The key file `/etc/shieldbot/recorder.env` must be loaded by the workers unit and removed from the
API unit. Set `BACKGROUND_WORKERS=external` in the shared `/opt/shieldbot/.env`, which both units read: an API
that reads `api` beside a running workers.py would run a second drain. workers.py refuses to start unless it
reads `external`, but it cannot see what the API reads.

If two drains do run on the database, only the holder of the sender lease (the `sender_leases` table) stores and
broadcasts verdict transactions. The holder renews the lease every 15 seconds. After signing, each send takes the
lease again and goes on only if the lease is its own and still has a lock wait (5 seconds) and the 60 second
broadcast phase to run; otherwise it discards what it signed, puts the row back in the queue, and the drain stops
claiming rows until it has taken the lease again. So a send that went on can finish its broadcast before any other
drain can hold the lease. The other drain logs
`Robinhood verdict registry: not sending, <host:pid:id> holds the sender lease until ...` and asks again when that
lease expires. It can take over only after the holder has gone 90 seconds without taking the lease: after a crash,
or when its renewals keep failing, in which case the holder stops claiming rows before the lease can run out. A
clean stop releases the lease at once, unless a send is still under way. The holder's id names its host and process
id. The drains compare the lease's expiry with their own clocks, so drains on different hosts need synchronised
clocks.

The lease also applies with the default `BACKGROUND_WORKERS=api`, where the API is the only drain. After a clean
stop or `systemctl restart` it sends again at once, unless the stop came while a send was still under way: as said
above, the lease is then left to expire rather than released. After a crash (a kill, an out-of-memory stop, a power
loss) the lease still names the dead process. In both cases the restarted API stores and broadcasts no verdict until
that lease expires: up to 90 seconds. Verdicts queued meanwhile wait as `pending` and go out after it.

To turn it on, as root:

```bash
# 1. Add the line BACKGROUND_WORKERS=external to /opt/shieldbot/.env, which the API and the workers both read.

# 2. The workers unit.
cp /opt/shieldbot/deploy/shieldbot-workers.service.example /etc/systemd/system/shieldbot-workers.service
systemctl daemon-reload

# 3. Move the recorder key file (only if the verdict registry is configured).
systemctl edit shieldbot-workers   # add: [Service] and EnvironmentFile=/etc/shieldbot/recorder.env
systemctl edit shieldbot           # delete the EnvironmentFile=/etc/shieldbot/recorder.env line
systemctl cat shieldbot | grep -c recorder.env            # 0: the API no longer loads the key
systemctl cat shieldbot-bot | grep -c recorder.env        # 0
systemctl cat shieldbot-workers | grep -c recorder.env    # 1

# 4. Restart the API first, which stops its own background work, then start the workers.
systemctl restart shieldbot
systemctl enable --now shieldbot-workers
```

Check: the API log says `Background work runs in workers.py (BACKGROUND_WORKERS=external)` and never
`Robinhood verdict registry: sending`; `journalctl -u shieldbot-workers` shows `ShieldBot workers started` and,
with the registry configured, `Robinhood verdict registry: sending as recorder 0x...`; `/api/stats` carries
`background_workers_note`.

**Deploys.** `deploy/deploy.sh` stops, backs up and starts only `shieldbot` and `shieldbot-bot`; it does not know
the workers unit. A cutover or rollback with the workers running would copy the database under a process that has
it open and leave the workers on the old code. Until the script manages the unit, run
`systemctl stop shieldbot-workers` before `--cutover` or `--rollback` and `systemctl start shieldbot-workers`
after it finishes, whether it deployed or rolled back. With `BACKGROUND_WORKERS=external` in the shared `.env`,
`--check` also says NO-GO while the API unit still loads `recorder.env` or sets the key.

**Rolling back past this feature.** A commit older than the workers split has no `workers.py` and ignores the
setting: after a `--rollback` (or a cutover) to one, the API starts the background work itself again, but sends no
verdicts while its unit lacks the recorder key. Move everything back, as root:

```bash
systemctl disable --now shieldbot-workers   # the old commit has no workers.py to run
systemctl edit shieldbot-workers            # delete the EnvironmentFile=/etc/shieldbot/recorder.env line
systemctl edit shieldbot                    # add it back: [Service] and EnvironmentFile=/etc/shieldbot/recorder.env
# then delete the line BACKGROUND_WORKERS=external from /opt/shieldbot/.env, and restart the API
systemctl restart shieldbot
```

With the registry configured, the API log says `Robinhood verdict registry: sending as recorder 0x...` again.

To turn it off: `systemctl disable --now shieldbot-workers`, move the recorder key file back to the API unit,
remove the setting from `/opt/shieldbot/.env` and restart the API.

Neither setting makes a second API process supported: MCP sessions, for one, live in a single process's memory.

---

## Earlier versions of this guide

An earlier version of this guide described a `shieldbot.service` that ran `bot.py`, Docker and screen setups,
a health check on port 8080, a verifier contract deployed from Remix and a checklist. None of that
describes production any more, so it was removed; it is in the git history. Its checklist recorded the BNB Smart
Chain verifier, which [DEPLOYMENTS.md](DEPLOYMENTS.md) describes:

- [x] Contract address documented: https://bscscan.com/address/0x867aE7449af56BB56a4978c758d7E88066E1f795#code
- [x] Deployment tx documented: https://bscscan.com/tx/0x021fb404910c2621497bcda167ffcc70e8ece846d1ade8066ab5ad87f13b6bbd

The main settings are listed in `.env.example`.
