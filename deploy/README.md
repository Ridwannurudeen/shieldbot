# Deploying ShieldBot

Production is one VPS shared with other projects. The app is a git checkout in `/opt/shieldbot`, with its venv
in `/opt/shieldbot/venv` and its SQLite database at `/opt/shieldbot/shieldbot.db`. Two systemd units run it:

- `shieldbot`: the API (`uvicorn api:app` on 127.0.0.1:8000; `shieldbot-api.service` in this repo)
- `shieldbot-bot`: the Telegram bot

nginx fronts the API and serves the landing site. Every other unit on the machine, including `rh-census-4663`,
belongs to other work. `deploy.sh` stops and starts only the two units above. It never touches other units,
nginx, `.env` or systemd itself (no `daemon-reload`: a changed unit file is applied by hand).

## Deploy a commit

Run as root on the server. Take the script from the commit you are deploying, not from the running checkout:
the commit running now may predate the script, and the deploy rewrites the checkout while it runs. (The
script also guards against that: it is read in full before it starts.)

```bash
SHA=<full or short commit hash, pushed to origin>
git -C /opt/shieldbot fetch origin
git -C /opt/shieldbot show "$SHA:deploy/deploy.sh" > /root/shieldbot-deploy.sh
bash /root/shieldbot-deploy.sh --check "$SHA"      # read-only: GO or NO-GO
```

Run `--cutover` only after `--check` says GO, and never straight in the SSH session: if the session drops, the
hangup makes the script roll back half way through a deploy that may have been fine. Run it in tmux, which
keeps running after a disconnect (reattach with `tmux attach -t deploy`), with a log:

```bash
tmux new -s deploy "bash /root/shieldbot-deploy.sh --cutover $SHA 2>&1 | tee /root/shieldbot-deploy-$SHA.log"
```

or, without tmux, detached under nohup, then follow the log:

```bash
nohup bash /root/shieldbot-deploy.sh --cutover "$SHA" > "/root/shieldbot-deploy-$SHA.log" 2>&1 &
tail -f "/root/shieldbot-deploy-$SHA.log"
```

`--check` changes nothing on the server apart from fetching origin, so it is safe to run at any time. It says
NO-GO when:

- the `shieldbot` or `shieldbot-bot` unit, or the venv's Python, is missing
- the database is missing; `/root` has no more than twice the database's size free (for the backup); or
  `/opt/shieldbot`'s filesystem has no more than twice the database's size plus 512 MiB free (for a migration's
  growth, new packages, and the backup if `/root` is on the same filesystem)
- a tracked file in `/opt/shieldbot` was edited on the server
- the recorder key (`ROBINHOOD_RECORDER_PRIVATE_KEY`) is set in the shared `/opt/shieldbot/.env`, the bot unit
  loads `recorder.env` or sets the key, or the running bot process has the key in its environment (or its
  environment cannot be read). Only the API may hold that key: `contracts/base/DEPLOY_ROBINHOOD.md`, section 8.
- the commit does not exist after `git fetch`, or is on no `origin` branch (a commit made only on the server)

It also names the origin branches holding the commit, how far it is ahead of the deployed one and whether
`requirements.txt` changes.

`--cutover` runs the same checks, then:

1. stops `shieldbot-bot`, then `shieldbot`
2. backs up the database with sqlite3's backup API to `/root/shieldbot-backup-<date>-<time>/shieldbot.db`,
   checked with `PRAGMA quick_check`, and writes the running commit to `ROLLBACK_COMMIT` and the installed
   packages (`pip freeze`) to `pip-freeze.txt` beside it
3. checks out the commit and runs `pip install -r requirements.txt` in the venv
4. starts the API alone (it runs any database migration) and waits for `/api/health`
5. requires `/api/health` to report `status: ok` with exactly the chains in the deployed
   `utils/chain_info.py`, and `/api/stats` to answer
6. starts the bot, checks that its running process does not hold the recorder key, and watches both units for
   20 seconds for a crash or restart

Any failure from step 1 on, and any HUP, INT or TERM signal, rolls back by itself: the old commit, packages and
backed-up database go back and both units start again. The script names the line and command that failed. The
one exception is the recorder key check in step 6: if the bot holds the key, the script stops the bot, leaves
the API running on the new commit and exits non-zero. Fix the bot's configuration, then start it.

An automatic rollback also discards whatever the new API wrote to the database between its start in step 4 and
the rollback: those writes go with the backed-up copy. If the failure came before the backup in step 2 was
taken, there is no copy to restore and the database is left as it is (the new code never ran on it).

The script prints no secret values (it looks for the recorder key by name) and never copies `.env`. Running
`--cutover` again for the commit that is already deployed repeats the backup, restart and checks and changes
nothing else.

## Roll back

A successful cutover ends with the exact command, for example:

```bash
bash /root/shieldbot-deploy.sh --rollback /root/shieldbot-backup-20260924-101500
```

It stops both units, checks out the commit in `ROLLBACK_COMMIT` (with `--force`, so files a failed run edited
cannot block it), removes any `shieldbot.db-wal` and `shieldbot.db-shm`, copies the backed-up database over the
live one, reinstalls the packages from `pip-freeze.txt` (or the old commit's `requirements.txt` if the backup
has no frozen list) and starts the API, then the bot. It exits 0 only when the API answers `/api/health` and the
bot is active. Signals are ignored while it runs, so neither a second Ctrl-C nor a dropped session can leave it
half done.

**A rollback puts back the database as it was at the cutover. Everything written since (scans, reports,
alerts, subscriptions, verdict records) is lost.** The database goes back with the code because older code may
not run on a schema the newer code migrated. If only the code must go back and the schema did not change,
deploy the older commit with `--cutover` instead: that keeps the data.

Each deploy backup in `/root` is a full copy of the database, user data included. Delete it once the deploy
has proven itself: `rm -r /root/shieldbot-backup-<date>-<time>`.

## nginx

`nginx-api.conf.example` is a reference for the API vhost, not a drop-in. The live vhost is
`/etc/nginx/sites-available/shieldbot` and is not in this repo. What must match: `X-Forwarded-For` set from
`$proxy_add_x_forwarded_for` (without it every user shares one rate-limit bucket), `X-Forwarded-Proto`,
`Host`, a read timeout above the 25 second scan deadline, and no CORS or security headers of nginx's own (the
app sends them). To compare:

```bash
grep -nE 'proxy_pass|proxy_set_header|proxy_.*timeout|add_header' /etc/nginx/sites-available/shieldbot
```

After an edit: `nginx -t && systemctl reload nginx`.

## Nightly backups

`backup.sh` (repo root) copies the database with sqlite3's backup API while both services keep running, checks
the copy with `PRAGMA quick_check` and saves it as `/opt/shieldbot/backups/shieldbot_<date>_<time>.db`
(mode 600). Only after a good backup does it prune: the newest `KEEP_COUNT` copies (default 7) always stay,
and of the rest it deletes those older than `KEEP_DAYS` days (default 7). A job that keeps failing never
deletes anything, and after a long outage the newest copies survive even though all of them are old. With
`BACKUP_REMOTE` set it also sends the new copy there with `scp` (ssh key auth, no password prompt, and the host
key must already be known); unset, nothing leaves the machine. Any failure exits non-zero.

Nothing schedules it. To run it nightly at 02:30, add this line to `/etc/cron.d/shieldbot-backup`:

```
30 2 * * * root /bin/bash /opt/shieldbot/backup.sh >> /var/log/shieldbot-backup.log 2>&1
```

With 14 days kept and an off-box copy:

```
30 2 * * * root KEEP_DAYS=14 BACKUP_REMOTE=backup@backup-host:/srv/shieldbot/ /bin/bash /opt/shieldbot/backup.sh >> /var/log/shieldbot-backup.log 2>&1
```

For the off-box copy, root's ssh key must be authorised on the backup host, and the host's key must already be
in `/root/.ssh/known_hosts`: `scp` runs with `StrictHostKeyChecking=yes` and refuses an unknown or changed host.
Connect once by hand as root (`ssh backup@backup-host`), check the fingerprint it shows against the one the
backup host's provider or console reports, and accept it.

Set these on the cron line, not by editing `backup.sh`: an edited tracked file makes `deploy.sh --check` say
NO-GO. Local copies sit on the same disk as the database, so they cover a bad write or a bad deploy, not the
loss of the machine; only `BACKUP_REMOTE` covers that. The copies hold user data and this script does not
encrypt them.

## Restore a backup

Pick a file with `ls -lt /opt/shieldbot/backups/`, then, as root:

```bash
BACKUP=/opt/shieldbot/backups/shieldbot_YYYYMMDD_HHMMSS.db

# 1. Check the backup before touching anything. It must print "ok", then a row count.
/opt/shieldbot/venv/bin/python - "$BACKUP" <<'PY'
import sqlite3, sys
from pathlib import Path
db = sqlite3.connect(Path(sys.argv[1]).resolve().as_uri() + "?mode=ro", uri=True)
print(db.execute("PRAGMA integrity_check").fetchone()[0])
print(db.execute("SELECT COUNT(*) FROM contract_scores").fetchone()[0], "contract_scores rows")
PY

# 2. Stop the bot, then the API.
systemctl stop shieldbot-bot
systemctl stop shieldbot

# 3. Keep the current database aside, then restore. A WAL file beside the database must not be replayed onto
#    the restored copy, and copying into the existing file keeps its owner and mode.
ASIDE=/root/shieldbot-before-restore-$(date +%Y%m%d-%H%M%S)
mkdir -m 700 "$ASIDE"
cp -a /opt/shieldbot/shieldbot.db* "$ASIDE"/
rm -f /opt/shieldbot/shieldbot.db-wal /opt/shieldbot/shieldbot.db-shm
cp "$BACKUP" /opt/shieldbot/shieldbot.db

# 4. Start the API, verify it, then start the bot.
systemctl start shieldbot
sleep 15
curl -s http://127.0.0.1:8000/api/health
curl -s http://127.0.0.1:8000/api/stats
systemctl start shieldbot-bot
systemctl is-active shieldbot shieldbot-bot
```

Verify: `/api/health` returns `"status":"ok"` with the chain list, `contracts_scanned` in `/api/stats` equals
the `contract_scores` count from step 1 (until new scans arrive), and both units print `active`. If anything is
wrong, put the previous database back: stop both units, run
`rm -f /opt/shieldbot/shieldbot.db-wal /opt/shieldbot/shieldbot.db-shm && cp -a "$ASIDE"/shieldbot.db* /opt/shieldbot/`
and start the API, then the bot.

To test a backup without touching production, run step 1 alone: it opens the file read-only and leaves nothing
beside it.
