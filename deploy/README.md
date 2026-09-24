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
bash /root/shieldbot-deploy.sh --cutover "$SHA"    # only after --check says GO
```

`--check` changes nothing on the server apart from fetching origin, so it is safe to run at any time. It says
NO-GO when:

- the `shieldbot` or `shieldbot-bot` unit, or the venv's Python, is missing
- the database is missing, or `/root` lacks twice its size in free space for the backup
- a tracked file in `/opt/shieldbot` was edited on the server
- the recorder key (`ROBINHOOD_RECORDER_PRIVATE_KEY`) is in the shared `/opt/shieldbot/.env`, the bot unit
  loads `recorder.env` or sets the key, or the running bot process has the key in its environment (or its
  environment cannot be read). Only the API may hold that key: `contracts/base/DEPLOY_ROBINHOOD.md`, section 8.
- the commit is not on origin after `git fetch`

It also says how far the commit is ahead of the deployed one and whether `requirements.txt` changes.

`--cutover` runs the same checks, then:

1. stops `shieldbot-bot`, then `shieldbot`
2. backs up the database with sqlite3's backup API to `/root/shieldbot-backup-<date>-<time>/shieldbot.db`,
   checked with `PRAGMA quick_check`, and writes the running commit to `ROLLBACK_COMMIT` beside it
3. checks out the commit and runs `pip install -r requirements.txt` in the venv
4. starts the API alone (it runs any database migration) and waits for `/api/health`
5. requires `/api/health` to report `status: ok` with exactly the chains in the deployed
   `utils/chain_info.py`, and `/api/stats` to answer
6. starts the bot, checks that its running process does not hold the recorder key, and watches both units for
   20 seconds for a crash or restart

Any failure from step 1 on rolls back by itself: the old commit and the backed-up database go back and both
units start again. The one exception is the recorder key check in step 6: if the bot holds the key, the script
stops the bot, leaves the API running on the new commit and exits non-zero. Fix the bot's configuration, then
start it.

The script prints no secret values (it looks for the recorder key by name) and never copies `.env`. Running
`--cutover` again for the commit that is already deployed repeats the backup, restart and checks and changes
nothing else.

## Roll back

A successful cutover ends with the exact command, for example:

```bash
bash /root/shieldbot-deploy.sh --rollback /root/shieldbot-backup-20260924-101500
```

It stops both units, checks out the commit in `ROLLBACK_COMMIT`, removes any `shieldbot.db-wal` and
`shieldbot.db-shm`, copies the backed-up database over the live one, reinstalls the requirements and starts
the API, then the bot. It exits 0 only when the API answers `/api/health` and the bot is active.

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
