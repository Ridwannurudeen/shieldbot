#!/usr/bin/env bash
# Gated production deploy for ShieldBot. Run on the server as root. See deploy/README.md.
#
#   deploy.sh --check    <commit>       read-only GO / NO-GO; safe to run at any time
#   deploy.sh --cutover  <commit>       stop, back up, deploy, verify; any failure rolls back by itself
#   deploy.sh --rollback <backup-dir>   put back the commit and database a cutover saved
#
# <commit> is a full or short hex SHA that exists on origin after `git fetch`.
# Only the shieldbot (API) and shieldbot-bot units are ever stopped or started.

set -Eeuo pipefail
umask 077

APP=/opt/shieldbot
VENV=$APP/venv
PY=$VENV/bin/python
DB=$APP/shieldbot.db
API_UNIT=shieldbot
BOT_UNIT=shieldbot-bot
API_URL=http://127.0.0.1:8000
RECORDER_KEY=ROBINHOOD_RECORDER_PRIVATE_KEY
BACKUP=/root/shieldbot-backup-$(date +%Y%m%d-%H%M%S)
LOCK=/run/shieldbot-deploy.lock
TARGET=
OLD=

say()   { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail()  { printf '\033[31mNO-GO: %s\033[0m\n' "$*" >&2; exit 1; }
usage() { echo "usage: $0 --check <commit> | --cutover <commit> | --rollback <backup-dir>" >&2; exit 2; }

# systemctl is-active exits 3 while a unit is "activating"; wait for it to settle.
wait_active() {
  local i
  for i in $(seq 1 20); do
    [ "$(systemctl is-active "$1" || true)" = active ] && return 0
    sleep 2
  done
  return 1
}

wait_health() {
  local i
  for i in $(seq 1 30); do
    sleep 2
    curl -sf --max-time 5 "$API_URL/api/health" >/dev/null && return 0
  done
  return 1
}

# The recorder key signs on-chain verdicts and belongs to the API alone (contracts/base/DEPLOY_ROBINHOOD.md,
# section 8). This reads the running bot process itself. grep -z reads the NUL-separated environ without a pipe,
# and a read error (grep exit 2) counts as a failure, never as a clean result. Nothing is printed from it.
bot_process_clean() {
  local pid rc=0
  pid=$(systemctl show -p MainPID --value "$BOT_UNIT")
  if [ "$pid" = 0 ]; then
    echo "bot is not running: no process environment to inspect"
    return 0
  fi
  grep -qz "^$RECORDER_KEY=" "/proc/$pid/environ" || rc=$?
  case $rc in
    1) echo "bot pid $pid: $RECORDER_KEY is not in its environment" ;;
    0) echo "bot pid $pid has $RECORDER_KEY in its environment" >&2; return 1 ;;
    *) echo "could not read the environment of bot pid $pid" >&2; return 1 ;;
  esac
}

# A unit that crashes and restarts can look active at any one moment, so watch both for a while.
units_settled() {
  local api_restarts bot_restarts
  api_restarts=$(systemctl show -p NRestarts --value "$API_UNIT")
  bot_restarts=$(systemctl show -p NRestarts --value "$BOT_UNIT")
  sleep 20
  [ "$(systemctl is-active "$API_UNIT" || true)" = active ] &&
    [ "$(systemctl is-active "$BOT_UNIT" || true)" = active ] &&
    [ "$(systemctl show -p NRestarts --value "$API_UNIT")" = "$api_restarts" ] &&
    [ "$(systemctl show -p NRestarts --value "$BOT_UNIT")" = "$bot_restarts" ]
}

# ---------------------------------------------------------------- preflight (read-only)
preflight() {
  local head rc=0 bot_unit need free
  head=$(git -C "$APP" rev-parse HEAD)

  say "Current state"
  echo "deployed : $head"
  echo "api      : $(systemctl is-active "$API_UNIT" || true)"
  echo "bot      : $(systemctl is-active "$BOT_UNIT" || true)"
  systemctl cat "$API_UNIT" >/dev/null 2>&1 || fail "unit $API_UNIT not found"
  bot_unit=$(systemctl cat "$BOT_UNIT" 2>/dev/null) || fail "unit $BOT_UNIT not found"
  [ -x "$PY" ] || fail "no Python at $PY"

  say "Database and backup space"
  [ -f "$DB" ] || fail "no database at $DB"
  need=$(( $(stat -c %s "$DB") / 1024 * 2 ))
  free=$(df -Pk "$(dirname "$BACKUP")" | awk 'NR == 2 { print $4 }')
  echo "database $(( need / 2 )) KiB; $free KiB free for the backup"
  [ "$free" -gt "$need" ] || fail "not enough free space in $(dirname "$BACKUP") to back up $DB"

  say "No modified tracked files (untracked and ignored files survive a checkout)"
  if [ -n "$(git -C "$APP" status --porcelain --untracked-files=no)" ]; then
    git -C "$APP" status --short --untracked-files=no
    fail "modified tracked files in $APP: resolve them before deploying"
  fi
  echo "clean"

  say "Only the API can see the recorder key"
  # Both units load the shared .env, and the bot must never hold the key. A comment naming it (as in
  # .env.example) is not an assignment.
  if [ -f "$APP/.env" ]; then
    grep -qE "^[[:space:]]*(export[[:space:]]+)?$RECORDER_KEY[[:space:]]*=" "$APP/.env" || rc=$?
    case $rc in
      0) fail "$RECORDER_KEY is in the shared $APP/.env, which the bot reads" ;;
      1) ;;
      *) fail "could not read $APP/.env" ;;
    esac
  fi
  if grep -q -e recorder.env -e "$RECORDER_KEY" <<<"$bot_unit"; then
    fail "the $BOT_UNIT unit loads recorder.env or sets $RECORDER_KEY: only the API may"
  fi
  echo "shared .env and the $BOT_UNIT unit are clean"
  bot_process_clean || fail "the running bot process check did not pass"

  say "Target commit"
  git -C "$APP" fetch --quiet origin
  TARGET=$(git -C "$APP" rev-parse --verify --quiet "$1^{commit}") || fail "$1 is not a commit in $APP after git fetch"
  git -C "$APP" log --oneline -1 "$TARGET"
  if [ "$TARGET" = "$head" ]; then
    echo "already deployed: --cutover would back up, restart and re-verify"
  elif git -C "$APP" merge-base --is-ancestor "$head" "$TARGET"; then
    echo "$(git -C "$APP" rev-list --count "$head..$TARGET") commit(s) ahead of the deployed one"
  else
    echo "not a descendant of the deployed commit: the database may hold schema this code does not expect"
  fi
  if git -C "$APP" diff --quiet "$head" "$TARGET" -- requirements.txt; then
    echo "requirements.txt unchanged"
  else
    echo "requirements.txt changes: pip will install new packages"
  fi

  printf '\n\033[32mGO\033[0m %s, rollback point %s\n' "${TARGET:0:7}" "${head:0:7}"
}

# ---------------------------------------------------------------- checks against the new code
# The chains the API must serve come from the deployed code itself (utils/chain_info.py), loaded as a
# single file so the check does not import the whole application.
check_health() {
  local health
  health=$(curl -sf --max-time 10 "$API_URL/api/health")
  "$PY" - "$APP/utils/chain_info.py" "$health" <<'PYEOF'
import importlib.util
import json
import sys

spec = importlib.util.spec_from_file_location("chain_info", sys.argv[1])
chain_info = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chain_info)
expected = set(chain_info.CHAIN_INFO)
health = json.loads(sys.argv[2])
served = set(health.get("supported_chains") or [])
if health.get("status") != "ok":
    sys.exit(f"/api/health status is {health.get('status')!r}")
if served != expected:
    sys.exit(f"/api/health serves chains {sorted(served)}, expected {sorted(expected)}")
print(f"/api/health ok, chains {sorted(served)}")
PYEOF
}

# /api/stats reads the database. The API can stall for seconds while it starts, so allow a few tries.
check_stats() {
  local i stats
  for i in 1 2 3; do
    stats=$(curl -sf --max-time 30 "$API_URL/api/stats" || true)
    if [ -n "$stats" ] && "$PY" -c 'import json, sys; assert isinstance(json.loads(sys.argv[1]), dict)' "$stats"; then
      echo "/api/stats answered: $stats"
      return 0
    fi
    sleep 5
  done
  echo "/api/stats did not answer with a JSON object" >&2
  return 1
}

# The backup runs with both units stopped. sqlite3's backup API writes the copy, which leaves WAL mode so it is
# one self-contained file (the app switches it back when it opens it) and is checked before it gets its final
# name, so a partial backup can never be restored.
backup_db() {
  "$PY" - "$DB" "$BACKUP/shieldbot.db.partial" <<'PYEOF'
import sqlite3
import sys
from pathlib import Path

source = sqlite3.connect(Path(sys.argv[1]).resolve().as_uri() + "?mode=rw", uri=True)
copy = sqlite3.connect(sys.argv[2])
source.backup(copy)
source.close()
copy.execute("PRAGMA journal_mode=DELETE")
result = copy.execute("PRAGMA quick_check").fetchone()[0]
copy.close()
if result != "ok":
    sys.exit(f"backup failed its integrity check: {result}")
PYEOF
  mv "$BACKUP/shieldbot.db.partial" "$BACKUP/shieldbot.db"
  ls -la "$BACKUP"
}

# ---------------------------------------------------------------- restore
# Puts back the commit and database recorded in $BACKUP and restarts both units. Returns 0 only when the API
# answers /api/health and the bot is active again.
restore() {
  trap - ERR
  set +e
  local old ok=0
  old=$(cat "$BACKUP/ROLLBACK_COMMIT")
  printf '\n\033[31m== Restoring %s from %s\033[0m\n' "${old:0:7}" "$BACKUP" >&2
  systemctl stop "$BOT_UNIT"
  systemctl stop "$API_UNIT"
  if ! git -C "$APP" checkout --quiet "$old"; then
    echo "git checkout $old failed: both units are left stopped and the database is untouched" >&2
    return 1
  fi
  if [ -f "$BACKUP/shieldbot.db" ]; then
    # A WAL left by the failed run must never be replayed onto the restored file. Copying into the existing
    # file keeps its owner and mode.
    rm -f "$DB-wal" "$DB-shm"
    cp "$BACKUP/shieldbot.db" "$DB" || { echo "could not copy the database back: units left stopped" >&2; return 1; }
    echo "database restored from $BACKUP/shieldbot.db"
  else
    echo "no database in $BACKUP (the failure came before the backup): database left as it was"
  fi
  "$VENV/bin/pip" install -q -r "$APP/requirements.txt" || ok=1
  systemctl start "$API_UNIT"
  if wait_health; then echo "API answers on ${old:0:7}"; else echo "API did not answer: journalctl -u $API_UNIT" >&2; ok=1; fi
  systemctl start "$BOT_UNIT"
  if wait_active "$BOT_UNIT"; then echo "bot active"; else echo "bot is not active: journalctl -u $BOT_UNIT" >&2; ok=1; fi
  return "$ok"
}

rollback() {
  if restore; then
    printf '\n\033[31mFAILED: the deploy of %s was rolled back to %s\033[0m\n' "${TARGET:0:7}" "${OLD:0:7}" >&2
  else
    printf '\n\033[31mFAILED, and the rollback did not complete: see above. Backup: %s\033[0m\n' "$BACKUP" >&2
  fi
  exit 1
}

# With errtrace (set -E) the ERR trap is inherited by command substitutions and pipeline subshells; only the main
# shell may roll back.
on_error() {
  [ "$BASHPID" = "$$" ] || return 0
  rollback
}

# ---------------------------------------------------------------- cutover
cutover() {
  preflight "$1"
  OLD=$(git -C "$APP" rev-parse HEAD)
  mkdir -m 700 "$BACKUP"
  echo "$OLD" > "$BACKUP/ROLLBACK_COMMIT"

  # From here on any failure puts the old commit and database back.
  trap on_error ERR

  say "Stopping $BOT_UNIT, then $API_UNIT"
  systemctl stop "$BOT_UNIT"
  systemctl stop "$API_UNIT"

  say "Backing up the database to $BACKUP"
  backup_db

  say "Deploying ${TARGET:0:7}"
  git -C "$APP" checkout --quiet "$TARGET"
  "$VENV/bin/pip" install -q -r "$APP/requirements.txt"

  say "Starting $API_UNIT alone (it runs any migration)"
  systemctl start "$API_UNIT"
  wait_health || { journalctl -u "$API_UNIT" -n 40 --no-pager || true; rollback; }
  check_health
  check_stats

  say "Starting $BOT_UNIT"
  systemctl start "$BOT_UNIT"
  wait_active "$BOT_UNIT" || { journalctl -u "$BOT_UNIT" -n 40 --no-pager || true; rollback; }

  say "The bot's live process cannot see the recorder key"
  if ! bot_process_clean; then
    trap - ERR
    systemctl stop "$BOT_UNIT"
    printf '\033[31mSECURITY: %s stopped. The API is live on %s. Keep %s out of the bot, then start it.\033[0m\n' \
      "$BOT_UNIT" "${TARGET:0:7}" "$RECORDER_KEY" >&2
    exit 1
  fi

  say "Both units stay up"
  units_settled || {
    journalctl -u "$API_UNIT" -n 20 --no-pager || true
    journalctl -u "$BOT_UNIT" -n 20 --no-pager || true
    rollback
  }
  echo "$API_UNIT and $BOT_UNIT active, no restarts"

  trap - ERR
  printf '\n\033[32mDEPLOYED\033[0m %s -> %s\n' "${OLD:0:7}" "${TARGET:0:7}"
  echo "Rollback: bash $0 --rollback $BACKUP"
}

main() {
  case "${1:-}" in
    --check | --cutover) [ $# -eq 2 ] && [[ $2 =~ ^[0-9a-fA-F]{7,40}$ ]] || usage ;;
    --rollback) [ $# -eq 2 ] || usage ;;
    *) usage ;;
  esac
  [ "$(id -u)" = 0 ] || fail "run as root"
  exec 9>"$LOCK"
  flock -n 9 || fail "another deploy holds $LOCK"

  case $1 in
    --check) preflight "$2" ;;
    --cutover) cutover "$2" ;;
    --rollback)
      BACKUP=${2%/}
      [[ -f $BACKUP/ROLLBACK_COMMIT && $(cat "$BACKUP/ROLLBACK_COMMIT") =~ ^[0-9a-f]{40}$ ]] ||
        fail "$BACKUP/ROLLBACK_COMMIT is missing or is not a commit"
      restore
      ;;
  esac
}

# Everything above only defines functions. The checkout rewrites this file when it is run from the tree it
# deploys, so nothing after this line may be read later: main and exit are parsed together.
main "$@"; exit
