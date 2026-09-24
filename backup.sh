#!/bin/bash
# Consistent backup of the ShieldBot SQLite database; safe while both services run.
#
#   KEEP_DAYS       days of local backups to keep (default 7)
#   BACKUP_REMOTE   optional scp destination for an off-box copy, e.g. backup@host:/srv/shieldbot/
#                   (unset: nothing leaves this machine)
#
# Set both on the cron line rather than editing this file: a modified tracked file stops deploy/deploy.sh.
# Scheduling and restore steps: deploy/README.md.

set -Eeuo pipefail
umask 077

DB=/opt/shieldbot/shieldbot.db
BACKUP_DIR=/opt/shieldbot/backups
PY=/opt/shieldbot/venv/bin/python3
KEEP_DAYS=${KEEP_DAYS:-7}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEST=$BACKUP_DIR/shieldbot_$TIMESTAMP.db

if ! [[ $KEEP_DAYS =~ ^[1-9][0-9]*$ ]]; then
  echo "KEEP_DAYS must be a whole number of days, got '$KEEP_DAYS'" >&2
  exit 2
fi
mkdir -p "$BACKUP_DIR"
trap 'rm -f "$DEST.partial"' EXIT

# sqlite3's backup API copies a consistent snapshot while the services keep writing. mode=rw never creates a
# missing database, and the copy gets its final name only after it passes an integrity check. The copy leaves
# WAL mode so it is one self-contained file that opens read-only without leaving -wal/-shm files beside it;
# the app switches it back to WAL when it opens it (core/database.py).
"$PY" - "$DB" "$DEST.partial" <<'PYEOF'
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
mv "$DEST.partial" "$DEST"
echo "[$TIMESTAMP] Backup saved: $DEST"

# Pruning runs only after a good backup, so a failing job never deletes the last good copies.
find "$BACKUP_DIR" -maxdepth 1 -name 'shieldbot_*.db' -mmin +$(( KEEP_DAYS * 24 * 60 )) -print -delete

if [ -n "${BACKUP_REMOTE:-}" ]; then
  scp -q -p -o BatchMode=yes "$DEST" "$BACKUP_REMOTE"
  echo "[$TIMESTAMP] Copied off-box to $BACKUP_REMOTE"
fi
