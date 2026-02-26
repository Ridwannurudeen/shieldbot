#!/bin/bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB=/opt/shieldbot/shieldbot.db
BACKUP_DIR=/opt/shieldbot/backups
DEST=$BACKUP_DIR/shieldbot_$TIMESTAMP.db

# Safe online backup using Python sqlite3 (works while bot is running)
/opt/shieldbot/venv/bin/python3 -c "import sqlite3; src=sqlite3.connect('$DB'); dst=sqlite3.connect('$DEST'); src.backup(dst); dst.close(); src.close()"

# Keep only last 7 backups
ls -t $BACKUP_DIR/shieldbot_*.db 2>/dev/null | tail -n +8 | xargs -r rm

echo "[$TIMESTAMP] Backup saved: $DEST"
