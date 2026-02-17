#!/usr/bin/env python3
"""CLI for managing ShieldBot API keys.

Usage:
    python scripts/manage_keys.py create --owner "partner" --tier pro
    python scripts/manage_keys.py deactivate --key-id "sb_abc123"
    python scripts/manage_keys.py list
"""

import argparse
import asyncio
import sys
import os

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import Settings
from core.database import Database
from core.auth import AuthManager


async def cmd_create(args, db):
    auth = AuthManager(db)
    result = await auth.create_key(owner=args.owner, tier=args.tier)
    print(f"API key created:")
    print(f"  Key:   {result['key']}")
    print(f"  ID:    {result['key_id']}")
    print(f"  Owner: {result['owner']}")
    print(f"  Tier:  {result['tier']}")
    print(f"\nStore this key securely — it cannot be recovered.")


async def cmd_deactivate(args, db):
    auth = AuthManager(db)
    await auth.deactivate_key(args.key_id)
    print(f"Key {args.key_id} deactivated.")


async def cmd_list(args, db):
    cursor = await db._db.execute(
        "SELECT key_id, owner, tier, is_active, created_at FROM api_keys ORDER BY created_at DESC"
    )
    rows = await cursor.fetchall()
    if not rows:
        print("No API keys found.")
        return

    print(f"{'Key ID':<14} {'Owner':<20} {'Tier':<8} {'Active':<8}")
    print("-" * 50)
    for row in rows:
        active = "Yes" if row[3] else "No"
        print(f"{row[0]:<14} {row[1]:<20} {row[2]:<8} {active:<8}")


async def main():
    parser = argparse.ArgumentParser(description="ShieldBot API Key Management")
    sub = parser.add_subparsers(dest="command")

    create_p = sub.add_parser("create", help="Create a new API key")
    create_p.add_argument("--owner", required=True, help="Key owner name")
    create_p.add_argument("--tier", default="free", choices=["free", "pro"], help="Key tier")

    deact_p = sub.add_parser("deactivate", help="Deactivate an API key")
    deact_p.add_argument("--key-id", required=True, help="Key ID prefix (sb_...)")

    sub.add_parser("list", help="List all API keys")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    settings = Settings()
    db = Database(settings.database_path)
    await db.initialize()

    try:
        if args.command == "create":
            await cmd_create(args, db)
        elif args.command == "deactivate":
            await cmd_deactivate(args, db)
        elif args.command == "list":
            await cmd_list(args, db)
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
