#!/usr/bin/env python3
"""CLI for managing ShieldBot agent registrations.

Usage:
    python scripts/manage_agents.py list-unowned
    python scripts/manage_agents.py claim <agent_id> <key_id>
"""

import argparse
import asyncio
import sys
import os

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import Settings
from core.database import Database


async def cmd_list_unowned(args, db):
    rows = await db.list_unowned_agent_policies()
    if not rows:
        print("No unowned agent policies found.")
        return

    print(f"{'Agent ID':<24} {'Owner Address':<44} {'Created At':<20}")
    print("-" * 92)
    for row in rows:
        print(f"{row['agent_id']:<24} {row['owner_address']:<44} {row['created_at']:<20}")


async def cmd_claim(args, db):
    claimed = await db.claim_unowned_agent_policy(args.agent_id, args.key_id)
    if claimed:
        print(f"Agent {args.agent_id} claimed by key {args.key_id}.")
    else:
        refusal = await db.get_agent_policy_claim_refusal(args.agent_id, args.key_id)
        if refusal == "agent_missing":
            print(f"Claim refused: agent {args.agent_id} does not exist.")
        elif refusal == "agent_owned":
            print(f"Claim refused: agent {args.agent_id} is already owned.")
        elif refusal == "key_inactive":
            print(f"Claim refused: API key {args.key_id} does not exist or is inactive.")
        else:
            print("Claim refused: policy or key state changed; retry the claim.")


async def main():
    parser = argparse.ArgumentParser(description="ShieldBot Agent Registration Management")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list-unowned", help="List agent policies without a registering API key")

    claim_p = sub.add_parser("claim", help="Assign an unowned agent policy to an API key")
    claim_p.add_argument("agent_id", help="Agent ID to claim")
    claim_p.add_argument("key_id", help="Existing API key ID")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    settings = Settings()
    db = Database(settings.database_path)
    await db.initialize()

    try:
        if args.command == "list-unowned":
            await cmd_list_unowned(args, db)
        elif args.command == "claim":
            await cmd_claim(args, db)
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
