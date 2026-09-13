"""Probe Blockscout PRO address, token and smart-contract field availability."""

import argparse
import asyncio
import json
import os
import sys

import aiohttp

from .probes import account_fields, request_record, sample_tokens, save_probe


# Official routes and authorization: https://docs.blockscout.com/devs/pro-api-responses-and-routes
# Endpoint definitions: https://docs.blockscout.com/api-reference/{addresses,tokens,smart-contracts}/
BASE_URL = "https://api.blockscout.com/4663/api/v2"
ENDPOINTS = ("addresses", "tokens", "smart-contracts")


async def probe(data_dir, limit, api_key):
    if not api_key:
        raise ValueError("BLOCKSCOUT_API_KEY is required")
    tokens = await sample_tokens(data_dir, limit)
    records = []
    async with aiohttp.ClientSession() as session:
        for token in tokens:
            for resource in ENDPOINTS:
                if records:
                    await asyncio.sleep(1)
                record = await request_record(
                    session,
                    token,
                    f"{BASE_URL}/{resource}/{token}",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                record["resource"] = resource
                payload = record["response"]
                if record["error"] is None:
                    if (
                        not isinstance(payload, dict)
                        or not payload
                        or "error" in payload
                        or "errors" in payload
                    ):
                        record["error"] = "Blockscout data missing or malformed"
                    elif "chain_id" in payload and str(payload["chain_id"]) != "4663":
                        record["error"] = "Blockscout returned the wrong chain"
                    elif (
                        resource in ("addresses", "tokens")
                        and str(
                            payload.get(
                                "hash" if resource == "addresses" else "address_hash",
                                "",
                            )
                        ).lower()
                        != token
                    ):
                        record["error"] = (
                            "Blockscout returned a missing or different address"
                        )
                    elif resource == "smart-contracts" and not any(
                        key in payload
                        for key in (
                            "source_code",
                            "deployed_bytecode",
                            "creation_bytecode",
                        )
                    ):
                        record["error"] = (
                            "Blockscout contract data missing or malformed"
                        )
                    else:
                        account_fields(record, payload)
                records.append(record)
    return save_probe(data_dir, "blockscout", records)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--limit", required=True, type=int)
    args = parser.parse_args(argv)
    api_key = os.getenv("BLOCKSCOUT_API_KEY")
    if not api_key:
        print("BLOCKSCOUT_API_KEY is required", file=sys.stderr)
        return 2
    try:
        result = asyncio.run(probe(args.data_dir, args.limit, api_key))
    except ValueError as exc:
        parser.error(str(exc))
    print(
        json.dumps({"calls": result["calls"], "field_summary": result["field_summary"]})
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
