"""Measure GoPlus field availability without interpreting missing data as safe."""

import argparse
import asyncio
import json

import aiohttp

from .probes import (
    IMPORTANT_FIELDS,
    account_fields,
    request_record,
    sample_tokens,
    save_probe,
)


URL = "https://api.gopluslabs.io/api/v1/token_security/4663"


async def probe(data_dir, limit):
    tokens = await sample_tokens(data_dir, limit)
    records = []
    async with aiohttp.ClientSession() as session:
        for token in tokens:
            if records:
                await asyncio.sleep(1)
            record = await request_record(
                session,
                token,
                URL,
                params={"contract_addresses": token},
            )
            payload = record["response"]
            if record["error"] is None:
                if not isinstance(payload, dict) or str(payload.get("code")) != "1":
                    record["error"] = "GoPlus did not return a successful result"
                elif "chain_id" in payload and str(payload["chain_id"]) != "4663":
                    record["error"] = "GoPlus returned the wrong chain"
                else:
                    result = payload.get("result")
                    fields = result.get(token) if isinstance(result, dict) else None
                    if isinstance(fields, dict) and fields:
                        account_fields(record, fields)
                    else:
                        record["error"] = "GoPlus token data missing or malformed"
            records.append(record)
    return save_probe(data_dir, "goplus", records, important_fields=IMPORTANT_FIELDS)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--limit", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(probe(args.data_dir, args.limit))
    except ValueError as exc:
        parser.error(str(exc))
    print(
        json.dumps({"calls": result["calls"], "field_summary": result["field_summary"]})
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
