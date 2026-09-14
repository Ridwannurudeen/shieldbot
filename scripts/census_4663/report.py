"""Cohort metrics for the Robinhood Chain observation census."""

import argparse
import asyncio
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, localcontext


WETH = "0x0bd7d308f8e1639fab988df18a8011f41eacad73"
NATIVE = "0x0000000000000000000000000000000000000000"
ETH_CURRENCIES = {WETH, NATIVE}
INFRASTRUCTURE = {
    "0x8366a39cc670b4001a1121b8f6a443a643e40951",  # v4 PoolManager
    "0x58daec3116aae6d93017baaea7749052e8a04fa7",  # PositionManager
    "0x8876789976decbfcbbbe364623c63652db8c0904",  # Universal Router
    "0x000000000022d473030f116ddee9f6b43ac78ba3",  # Permit2
    "0x8dc178efb8111bb0973dd9d722ebeff267c98f94",  # Quoter
    "0xf3334192d15450cdd385c8b70e03f9a6bd9e673b",  # StateView
    "0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f",  # V2 factory
    "0x89e5db8b5aa49aa85ac63f691524311aeb649eba",  # V2 Router02
    *ETH_CURRENCIES,
}
DOPPLER_SOURCE = "https://raw.githubusercontent.com/whetstoneresearch/doppler/main/deployments.config.toml"
# [4663.address] in the official deployment configuration above.
LAUNCH_LABELS = {
    "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544": "Doppler HookInitializer",
    "0xeb7c034704ef8dcd2d32324c1545f62fb4ad0862": "Doppler Airlock",
}
METHODS = {
    "new_tokens": "First observed pool creation in this census, not token deployment. "
    "One token per day globally; source counts deduplicate tokens but overlap across sources.",
    "candidates": "Transaction recipient and receipt emitters are candidates, not proven "
    "launchpads. Launch counts require the token's first Transfer in that receipt to be "
    "a mint; earlier-minted tokens are prior. Topic counts include candidate logs in "
    "pool-creation receipts and one example transaction per topic. Known AMM infrastructure, "
    "tokens and pair contracts are excluded from ranking; full receipt evidence is retained. "
    "Contract counts from the same launch transaction overlap, are not independent launchpads "
    "and must not be summed. Doppler components form one token-deduplicated launch stack; "
    "unlabelled addresses remain separate candidates with potentially overlapping counts.",
    "launch_labels": f"Doppler labels: [official deployment configuration]({DOPPLER_SOURCE}), "
    "section [4663.address].",
    "eligibility": "At least 10 Swap logs OR at least 0.5 ETH of simultaneously observed "
    "ETH/WETH-side liquidity across a token's pools within 1,800 seconds of its first "
    "observed pool. Tokens younger than 1,800 seconds at the coverage-clamped window "
    "end are excluded. Missing liquidity evidence is unknown; observed lower bounds "
    "can establish a pass. Pass rate denominator includes all mature tokens. "
    "All threshold comparisons use Decimal liquidity; floats are presentation only.",
    "v4_liquidity": "Estimate of position principal reconstructed from signed "
    "ModifyLiquidity deltas grouped by sender/tickLower/tickUpper/salt and repriced "
    "at Initialize/Swap sqrtPriceX96. For sqrt tick bounds a,b and clamped price p: "
    "amount0=L*(1/p-1/b), amount1=L*(p-a); divide ETH-side wei by 1e18. "
    "Uses decimal sqrt(1.0001**tick), not Solidity's exact integer rounding. "
    "Excludes fees, donations and hook-specific claims; not executable exit liquidity.",
    "v2_liquidity": "Latest Sync reserve on the WETH side, divided by 1e18; "
    "no Sync means unknown. Peaks use simultaneous pool states, not sum of pool peaks.",
    "latency": "Creation-event collector ingestion time minus creation block timestamp "
    "in seconds; includes confirmation delay and historical replay delay.",
}


def parse_time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(
            "Time must include a timezone (for example, 2026-09-13T12:00:00Z)"
        )
    return parsed.timestamp()


def _iso(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _principal(positions, sqrt_price_x96, side):
    # Formula: Uniswap v4-core src/libraries/SqrtPriceMath.sol getAmount{0,1}Delta.
    # Tick price: v4-core src/libraries/TickMath.sol getSqrtPriceAtTick.
    if sqrt_price_x96 is None or sqrt_price_x96 <= 0:
        return None
    with localcontext() as context:
        context.prec = 70
        price = Decimal(sqrt_price_x96) / Decimal(2**96)
        total = Decimal(0)
        for (_, lower, upper, _), liquidity in positions.items():
            if liquidity < 0 or lower >= upper:
                return None
            a = Decimal("1.0001") ** (Decimal(lower) / 2)
            b = Decimal("1.0001") ** (Decimal(upper) / 2)
            p = min(b, max(a, price))
            amount = (1 / p - 1 / b) if side == 0 else (p - a)
            total += Decimal(liquidity) * amount
        return total / Decimal(10**18)


def _token_metrics(token, pools, events, first_seen, end):
    deadline = min(first_seen + 1800, end)
    pool_map = {pool["pool_key"]: pool for pool in pools}
    states = {}
    for key, pool in pool_map.items():
        if pool["timestamp"] > deadline:
            continue
        eth_side = next(
            (i for i in (0, 1) if pool[f"token{i}"] in ETH_CURRENCIES), None
        )
        states[key] = {
            "side": eth_side,
            "value": None,
            "positions": {},
            "price": pool["data"].get("sqrt_price_x96"),
            "modified": False,
            "invalid": False,
        }
    swaps = buys = sells = 0
    maximum = None
    unknown = any(state["side"] is None for state in states.values())
    for event in sorted(events, key=lambda e: (e["block_number"], e["log_index"])):
        key = event["pool_key"]
        if (
            key not in pool_map
            or event["timestamp"] < first_seen
            or event["timestamp"] > end
        ):
            continue
        pool, fields = pool_map[key], event["data"]
        if event["name"] == "Swap":
            if event["timestamp"] <= deadline:
                swaps += 1
            side = 0 if pool["token0"] == token else 1
            if pool["source"] == "v4":
                amount = fields.get(f"amount{side}")
                buys += int(amount is not None and amount > 0)
                sells += int(amount is not None and amount < 0)
            elif pool["source"] == "v2":
                buys += int(fields.get(f"amount{side}_out", 0) > 0)
                sells += int(fields.get(f"amount{side}_in", 0) > 0)
        if event["timestamp"] > deadline or key not in states:
            continue
        state = states[key]
        if state["side"] is None:
            continue
        if pool["source"] == "v4":
            if event["name"] in ("Initialize", "Swap"):
                state["price"] = fields.get("sqrt_price_x96")
            if event["name"] == "ModifyLiquidity":
                required = (
                    "sender",
                    "tick_lower",
                    "tick_upper",
                    "salt",
                    "liquidity_delta",
                )
                if any(field not in fields for field in required):
                    state["invalid"] = True
                else:
                    position = tuple(fields[field] for field in required[:-1])
                    positions = state["positions"]
                    positions[position] = (
                        positions.get(position, 0) + fields["liquidity_delta"]
                    )
                    state["invalid"] |= positions[position] < 0
                    state["modified"] = True
            if state["modified"] and not state["invalid"]:
                state["value"] = _principal(
                    state["positions"], state["price"], state["side"]
                )
            else:
                state["value"] = None
        elif pool["source"] == "v2" and event["name"] == "Sync":
            reserve = fields.get(f"reserve{state['side']}")
            state["value"] = (
                Decimal(reserve) / Decimal(10**18) if reserve is not None else None
            )
        current = [s["value"] for s in states.values() if s["value"] is not None]
        if current:
            with localcontext() as context:
                context.prec = 70
                total = sum(current, Decimal(0))
            maximum = total if maximum is None else max(maximum, total)
    unknown |= any(state["value"] is None for state in states.values())
    return {
        "token": token,
        "first_seen": first_seen,
        "age_seconds": end - first_seen,
        "mature": end - first_seen >= 1800,
        "sources": sorted({pool["source"] for pool in pools}),
        "pool_keys": sorted(pool_map),
        "swaps_30m": swaps,
        "buys_window": buys,
        "sells_window": sells,
        "max_eth_liquidity_30m": maximum,
        "liquidity_incomplete": unknown,
    }


def _status(token, swaps, eth):
    if not token["mature"]:
        return "young"
    liquidity = token["max_eth_liquidity_30m"]
    if token["swaps_30m"] >= swaps or (
        liquidity is not None and liquidity >= Decimal(str(eth))
    ):
        return "pass"
    return "unknown" if token["liquidity_incomplete"] else "fail"


def _eligibility(tokens, swaps, eth):
    counts = Counter(_status(token, swaps, eth) for token in tokens)
    mature = len(tokens) - counts["young"]
    return {
        "swaps_threshold": swaps,
        "eth_threshold": eth,
        "mature": mature,
        "young_excluded": counts["young"],
        "passed": counts["pass"],
        "failed": counts["fail"],
        "unknown": counts["unknown"],
        "pass_rate": counts["pass"] / mature if mature else None,
    }


def build_report(data, since=None, until=None):
    if data["meta"].get("chain_id") != "4663":
        raise ValueError("Census chain_id must be 4663")
    if not data["blocks"]:
        raise ValueError("Census contains no collected blocks")
    coverage_start = min(block["timestamp"] for block in data["blocks"])
    coverage_end = max(block["timestamp"] for block in data["blocks"])
    start = max(coverage_start, since) if since is not None else coverage_start
    end = min(coverage_end, until) if until is not None else coverage_end
    if start > end:
        raise ValueError("Report window does not overlap collected data")
    token_pools = defaultdict(list)
    pool_events = defaultdict(list)
    for event in data["events"]:
        pool_events[event["pool_key"]].append(event)
    for pool in data["pools"]:
        for token in {pool["token0"], pool["token1"]} - ETH_CURRENCIES:
            token_pools[token].append(pool)
    tokens = []
    daily = defaultdict(lambda: defaultdict(set))
    source_tokens = defaultdict(set)
    for token, pools in sorted(token_pools.items()):
        first = min(pool["timestamp"] for pool in pools)
        if not start <= first <= end:
            continue
        pools = [pool for pool in pools if pool["timestamp"] <= end]
        events = [event for pool in pools for event in pool_events[pool["pool_key"]]]
        metrics = _token_metrics(token, pools, events, first, end)
        metrics["eligibility"] = _status(metrics, 10, 0.5)
        tokens.append(metrics)
        day = _iso(first)[:10]
        daily[day]["all"].add(token)
        for source in metrics["sources"]:
            daily[day][source].add(token)
            source_tokens[source].add(token)
    cohort = {token["token"]: token for token in tokens}
    excluded = INFRASTRUCTURE | set(token_pools)
    excluded.update(
        pool["pool_key"] for pool in data["pools"] if pool["source"] in ("v2", "v3")
    )
    if data["meta"].get("v3_factory"):
        excluded.add(data["meta"]["v3_factory"])
    candidates = {}
    prior = set()
    atomic = set()
    for evidence in data["evidence"]:
        fields = evidence["data"]
        matching = {
            token
            for token in fields["tokens"]
            if token in cohort
            and any(
                pool["tx_hash"] == evidence["tx_hash"]
                and start <= pool["timestamp"] <= end
                for pool in token_pools[token]
            )
        }
        if not matching:
            continue
        minted = {
            token
            for token in matching
            if fields["tokens"][token].get("first_transfer_mint") is True
        }
        atomic.update(minted)
        prior.update(
            token
            for token in matching
            if fields["tokens"][token].get("first_transfer_mint") is False
        )
        addresses = set(fields["emitters"])
        if fields.get("to"):
            addresses.add(fields["to"])
        for address in addresses - excluded - fields["tokens"].keys():
            candidate = candidates.setdefault(
                address, {"tokens": set(), "topics": Counter(), "examples": {}}
            )
            candidate["tokens"].update(minted)
            for token in minted:
                source = "Doppler" if address in LAUNCH_LABELS else address
                daily[_iso(cohort[token]["first_seen"])[:10]][source].add(token)
            for log in fields["logs"]:
                if log["address"] == address and log["topics"]:
                    topic = log["topics"][0]
                    candidate["topics"][topic] += 1
                    candidate["examples"].setdefault(topic, evidence["tx_hash"])
    ranked = [
        {
            "address": address,
            "label": LAUNCH_LABELS.get(address),
            "launch_stack": "Doppler" if address in LAUNCH_LABELS else None,
            "new_tokens": len(candidate["tokens"]),
            "topics": [
                {
                    "topic0": topic,
                    "count": count,
                    "example_tx": candidate["examples"][topic],
                }
                for topic, count in sorted(
                    candidate["topics"].items(), key=lambda item: (-item[1], item[0])
                )
            ],
        }
        for address, candidate in candidates.items()
    ]
    ranked.sort(key=lambda candidate: (-candidate["new_tokens"], candidate["address"]))
    launch_sources = {}
    for address, candidate in candidates.items():
        name = "Doppler" if address in LAUNCH_LABELS else address
        source = launch_sources.setdefault(name, {"tokens": set(), "contracts": []})
        source["tokens"].update(candidate["tokens"])
        source["contracts"].append(address)
    source_ranking = sorted(
        (
            {
                "name": name,
                "new_tokens": len(source["tokens"]),
                "contracts": sorted(source["contracts"]),
            }
            for name, source in launch_sources.items()
        ),
        key=lambda source: (-source["new_tokens"], source["name"]),
    )
    creation_keys = {
        pool["pool_key"]
        for pool in data["pools"]
        if start <= pool["timestamp"] <= end
        and ({pool["token0"], pool["token1"]} & cohort.keys())
    }
    latency = sorted(
        event["ingested_at"] - event["timestamp"]
        for event in data["events"]
        if event["pool_key"] in creation_keys
        and event["name"] in ("Initialize", "PairCreated", "PoolCreated")
    )
    distribution = {"count": len(latency)}
    for label, quantile in (
        ("min", 0),
        ("p50", 0.5),
        ("p90", 0.9),
        ("p95", 0.95),
        ("p99", 0.99),
        ("max", 1),
    ):
        distribution[label] = (
            latency[max(0, math.ceil(quantile * len(latency)) - 1)] if latency else None
        )
    result = {
        "version": 1,
        "chain_id": 4663,
        "window": {
            "since": _iso(start),
            "until": _iso(end),
            "coverage_start": _iso(coverage_start),
            "coverage_end": _iso(coverage_end),
        },
        "v3": "measured (creation only; eligibility unknown)"
        if data["meta"].get("v3_factory")
        else "v3 not measured",
        "new_tokens": {
            "total": len(tokens),
            "by_source": {
                source: len(source_tokens[source]) for source in ("v4", "v2", "v3")
            },
            "atomic": len(atomic),
            "prior": len(prior - atomic),
            "launch_source_unknown": len(cohort.keys() - atomic - prior),
        },
        "new_tokens_per_day": {
            day: {
                source: len(addresses) for source, addresses in sorted(sources.items())
            }
            for day, sources in sorted(daily.items())
        },
        "eligibility": _eligibility(tokens, 10, 0.5),
        "threshold_grid": [
            _eligibility(tokens, swaps, eth)
            for swaps in (5, 10, 20)
            for eth in (0.1, 0.5, 1.0)
        ],
        "discovery_latency_seconds": distribution,
        "candidate_launch_contracts": ranked,
        "launch_sources": source_ranking,
        "tokens": tokens,
        "methods": METHODS,
    }
    for token in tokens:
        liquidity = token["max_eth_liquidity_30m"]
        token["max_eth_liquidity_30m"] = (
            float(liquidity) if liquidity is not None else None
        )
    return result


def render_markdown(report):
    eligibility = report["eligibility"]
    rate = eligibility["pass_rate"]
    lines = [
        "# Robinhood Chain census",
        "",
        f"Window: {report['window']['since']} to {report['window']['until']}",
        "",
        f"New tokens: **{report['new_tokens']['total']}**. Sources: {report['new_tokens']['by_source']}. "
        f"Atomic: {report['new_tokens']['atomic']}; prior: {report['new_tokens']['prior']}; "
        f"source unknown: {report['new_tokens']['launch_source_unknown']}.",
        "",
        f"Eligibility: {eligibility['passed']}/{eligibility['mature']} mature tokens "
        f"({format(rate, '.2%') if rate is not None else 'unknown'}); "
        f"{eligibility['young_excluded']} young excluded; {eligibility['unknown']} unknown.",
        "",
        report["v3"],
        "",
        "## Daily deduplicated counts",
        "",
        "| Day | Source / candidate | Tokens |",
        "| --- | --- | ---: |",
    ]
    for day, sources in report["new_tokens_per_day"].items():
        lines.extend(
            f"| {day} | {source} | {count} |" for source, count in sources.items()
        )
    lines.extend(
        [
            "",
            "## Threshold grid",
            "",
            "| Swaps OR ETH | Passed / mature | Rate | Unknown |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for grid in report["threshold_grid"]:
        rate = grid["pass_rate"]
        lines.append(
            f"| {grid['swaps_threshold']} OR {grid['eth_threshold']} | {grid['passed']} / {grid['mature']} | {format(rate, '.2%') if rate is not None else 'unknown'} | {grid['unknown']} |"
        )
    lines.extend(
        [
            "",
            "## Discovery latency (seconds)",
            "",
            json.dumps(report["discovery_latency_seconds"], sort_keys=True),
            "",
            "## Launch-source ranking",
            "",
            "| Launch stack / candidate | Tokens |",
            "| --- | ---: |",
        ]
    )
    lines.extend(
        f"| {source['name']} | {source['new_tokens']} |"
        for source in report["launch_sources"]
    )
    lines.extend(
        [
            "",
            "Contract counts overlap and must not be summed. Doppler is one launch stack.",
            "",
            "## Per-contract evidence (components, not independent launchpads)",
            "",
        ]
    )
    for candidate in report["candidate_launch_contracts"]:
        lines.extend(
            [
                f"### {candidate['label'] or candidate['address']} ({candidate['new_tokens']} tokens)",
                f"Address: {candidate['address']}",
                "",
                "| Topic0 | Logs | Example transaction |",
                "| --- | ---: | --- |",
            ]
        )
        lines.extend(
            f"| {topic['topic0']} | {topic['count']} | {topic['example_tx']} |"
            for topic in candidate["topics"]
        )
        lines.append("")
    lines.extend(["## Metric definitions and limits", ""])
    lines.extend(
        f"- **{name}**: {method}" for name, method in report["methods"].items()
    )
    return "\n".join(lines) + "\n"


async def run(args):
    from .storage import data_directory, load_data

    directory = data_directory(args.data_dir)
    report = build_report(
        await load_data(directory),
        parse_time(args.since) if args.since else None,
        parse_time(args.until) if args.until else None,
    )
    (directory / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (directory / "report.md").write_text(render_markdown(report), encoding="utf-8")
    print(
        json.dumps(
            {
                key: report[key]
                for key in ("new_tokens", "eligibility", "discovery_latency_seconds")
            }
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--since")
    parser.add_argument("--until")
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
