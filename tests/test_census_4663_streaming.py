"""Streamed, read-only census reports must equal the fully loaded report."""

import hashlib
import json
import random
import sqlite3
from argparse import Namespace

import aiosqlite
import pytest

from scripts.census_4663 import probes, smoke_cases
from scripts.census_4663.report import (
    NATIVE,
    WETH,
    build_report,
    parse_time,
    render_markdown,
    run,
)
from scripts.census_4663.smoke_cases import select_cases
from scripts.census_4663.storage import initialize, load_data, read_snapshot


HUB = "0x" + "99" * 20
ROUTER = "0x" + "ab" * 20
DOPPLER_HOOK = "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"
DOPPLER_AIRLOCK = "0xeb7c034704ef8dcd2d32324c1545f62fb4ad0862"
POOL_MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951"


async def census_database(directory):
    """Write a seeded census with ties, boundary timestamps and shuffled row order."""
    rng = random.Random(4663)
    hashes = iter(range(1, 10**6))
    keys = set()
    pools, events, evidence = [], [], []

    def tx_hash():
        return "0x" + format(next(hashes), "064x")

    def pool_key(width):
        while True:
            key = "0x" + format(rng.getrandbits(width * 4), f"0{width}x")
            if key not in keys:
                keys.add(key)
                return key

    def block(timestamp):
        return (timestamp - 10000) // 10

    def event(source, key, name, timestamp, fields, number=None, log_index=None):
        events.append(
            (
                source,
                key,
                name,
                block(timestamp) if number is None else number,
                timestamp,
                tx_hash(),
                rng.randrange(0, 40) if log_index is None else log_index,
                timestamp + rng.choice((12.5, 65.25, 3600.125)),
                json.dumps(fields),
            )
        )

    def pool(source, token0, token1, timestamp, transaction=None):
        key = pool_key(64 if source == "v4" else 40)
        transaction = transaction or tx_hash()
        if source == "v4":
            name, fields = "Initialize", {"sqrt_price_x96": rng.choice((2**96, 2**97))}
        else:
            name = "PairCreated" if source == "v2" else "PoolCreated"
            fields = {"token0": token0, "token1": token1}
        row = (key, source, token0, token1, block(timestamp), timestamp, transaction)
        pools.append((*row, json.dumps(fields)))
        events.append(
            (
                source,
                key,
                name,
                block(timestamp),
                timestamp,
                transaction,
                40 + len(pools),
                timestamp + 65.5,
                json.dumps(fields),
            )
        )
        return key, transaction

    def activity(source, key, first, count):
        for _ in range(count):
            timestamp = first + rng.randrange(-120, 5400)
            number = block(timestamp) + rng.choice((0, 0, 0, 0, -3, 3))
            if source == "v2":
                name = rng.choice(("Swap", "Swap", "Sync", "Mint"))
                if name == "Swap":
                    fields = {
                        field: rng.choice((0, 0, rng.randrange(1, 10**18)))
                        for field in (
                            "amount0_in",
                            "amount1_in",
                            "amount0_out",
                            "amount1_out",
                        )
                    }
                elif name == "Sync":
                    fields = {
                        "reserve0": rng.randrange(0, 10**21),
                        "reserve1": rng.randrange(0, 2 * 10**18),
                    }
                else:
                    fields = {"amount0": 1, "amount1": 2}
            else:
                name = rng.choice(("Swap", "Swap", "ModifyLiquidity"))
                if name == "Swap":
                    fields = {
                        "amount0": rng.randrange(-(10**18), 10**18),
                        "amount1": rng.choice((0, rng.randrange(-(10**18), 10**18))),
                        "sqrt_price_x96": rng.choice((2**96, 2**97, 3 * 2**95)),
                        "liquidity": 1,
                        "tick": 0,
                        "fee": 3000,
                    }
                else:
                    fields = {
                        "sender": ROUTER,
                        "tick_lower": rng.choice((-600, -60)),
                        "tick_upper": rng.choice((60, 600)),
                        "salt": "0x00",
                        "liquidity_delta": rng.choice(
                            (10**18, 3 * 10**18, 5 * 10**19, -(10**18))
                        ),
                    }
                    if rng.random() < 0.05:
                        del fields["salt"]
            event(source, key, name, timestamp, fields, number)

    # A token whose pools tie on (block, log index), where the tie order changes
    # its simultaneous liquidity peak, and whose events sit on the deadline.
    edge = "0x" + "a1" * 20
    pair, _ = pool("v2", edge, WETH, 10000)
    second, _ = pool("v2", edge, WETH, 10000)
    native, _ = pool("v4", NATIVE, edge, 10500)
    event("v2", pair, "Sync", 10090, {"reserve0": 1, "reserve1": 4 * 10**17}, 40, 7)
    event("v2", second, "Sync", 10095, {"reserve0": 1, "reserve1": 10**17}, 41, 1)
    event("v2", pair, "Sync", 10100, {"reserve0": 1, "reserve1": 0}, 50, 7)
    event("v2", second, "Sync", 10100, {"reserve0": 1, "reserve1": 5 * 10**17}, 50, 7)
    event(
        "v4",
        native,
        "ModifyLiquidity",
        10600,
        {
            "sender": ROUTER,
            "tick_lower": -600,
            "tick_upper": 600,
            "salt": "0x00",
            "liquidity_delta": 3 * 10**18,
        },
        60,
        7,
    )
    event("v2", pair, "Swap", 11800, {"amount0_out": 1, "amount1_in": 5}, 180, 1)
    event("v2", pair, "Swap", 11801, {"amount0_in": 1, "amount1_out": 5}, 180, 2)
    event("v2", pair, "Sync", 11801, {"reserve0": 1, "reserve1": 10**19}, 180, 3)
    event("v2", pair, "Swap", 9999, {"amount0_out": 1}, 0, 0)
    for timestamp in (12000, 16000, 18000):
        event("v2", pair, "Swap", timestamp, {"amount0_out": 2, "amount1_in": 3})

    # A hub token paired with many generated tokens, including pools created
    # after later report windows end, and an ETH-only pool.
    for timestamp in (12000, 13000, 15000, 18000, 19950):
        key, _ = pool("v4", HUB, "0x" + format(timestamp, "040x"), timestamp)
        activity("v4", key, timestamp, 25)
    pool("v2", WETH, NATIVE, 10500)
    pool("v4", "0x" + "b2" * 20, WETH, 9000)
    later, _ = pool("v4", "0x" + "b2" * 20, WETH, 14000)
    activity("v4", later, 14000, 10)

    for index in range(36):
        token = "0x" + format(0x1000 + index * 7919, "040x")
        first = rng.randrange(10000, 19950)
        transaction = None
        for offset in range(rng.choice((1, 1, 2, 3))):
            source = rng.choice(("v4", "v4", "v4", "v2", "v3"))
            quote = rng.choice((WETH, WETH, NATIVE, HUB, edge))
            if source != "v4" and quote == NATIVE:
                quote = WETH
            timestamp = min(first + offset * rng.randrange(0, 2400), 20000)
            if transaction is not None and rng.random() < 0.3:
                timestamp = pools[-1][5]
            else:
                transaction = None
            key, transaction = pool(source, token, quote, timestamp, transaction)
            if source != "v3":
                activity(source, key, timestamp, rng.randrange(5, 60))

    creations = {}
    for _, _, token0, token1, _, _, transaction, _ in pools:
        creations.setdefault(transaction, []).append((token0, token1))
    for transaction, pairs in creations.items():
        tokens = sorted({token for pair in pairs for token in pair} - {WETH, NATIVE})
        emitters = sorted(
            set(rng.sample([ROUTER, DOPPLER_HOOK, DOPPLER_AIRLOCK, POOL_MANAGER], 2))
            | set(tokens)
        )
        evidence.append(
            (
                transaction,
                0,
                json.dumps(
                    {
                        "from": "0x" + "05" * 20,
                        "to": rng.choice((ROUTER, DOPPLER_AIRLOCK, POOL_MANAGER, None)),
                        "emitters": emitters,
                        "tokens": {
                            token: rng.choice(
                                (
                                    {"first_transfer_mint": True},
                                    {"first_transfer_mint": False},
                                    {},
                                )
                            )
                            for token in tokens
                        },
                        "logs": [
                            {
                                "address": address,
                                "topics": rng.choice(([], ["0x01"], ["0x02", "0x03"])),
                            }
                            for address in emitters
                        ],
                    }
                ),
            )
        )

    for rows in (pools, events, evidence):
        rng.shuffle(rows)
    async with aiosqlite.connect(directory / "census.sqlite3") as db:
        await initialize(db)
        await db.executemany(
            "INSERT INTO meta VALUES (?, ?)",
            [
                ("chain_id", "4663"),
                ("v3_factory", "0x" + "03" * 20),
                ("start_block", "0"),
                ("cursor", "1000"),
            ],
        )
        await db.executemany(
            "INSERT INTO blocks VALUES (?, ?, ?)",
            [(n, "0x" + format(n, "064x"), 10000 + n * 10) for n in range(1001)],
        )
        await db.executemany("INSERT INTO pools VALUES (?,?,?,?,?,?,?,?)", pools)
        await db.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)", events)
        await db.executemany("INSERT INTO evidence VALUES (?,?,?)", evidence)
        await db.commit()
    return directory / "census.sqlite3"


WINDOWS = [
    (None, None),
    ("1970-01-01T03:36:40Z", None),
    (None, "1970-01-01T04:26:40Z"),
    ("1970-01-01T03:20:00Z", "1970-01-01T05:00:00Z"),
    ("1970-01-01T03:19:59.5Z", "1970-01-01T05:00:00.5Z"),
    ("1970-01-01T02:00:00Z", "1970-01-02T00:00:00Z"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("since,until", WINDOWS)
async def test_streamed_report_matches_loaded_report(tmp_path, since, until):
    await census_database(tmp_path)
    window = [parse_time(value) if value else None for value in (since, until)]
    loaded = build_report(await load_data(tmp_path), *window)
    with read_snapshot(tmp_path) as census:
        streamed = build_report(census, *window)
    assert json.dumps(streamed, indent=2) == json.dumps(loaded, indent=2)
    assert render_markdown(streamed) == render_markdown(loaded)
    assert loaded["tokens"] and loaded["candidate_launch_contracts"]
    assert loaded["discovery_latency_seconds"]["count"] > 0


@pytest.mark.asyncio
async def test_streamed_report_rejects_the_same_windows(tmp_path):
    await census_database(tmp_path)
    loaded = await load_data(tmp_path)
    with read_snapshot(tmp_path) as census:
        for since, until in ((20001, None), (None, 9999), (15000, 14000)):
            with pytest.raises(ValueError, match="does not overlap") as expected:
                build_report(loaded, since, until)
            with pytest.raises(ValueError) as actual:
                build_report(census, since, until)
            assert str(actual.value) == str(expected.value)


@pytest.mark.asyncio
async def test_streamed_smoke_selection_and_probe_sample_match_loaded_data(tmp_path):
    await census_database(tmp_path)
    loaded = await load_data(tmp_path)
    with read_snapshot(tmp_path) as census:
        streamed = select_cases(build_report(census))
    assert streamed == select_cases(build_report(loaded))
    tokens = {pool[key] for pool in loaded["pools"] for key in ("token0", "token1")}
    expected = sorted(tokens - {WETH, NATIVE})
    assert await probes.sample_tokens(tmp_path, 10**6) == expected
    assert await probes.sample_tokens(tmp_path, 3) == expected[:3]


@pytest.mark.asyncio
async def test_snapshot_is_read_only_consistent_and_does_not_block_the_writer(
    tmp_path,
):
    database = await census_database(tmp_path)
    with read_snapshot(tmp_path) as census:
        before = census.coverage()
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            census.connection.execute("INSERT INTO meta VALUES ('report', 'write')")
        writer = sqlite3.connect(database, timeout=0, isolation_level=None)
        try:
            writer.execute("BEGIN IMMEDIATE")
            writer.execute("INSERT INTO blocks VALUES (5000, '0x00', 99999)")
            writer.execute("COMMIT")
        finally:
            writer.close()
        assert census.coverage() == before
    with read_snapshot(tmp_path) as census:
        assert census.coverage() == (before[0], 99999)


@pytest.mark.asyncio
async def test_report_command_writes_loaded_report_without_modifying_database(
    tmp_path,
):
    database = await census_database(tmp_path)
    until = "1970-01-01T05:00:00Z"
    expected = build_report(await load_data(tmp_path), None, parse_time(until))
    digest = hashlib.sha256(database.read_bytes()).hexdigest()
    before = {path.name for path in tmp_path.iterdir()}
    await run(Namespace(data_dir=tmp_path, since=None, until=until))
    assert hashlib.sha256(database.read_bytes()).hexdigest() == digest
    created = {path.name for path in tmp_path.iterdir()} - before
    assert created - {"census.sqlite3-wal", "census.sqlite3-shm"} == {
        "report.json",
        "report.md",
    }
    assert (tmp_path / "report.json").read_text(encoding="utf-8") == (
        json.dumps(expected, indent=2) + "\n"
    )
    assert (tmp_path / "report.md").read_text(encoding="utf-8") == render_markdown(
        expected
    )


@pytest.mark.asyncio
async def test_read_paths_do_not_create_a_missing_data_directory(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(ValueError, match="No census database"):
        await run(Namespace(data_dir=missing, since=None, until=None))
    with pytest.raises(ValueError, match="No census database"):
        await probes.sample_tokens(missing, 1)
    with pytest.raises(ValueError, match="No census database"):
        await smoke_cases.run(
            Namespace(command="select", data_dir=missing, out=tmp_path / "cases.json")
        )
    with pytest.raises(ValueError, match="No census database"):
        with read_snapshot(missing):
            pass
    assert not missing.exists()
    assert not (tmp_path / "cases.json").exists()


@pytest.mark.asyncio
async def test_snapshot_rejects_database_not_bound_to_chain(tmp_path):
    async with aiosqlite.connect(tmp_path / "census.sqlite3") as db:
        await initialize(db)
        await db.execute("INSERT INTO meta VALUES ('chain_id', '1')")
        await db.commit()
    with pytest.raises(ValueError, match="not bound to chain 4663"):
        with read_snapshot(tmp_path):
            pass
