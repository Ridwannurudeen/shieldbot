"""The shared 4663 RPC request budget and circuit breaker."""

import asyncio
import logging
from unittest.mock import patch

import pytest

from services.rpc_guard import (
    BREAKER_BASE_COOLDOWN_SECONDS,
    BREAKER_FAILURE_THRESHOLD,
    BREAKER_MAX_COOLDOWN_SECONDS,
    CLOSED,
    HALF_OPEN,
    OPEN,
    RPC_BUDGET_RPS,
    BreakerOpenError,
    RpcGuard,
    is_failure_status,
)


_real_sleep = asyncio.sleep


class FakeClock:
    """A frozen clock for RpcGuard whose asyncio.sleep() only records the delay.

    Tests move ``now`` by hand. With the clock frozen, every paced request sleeps exactly until
    the slot the budget gave it.
    """

    def __init__(self):
        self.now = 1_000.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    async def sleep(self, delay):
        self.sleeps.append(delay)
        await _real_sleep(0)


@pytest.fixture
def clock():
    fake = FakeClock()
    with patch("services.rpc_guard.asyncio.sleep", fake.sleep):
        yield fake


def guard_on(clock, rate=RPC_BUDGET_RPS):
    return RpcGuard("Robinhood Chain", rate=rate, clock=clock.monotonic)


def open_guard(guard):
    for _ in range(BREAKER_FAILURE_THRESHOLD):
        guard.record_failure("HTTP 429")
    assert guard.state == OPEN


# --- budget ---


@pytest.mark.asyncio
async def test_a_burst_is_spread_at_the_budget_rate(clock):
    guard = guard_on(clock)
    costs = [18 if index % 10 == 0 else 1 for index in range(40)]

    await asyncio.gather(*(guard.acquire(cost) for cost in costs))

    # The first request goes at once; every later one waits for its own slot.
    starts = [clock.now] + [clock.now + delay for delay in clock.sleeps]
    assert len(starts) == len(costs)
    for index in range(len(costs) - 1):
        assert starts[index + 1] - starts[index] == pytest.approx(costs[index] / RPC_BUDGET_RPS)
    # So over any window the requests started never exceed rate * window plus one reservation.
    for first in range(len(starts)):
        for last in range(first, len(starts)):
            assert sum(costs[first:last]) <= RPC_BUDGET_RPS * (starts[last] - starts[first]) + 1e-9


@pytest.mark.asyncio
async def test_an_idle_budget_grants_at_once_and_a_reservation_delays_the_next_request(clock):
    guard = guard_on(clock, rate=2.0)

    await guard.acquire(18)
    assert clock.sleeps == []
    await guard.acquire(1)

    assert clock.sleeps == [9.0]
    clock.now += 100
    await guard.acquire(1)
    assert clock.sleeps == [9.0]


# --- breaker ---


def test_failures_below_the_threshold_do_not_open_and_a_success_resets_them(clock):
    guard = guard_on(clock)
    for _ in range(BREAKER_FAILURE_THRESHOLD - 1):
        guard.record_failure("HTTP 429")
    guard.record_success()
    for _ in range(BREAKER_FAILURE_THRESHOLD - 1):
        guard.record_failure("TimeoutError")

    assert guard.state == CLOSED
    guard.record_failure("HTTP 503")
    assert guard.state == OPEN


@pytest.mark.asyncio
async def test_an_open_breaker_refuses_work_without_waiting(clock):
    guard = guard_on(clock)
    open_guard(guard)

    with pytest.raises(BreakerOpenError):
        await guard.acquire(1)
    with pytest.raises(BreakerOpenError):
        await guard.acquire(1, probe=True)
    assert clock.sleeps == []


@pytest.mark.asyncio
async def test_work_waiting_for_budget_is_refused_if_the_breaker_opens_meanwhile(clock):
    guard = guard_on(clock)
    await guard.acquire(18)
    waiting = asyncio.ensure_future(guard.acquire(1))
    await _real_sleep(0)
    open_guard(guard)

    with pytest.raises(BreakerOpenError):
        await waiting


@pytest.mark.asyncio
async def test_open_then_half_open_probe_then_closed(clock):
    guard = guard_on(clock)
    open_guard(guard)

    clock.now += BREAKER_BASE_COOLDOWN_SECONDS - 1
    assert not guard.probe_due
    clock.now += 1
    assert guard.probe_due

    await guard.acquire(1, probe=True)
    assert guard.state == HALF_OPEN
    # Only the one probe runs while half-open.
    with pytest.raises(BreakerOpenError):
        await guard.acquire(1)
    with pytest.raises(BreakerOpenError):
        await guard.acquire(1, probe=True)

    guard.record_success()
    assert guard.state == CLOSED
    await guard.acquire(1)


@pytest.mark.asyncio
async def test_each_failed_probe_doubles_the_cooldown_up_to_the_cap(clock):
    guard = guard_on(clock)
    open_guard(guard)
    cooldowns = []
    for _ in range(7):
        cooldown = 0
        while not guard.probe_due:
            clock.now += 1
            cooldown += 1
        cooldowns.append(cooldown)
        await guard.acquire(1, probe=True)
        guard.record_failure("HTTP 429")
        assert guard.state == OPEN

    assert cooldowns == [60, 120, 240, 480, 960, 960, 960]
    assert BREAKER_BASE_COOLDOWN_SECONDS == 60 and BREAKER_MAX_COOLDOWN_SECONDS == 960

    while not guard.probe_due:
        clock.now += 1
    await guard.acquire(1, probe=True)
    guard.record_success()
    open_guard(guard)
    clock.now += BREAKER_BASE_COOLDOWN_SECONDS
    assert guard.probe_due


def test_outcomes_of_requests_already_in_flight_do_not_move_an_open_breaker(clock):
    guard = guard_on(clock)
    open_guard(guard)

    guard.record_success()
    guard.record_failure("HTTP 429")

    assert guard.state == OPEN
    clock.now += BREAKER_BASE_COOLDOWN_SECONDS
    assert guard.probe_due


@pytest.mark.asyncio
async def test_only_state_changes_are_logged_with_class_only_causes(clock, caplog):
    guard = guard_on(clock)
    with caplog.at_level(logging.DEBUG, logger="services.rpc_guard"):
        guard.record_success()
        for cause in ("HTTP 429", "TimeoutError", "ClientConnectorError"):
            guard.record_failure(cause)
        guard.record_failure("HTTP 429")
        clock.now += BREAKER_BASE_COOLDOWN_SECONDS
        await guard.acquire(1, probe=True)
        guard.record_success()
        guard.record_success()

    assert [record.getMessage() for record in caplog.records] == [
        "Robinhood Chain RPC breaker closed -> open (ClientConnectorError); cooldown 60 s",
        "Robinhood Chain RPC breaker open -> half_open (probe); cooldown 60 s",
        "Robinhood Chain RPC breaker half_open -> closed (probe succeeded); cooldown 60 s",
    ]


@pytest.mark.parametrize("status,failure", [
    (200, False), (400, False), (404, False), (429, True), (500, True), (502, True), (503, True), (504, True),
])
def test_throttling_and_server_errors_are_failures(status, failure):
    assert is_failure_status(status) is failure
