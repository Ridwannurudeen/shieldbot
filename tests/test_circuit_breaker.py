"""The shared circuit breaker for external data providers (core/circuit_breaker.py)."""

import asyncio
import json
from unittest.mock import MagicMock

import aiohttp
import pytest

from core.circuit_breaker import (
    CLOSED,
    FAILURE_THRESHOLD,
    HALF_OPEN,
    OPEN,
    OPEN_SECONDS,
    CircuitOpenError,
    ProviderBreakers,
)


class FakeClock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def breakers(clock):
    return ProviderBreakers(clock=clock)


def fail(breakers, times=FAILURE_THRESHOLD, provider="dexscreener", chain_id=None):
    for _ in range(times):
        breakers.check(provider, chain_id)
        breakers.record_error(provider, chain_id, asyncio.TimeoutError())


def test_it_opens_after_the_threshold_of_failed_lookups_in_a_row(breakers):
    fail(breakers, FAILURE_THRESHOLD - 1)
    breakers.check("dexscreener")
    assert breakers.states() == {"dexscreener": CLOSED}

    breakers.record_status("dexscreener", None, 503)
    assert breakers.states() == {"dexscreener": OPEN}
    with pytest.raises(CircuitOpenError):
        breakers.check("dexscreener")


def test_an_answer_ends_the_run_of_failures(breakers):
    fail(breakers, FAILURE_THRESHOLD - 1)
    breakers.record_status("dexscreener", None, 200)
    fail(breakers, FAILURE_THRESHOLD - 1)
    breakers.check("dexscreener")
    assert breakers.states() == {"dexscreener": CLOSED}


@pytest.mark.parametrize("status", [200, 204, 400, 401, 403, 404])
def test_a_reply_that_is_not_429_or_5xx_is_an_answer(breakers, status):
    fail(breakers, FAILURE_THRESHOLD - 1)
    breakers.record_status("dexscreener", None, status)
    fail(breakers, FAILURE_THRESHOLD - 1)
    assert breakers.states() == {"dexscreener": CLOSED}


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_throttling_and_server_errors_are_failures(breakers, status):
    for _ in range(FAILURE_THRESHOLD):
        breakers.record_status("dexscreener", None, status)
    assert breakers.states() == {"dexscreener": OPEN}


@pytest.mark.parametrize(
    "error",
    [
        asyncio.TimeoutError(),
        aiohttp.ClientConnectionError(),
        aiohttp.ServerDisconnectedError(),
        json.JSONDecodeError("Expecting value", "<html>", 0),
        aiohttp.ContentTypeError(MagicMock(), (), message="unexpected mimetype: text/html"),
    ],
)
def test_timeouts_connection_errors_and_unreadable_replies_are_failures(breakers, error):
    for _ in range(FAILURE_THRESHOLD):
        breakers.record_error("dexscreener", None, error)
    assert breakers.states() == {"dexscreener": OPEN}


@pytest.mark.parametrize(
    "error",
    [
        CircuitOpenError("open"),
        KeyError("result"),
        RuntimeError("bug"),
        # Raised by the caller's own parsing of a reply that was read, such as float("n/a").
        ValueError("could not convert string to float: 'n/a'"),
        TypeError("unsupported operand type(s)"),
    ],
)
def test_other_exceptions_are_not_counted(breakers, error):
    for _ in range(FAILURE_THRESHOLD):
        breakers.record_error("dexscreener", None, error)
    assert breakers.states() == {"dexscreener": CLOSED}


def test_half_open_lets_one_probe_through_and_an_answer_closes_it(breakers, clock):
    fail(breakers)
    clock.now += OPEN_SECONDS - 0.1
    with pytest.raises(CircuitOpenError):
        breakers.check("dexscreener")

    clock.now += 0.1
    breakers.check("dexscreener")
    assert breakers.states() == {"dexscreener": HALF_OPEN}
    with pytest.raises(CircuitOpenError):
        breakers.check("dexscreener")

    breakers.record_status("dexscreener", None, 200)
    assert breakers.states() == {"dexscreener": CLOSED}
    breakers.check("dexscreener")


def test_a_failed_probe_opens_it_for_another_open_period(breakers, clock):
    fail(breakers)
    clock.now += OPEN_SECONDS
    breakers.check("dexscreener")
    breakers.record_error("dexscreener", None, asyncio.TimeoutError())
    assert breakers.states() == {"dexscreener": OPEN}

    clock.now += OPEN_SECONDS - 0.1
    with pytest.raises(CircuitOpenError):
        breakers.check("dexscreener")
    clock.now += 0.1
    breakers.check("dexscreener")
    assert breakers.states() == {"dexscreener": HALF_OPEN}


def test_a_probe_that_never_reports_frees_the_slot_after_the_open_period(breakers, clock):
    # A scan cut at its deadline cancels the probe's lookup before it records anything.
    fail(breakers)
    clock.now += OPEN_SECONDS
    breakers.check("dexscreener")

    clock.now += OPEN_SECONDS - 0.1
    with pytest.raises(CircuitOpenError):
        breakers.check("dexscreener")
    clock.now += 0.1
    breakers.check("dexscreener")
    assert breakers.states() == {"dexscreener": HALF_OPEN}


def test_a_late_answer_does_not_close_an_open_breaker(breakers):
    # A request sent before the breaker opened can still come back; only the probe decides.
    fail(breakers)
    breakers.record_status("dexscreener", None, 200)
    assert breakers.states() == {"dexscreener": OPEN}


def test_each_provider_and_chain_has_its_own_breaker(breakers):
    fail(breakers, provider="goplus_token", chain_id=56)
    with pytest.raises(CircuitOpenError):
        breakers.check("goplus_token", 56)
    breakers.check("goplus_token", 1)
    breakers.check("honeypot.is", 56)
    breakers.check("goplus_phishing")
    assert breakers.states() == {
        "goplus_token:56": OPEN,
        "goplus_token:1": CLOSED,
        "honeypot.is:56": CLOSED,
        "goplus_phishing": CLOSED,
    }


def test_a_chain_outside_the_registered_chains_never_gets_a_breaker(breakers):
    for chain_id in range(10_000, 10_500):
        for _ in range(FAILURE_THRESHOLD + 1):
            breakers.check("goplus_token", chain_id)
            breakers.record_error("goplus_token", chain_id, asyncio.TimeoutError())
            breakers.record_status("goplus_token", chain_id, 503)
    assert breakers.states() == {}
