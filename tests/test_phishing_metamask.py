"""MetaMask's open phishing list as a second phishing source beside GoPlus.

tests/fixtures/metamask_phishing_config.json holds entries of
https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json exactly as served on
2026-09-24 (version 2, tolerance 1): its whole fuzzylist and a subset of its whitelist and blacklist,
including one entry with a path and one internationalised (xn--) domain. No test touches the network.
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

import services.phishing_service as phishing_service
from services.phishing_service import (
    METAMASK_CONFIG_URL,
    MetaMaskPhishingList,
    PhishingService,
)

RECORDED = json.loads(
    (Path(__file__).parent / "fixtures" / "metamask_phishing_config.json").read_text(
        encoding="utf-8"
    )
)
LISTED = {"type": "blocklist", "domain": "poly-mark.xyz"}


async def _chunks(body, size):
    for start in range(0, len(body), size):
        yield body[start : start + size]


def _serve(payload=None, status=200, error=None, body=None):
    """Patch aiohttp so every GET answers `payload` (or the raw `body`) with `status`, or raises `error`."""
    response = MagicMock(status=status)
    response.json = AsyncMock(return_value=payload)
    raw = json.dumps(payload).encode("utf-8") if body is None else body
    response.content.iter_chunked = lambda size: _chunks(raw, size)
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    session.get.side_effect = error
    client = patch("services.phishing_service.aiohttp.ClientSession")
    started = client.start()
    started.return_value.__aenter__ = AsyncMock(return_value=session)
    return client, session


async def loaded_list(payload=RECORDED):
    metamask = MetaMaskPhishingList()
    client, session = _serve(payload)
    try:
        assert await metamask.refresh()
    finally:
        client.stop()
    assert session.get.call_args.args[0] == METAMASK_CONFIG_URL
    return metamask


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "host,expected",
    [
        ("poly-mark.xyz", LISTED),
        ("POLY-MARK.XYZ.", LISTED),
        ("claim.opensea.support", {"type": "blocklist", "domain": "opensea.support"}),
        ("www.opensea.uno", {"type": "blocklist", "domain": "www.opensea.uno"}),
        # The list holds internationalised names in their ASCII form; a Unicode host is encoded first.
        ("xn--phntom-jta.com", {"type": "blocklist", "domain": "xn--phntom-jta.com"}),
        ("ph\u00e0ntom.com", {"type": "blocklist", "domain": "xn--phntom-jta.com"}),
        ("PH\u00c0NTOM.COM", {"type": "blocklist", "domain": "xn--phntom-jta.com"}),
        ("app.ph\u00e0ntom.com", {"type": "blocklist", "domain": "xn--phntom-jta.com"}),
        # Not a valid IDNA name: matched as given, never an error.
        ("poly_mark.xyz", None),
        # Lookalikes: one edit from a fuzzylist domain's name, after dropping the TLD and a leading www.
        ("metamusk.io", {"type": "fuzzy", "domain": "metamask.io"}),
        ("www.etherscam.io", {"type": "fuzzy", "domain": "etherscan.io"}),
        ("opensea.uno", {"type": "fuzzy", "domain": "opensea.io"}),
        # Whitelisted domains and their subdomains never match, lookalike or not.
        ("metamask.io", None),
        ("portfolio.metamask.io", None),
        ("etherscan.com", None),
        ("relay.walletconnect.org", None),
        ("localhost", None),
        # Only whole labels match, and a listed page does not list its host.
        ("notpoly-mark.xyz", None),
        ("poly-mark.xyz.example.com", None),
        ("sites.google.com", None),
        ("uniswap.org", None),
    ],
)
async def test_hosts_match_the_way_metamask_matches_them(host, expected):
    metamask = await loaded_list()
    assert metamask.match(host) == expected


@pytest.mark.asyncio
async def test_a_zero_tolerance_turns_off_lookalike_matching():
    metamask = await loaded_list({**RECORDED, "tolerance": 0})
    assert metamask.match("metamusk.io") is None
    assert metamask.match("poly-mark.xyz") == LISTED


def test_nothing_matches_before_the_list_is_loaded():
    assert MetaMaskPhishingList().match("poly-mark.xyz") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload,status,error",
    [
        (None, 503, None),
        (None, 200, aiohttp.ClientConnectionError()),
        (None, 200, asyncio.TimeoutError()),
        ("<html>", 200, None),
        ({**RECORDED, "version": 3}, 200, None),
        ({**RECORDED, "tolerance": "1"}, 200, None),
        ({**RECORDED, "tolerance": True}, 200, None),
        ({**RECORDED, "blacklist": []}, 200, None),
        ({**RECORDED, "blacklist": "poly-mark.xyz"}, 200, None),
        ({**RECORDED, "whitelist": [1]}, 200, None),
        ({key: value for key, value in RECORDED.items() if key != "fuzzylist"}, 200, None),
    ],
)
async def test_a_failed_refresh_keeps_the_last_good_copy(payload, status, error, caplog):
    metamask = await loaded_list()
    client, _ = _serve(payload, status, error)
    try:
        assert not await metamask.refresh()
    finally:
        client.stop()
    assert metamask.match("poly-mark.xyz") == LISTED
    assert "keeping the last good copy" in caplog.text


@pytest.mark.asyncio
async def test_a_refused_status_is_logged_with_its_number(caplog):
    metamask = await loaded_list()
    client, _ = _serve(None, 429)
    try:
        assert not await metamask.refresh()
    finally:
        client.stop()
    record = next(r for r in caplog.records if "not refreshed" in r.getMessage())
    assert record.args[0] == 429
    assert "HTTP 429" in record.getMessage()
    assert metamask.match("poly-mark.xyz") == LISTED


@pytest.mark.asyncio
async def test_a_body_over_the_cap_is_refused_and_the_last_good_copy_kept(monkeypatch, caplog):
    metamask = await loaded_list()
    body = json.dumps({**RECORDED, "blacklist": ["other.example"]}).encode("utf-8")
    monkeypatch.setattr(phishing_service, "METAMASK_MAX_BYTES", len(body) - 1)
    client, _ = _serve(body=body)
    try:
        assert not await metamask.refresh()
    finally:
        client.stop()
    assert f"larger than {len(body) - 1} bytes" in caplog.text
    assert metamask.match("poly-mark.xyz") == LISTED
    assert metamask.match("other.example") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [b"", b"<html>not json</html>", b'{"version": 2'])
async def test_a_body_that_is_not_json_keeps_the_last_good_copy(body, caplog):
    metamask = await loaded_list()
    client, _ = _serve(body=body)
    try:
        assert not await metamask.refresh()
    finally:
        client.stop()
    assert metamask.match("poly-mark.xyz") == LISTED
    assert "keeping the last good copy" in caplog.text


@pytest.mark.asyncio
async def test_the_list_is_parsed_off_the_event_loop(monkeypatch):
    threaded = []
    real_to_thread = asyncio.to_thread

    async def to_thread(function, *args):
        threaded.append(function)
        return await real_to_thread(function, *args)

    monkeypatch.setattr(phishing_service.asyncio, "to_thread", to_thread)
    await loaded_list()
    assert threaded == [phishing_service._parse_metamask_body]


@pytest.mark.asyncio
async def test_a_failed_first_fetch_leaves_the_list_silent(caplog):
    metamask = MetaMaskPhishingList()
    client, _ = _serve(None, 503)
    try:
        assert not await metamask.refresh()
    finally:
        client.stop()
    assert metamask.match("poly-mark.xyz") is None
    assert "no copy loaded yet" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url,match",
    [
        (
            "https://claim.opensea.support/mint?id=1",
            {"type": "blocklist", "domain": "opensea.support"},
        ),
        ("https://metamask.io@poly-mark.xyz:8443/", LISTED),
        ("https://metamusk.io/", {"type": "fuzzy", "domain": "metamask.io"}),
    ],
)
async def test_a_listed_host_is_phishing_even_when_goplus_has_no_verdict(url, match):
    service = PhishingService()
    service.metamask = await loaded_list()
    client, session = _serve({}, 503)
    try:
        result = await service.check_url(url)
    finally:
        client.stop()
    assert result == {
        "is_phishing": True,
        "confidence": "high",
        "source": "metamask",
        "cached": False,
        "match": match,
    }
    session.get.assert_not_called()


@pytest.mark.asyncio
async def test_the_list_overrides_an_earlier_goplus_answer():
    service = PhishingService()
    client, _ = _serve({"code": 1, "message": "OK", "result": {"phishing_site": 0}})
    try:
        before = await service.check_url("https://poly-mark.xyz/")
    finally:
        client.stop()
    assert (before["is_phishing"], before["source"]) == (False, "goplus")
    service.metamask = await loaded_list()
    after = await service.check_url("https://poly-mark.xyz/")
    assert (after["is_phishing"], after["source"], after["match"]) == (True, "metamask", LISTED)


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["example.com", "metamask.io"])
async def test_when_both_sources_are_silent_there_is_no_verdict(host):
    service = PhishingService()
    service.metamask = await loaded_list()
    client, _ = _serve({}, 503)
    try:
        result = await service.check_url(f"https://{host}/")
    finally:
        client.stop()
    assert result == {
        "is_phishing": None,
        "confidence": None,
        "source": None,
        "cached": False,
        "reason": "GoPlus HTTP 503",
    }


@pytest.mark.asyncio
async def test_goplus_still_decides_a_host_the_list_does_not_flag():
    service = PhishingService()
    service.metamask = await loaded_list()
    client, _ = _serve({"code": 1, "message": "OK", "result": {"phishing_site": 1}})
    try:
        result = await service.check_url("https://metamask.io/")
    finally:
        client.stop()
    assert (result["is_phishing"], result["source"]) == (True, "goplus")


@pytest.mark.asyncio
async def test_the_list_is_fetched_at_start_hourly_and_sooner_after_a_failure(monkeypatch):
    assert phishing_service.METAMASK_REFRESH_SECONDS == 3600
    monkeypatch.setattr(phishing_service, "METAMASK_RETRY_SECONDS", 0)
    service = PhishingService()
    service.metamask.refresh = AsyncMock(side_effect=[False, True, True])
    service.start()
    for _ in range(20):
        await asyncio.sleep(0)
    # The failed fetch is retried at once (retry delay 0 here); the good one waits an hour.
    assert service.metamask.refresh.await_count == 2
    await service.stop()
    assert service._refresh_task is None
    await service.stop()
