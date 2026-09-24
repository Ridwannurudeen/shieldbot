"""MetaMask's open phishing list as a second phishing source beside GoPlus.

tests/fixtures/metamask_phishing_config.json holds entries of
https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json exactly as served on
2026-09-24 (version 2, tolerance 1): its whole fuzzylist and a subset of its whitelist and blacklist,
including one entry with a path. No test touches the network.
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


def _serve(payload=None, status=200, error=None):
    """Patch aiohttp so every GET answers `payload` with `status`, or raises `error`."""
    response = MagicMock(status=status)
    response.json = AsyncMock(return_value=payload)
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
    await service.start()
    for _ in range(20):
        await asyncio.sleep(0)
    # The failed fetch is retried at once (retry delay 0 here); the good one waits an hour.
    assert service.metamask.refresh.await_count == 2
    await service.stop()
    assert service._refresh_task is None
    await service.stop()
