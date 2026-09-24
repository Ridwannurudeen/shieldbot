"""A phishing check that gets no answer is "no verdict" (is_phishing None), never "not phishing"."""

import asyncio
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from fastapi.testclient import TestClient

from core.circuit_breaker import FAILURE_THRESHOLD
from services.phishing_service import PhishingService

URL = "https://example.com/swap"


def _goplus(payload=None, status=200, error=None):
    """Patch aiohttp so the GoPlus phishing endpoint answers `payload` with `status`, or raises."""
    response = MagicMock(status=status)
    response.json = AsyncMock(return_value=payload)
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    session.get.side_effect = error
    client = patch("services.phishing_service.aiohttp.ClientSession")
    started = client.start()
    started.return_value.__aenter__ = AsyncMock(return_value=session)
    return client, session


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload,status,error,reason",
    [
        ({}, 503, None, "GoPlus HTTP 503"),
        (
            None,
            200,
            aiohttp.ClientConnectionError(),
            "GoPlus request failed (ClientConnectionError)",
        ),
        (None, 200, asyncio.TimeoutError(), "Phishing check failed (TimeoutError)"),
        (
            {"code": 4029, "message": "limit", "result": None},
            200,
            None,
            "GoPlus returned no phishing verdict",
        ),
        (
            {"code": 1, "message": "OK", "result": {}},
            200,
            None,
            "GoPlus returned no phishing verdict",
        ),
        (
            {"code": 1, "result": {"phishing_site": "maybe"}},
            200,
            None,
            "GoPlus returned no phishing verdict",
        ),
        ([], 200, None, "GoPlus returned no phishing verdict"),
    ],
)
async def test_no_answer_is_no_verdict_held_for_45_seconds(payload, status, error, reason):
    client, session = _goplus(payload, status, error)
    clock = [1000.0]
    try:
        with patch("services.phishing_service.time.time", side_effect=lambda: clock[0]):
            service = PhishingService()
            first = await service.check_url(URL)
            clock[0] += 44
            held = await service.check_url("https://example.com/other-page")
            clock[0] += 2
            asked_again = await service.check_url(URL)
    finally:
        client.stop()
    assert first == {
        "is_phishing": None,
        "confidence": None,
        "source": None,
        "cached": False,
        "reason": reason,
    }
    assert held == {**first, "cached": True}
    assert asked_again == first
    assert session.get.call_count == 2


@pytest.mark.asyncio
async def test_an_outage_cannot_grow_the_cache_past_its_bound():
    client, session = _goplus({}, 503)
    try:
        with patch("services.phishing_service.CACHE_MAXSIZE", 5):
            service = PhishingService()
        for index in range(12):
            result = await service.check_url(f"https://site{index}.example/")
            assert result["is_phishing"] is None
    finally:
        client.stop()
    assert len(service._cache) == 5
    # The breaker stops asking after the first failures in a row; every domain still gets its answer.
    assert session.get.call_count == FAILURE_THRESHOLD


@pytest.mark.asyncio
@pytest.mark.parametrize("raw,verdict", [(0, False), (1, True), ("0", False), ("1", True)])
async def test_goplus_answers_are_verdicts_and_are_cached(raw, verdict):
    client, session = _goplus({"code": 1, "message": "OK", "result": {"phishing_site": raw}})
    try:
        service = PhishingService()
        first = await service.check_url(URL)
        second = await service.check_url(URL)
    finally:
        client.stop()
    assert first == {
        "is_phishing": verdict,
        "confidence": "high" if verdict else "low",
        "source": "goplus",
        "cached": False,
    }
    assert second == {**first, "cached": True}
    assert session.get.call_count == 1


def test_api_passes_no_verdict_through():
    import api as api_module

    phishing_service = SimpleNamespace(
        check_url=AsyncMock(
            return_value={
                "is_phishing": None,
                "confidence": None,
                "source": None,
                "cached": False,
                "reason": "GoPlus HTTP 503",
            }
        )
    )
    with patch.object(api_module, "container", SimpleNamespace(phishing_service=phishing_service)):
        response = TestClient(api_module.app).get("/api/phishing", params={"url": URL})
    assert response.status_code == 200
    assert response.json()["is_phishing"] is None


def _run_background(script, argument):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for extension JavaScript regression tests")
    result = subprocess.run(
        [node, "-e", script, "--", json.dumps(argument)],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "completed" in result.stdout, "JavaScript assertions did not finish"


BACKGROUND = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const scenario = JSON.parse(process.argv[1]);
let fetches = 0;
const context = vm.createContext({
  chrome: {
    runtime: {onInstalled: {addListener() {}}, onMessage: {addListener() {}}},
    storage: {local: {get(defaults, cb) {cb(defaults);}}},
  },
  URL, AbortSignal, console: {warn() {}},
  fetch: async () => {
    fetches++;
    if (scenario === 'network-error') throw new Error('offline');
    if (scenario === 'http-error') return {ok: false, status: 503};
    return {ok: true, json: async () => ({is_phishing: scenario === 'unknown' ? null : false, source: 'goplus'})};
  },
});
vm.runInContext(fs.readFileSync('extension/background.js', 'utf8'), context);
(async () => {
  const first = await context.checkPhishing('https://example.com/swap');
  const second = await context.checkPhishing('https://example.com/other');
  if (scenario === 'safe') {
    assert.equal(first.is_phishing, false);
    assert.equal(fetches, 1);
  } else {
    assert.equal(first.is_phishing, null);
    assert.equal(second.is_phishing, null);
    assert.equal(fetches, 2);
  }
})().then(() => console.log('completed')).catch(error => {console.error(error); process.exitCode = 1;});
"""


@pytest.mark.parametrize("scenario", ["unknown", "network-error", "http-error", "safe"])
def test_extension_treats_no_verdict_as_no_verdict_and_does_not_cache_it(scenario):
    _run_background(BACKGROUND, scenario)
