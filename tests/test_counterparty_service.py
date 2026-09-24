"""Counterparty facts: wallet or contract, verification, age and GoPlus address labels."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cachetools import TLRUCache

import services.counterparty_service as counterparty_module
import utils.scam_db as scam_module
from services.counterparty_service import (
    PERMIT2,
    CounterpartyService,
    UnavailableCounterparty,
    judge_spender,
    unknown_facts,
)
from utils.scam_db import ScamDatabase

SPENDER = "0x" + "5" * 40
ROUTER = "0x10ed43c718714eb63d5aa57b78b54704e256024e"
CLEAN = {"phishing_activities": "0", "blacklist_doubt": "0", "data_source": "", "gas_abuse": "0"}
# Recorded 2026-09-24 for the Inferno Drainer fee address 0x0000db5c...0000.
DRAINER = {
    "phishing_activities": "1",
    "blacklist_doubt": "1",
    "stealing_attack": "0",
    "number_of_malicious_contracts_created": "0",
    "gas_abuse": "0",
    "data_source": "SlowMist,GoPlus",
}


@pytest.fixture(autouse=True)
def caches():
    counterparty_module._FACTS_CACHE.clear()
    scam_module._GOPLUS_ADDRESS_CACHE.clear()
    yield
    counterparty_module._FACTS_CACHE.clear()
    scam_module._GOPLUS_ADDRESS_CACHE.clear()


def _service(code="0x6080", verified=True, age=400, labels=None, goplus=None):
    adapter = SimpleNamespace(get_whitelisted_routers=lambda: {ROUTER: "PancakeSwap V2 Router"})
    web3 = SimpleNamespace(
        _get_adapter=MagicMock(return_value=adapter),
        get_bytecode=AsyncMock(return_value=code),
        is_verified_contract=AsyncMock(return_value=(verified, None)),
        get_contract_creation_info=AsyncMock(
            return_value=None if age is None else {"age_days": age}
        ),
    )
    security = goplus or {"status": "ok", "reason": None, "data": labels or CLEAN}
    scam_db = SimpleNamespace(fetch_address_security=AsyncMock(return_value=security))
    return CounterpartyService(web3, scam_db), web3, scam_db


def _calls(web3, scam_db):
    return (
        web3.get_bytecode.await_count
        + web3.is_verified_contract.await_count
        + web3.get_contract_creation_info.await_count
        + scam_db.fetch_address_security.await_count
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address, name",
    [(ROUTER, "PancakeSwap V2 Router"), (PERMIT2.upper().replace("0X", "0x"), "Permit2")],
)
async def test_allowlisted_spender_needs_no_lookup(address, name):
    service, web3, scam_db = _service()
    assert service.allowlisted_name(address, 56) == name
    facts = await service.fetch(address, 56)
    assert facts["allowlisted"] == name
    assert all(facts["coverage"].values())
    assert facts["reason"] is None
    assert _calls(web3, scam_db) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["", "0x"], ids=["web3-7", "web3-6"])
async def test_empty_code_is_a_fully_covered_wallet(code):
    service, _, _ = _service(code=code, verified=None, age=None)
    facts = await service.fetch(SPENDER, 56)
    assert facts["is_contract"] is False
    assert facts["delegated"] is False
    assert facts["is_verified"] is None
    assert facts["age_days"] is None
    assert facts["labels"] == []
    assert all(facts["coverage"].values())
    assert facts["reason"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("prefix", ["", "0x"], ids=["web3-7", "web3-6"])
async def test_eip7702_delegation_is_a_wallet(prefix):
    # vitalik.eth's code on 2026-09-24: the delegation designator and a 20-byte delegate.
    code = prefix + "ef0100" + "5a7fc11397e9a8ad41bf10bf13f22b0a63f96f6d"
    service, _, _ = _service(code=code, verified=False, age=None)
    facts = await service.fetch(SPENDER, 1)
    assert facts["is_contract"] is True
    assert facts["delegated"] is True
    assert facts["is_verified"] is None
    assert all(facts["coverage"].values())


@pytest.mark.asyncio
async def test_contract_facts():
    service, _, _ = _service(code="0x6080604052", verified=False, age=2)
    facts = await service.fetch(SPENDER, 56)
    assert (facts["is_contract"], facts["delegated"]) == (True, False)
    assert (facts["is_verified"], facts["age_days"]) == (False, 2)
    assert all(facts["coverage"].values())


@pytest.mark.asyncio
async def test_goplus_theft_labels_are_read_and_others_ignored():
    record = {
        **DRAINER,
        "number_of_malicious_contracts_created": "2",
        "contract_address": "1",
        "gas_abuse": "1",
        "fake_kyc": "1",
    }
    service, _, _ = _service(labels=record)
    facts = await service.fetch(SPENDER, 56)
    assert facts["labels"] == [
        "phishing_activities",
        "blacklist_doubt",
        "number_of_malicious_contracts_created",
    ]
    assert facts["label_source"] == "SlowMist,GoPlus"
    assert facts["coverage"]["labels"] is True


LEGITIMATE_SPENDERS = json.loads(
    (Path(__file__).parent / "fixtures" / "goplus_address_security_spenders.json").read_text(encoding="utf-8")
)["probes"]


@pytest.mark.asyncio
@pytest.mark.parametrize("probe", LEGITIMATE_SPENDERS, ids=[p["name"] for p in LEGITIMATE_SPENDERS])
async def test_recorded_legitimate_spenders_carry_no_theft_label(probe):
    # Association labels (honeypot_related_address, malicious contracts created) floor at 100, so
    # the aggregators, marketplaces and routers users approve must not carry them. The record is
    # read as a non-allowlisted spender's, since Permit2 and the routers skip the lookup.
    service, _, _ = _service(labels=probe["record"])
    facts = await service.fetch(SPENDER, probe["chain_id"])
    assert facts["labels"] == []
    assert judge_spender(facts, True) == (None, None, False)


@pytest.mark.asyncio
async def test_goplus_outage_leaves_labels_unknown_with_a_class_only_reason():
    service, _, _ = _service(
        goplus={"status": "unknown", "reason": "GoPlus HTTP 429", "data": {}},
    )
    facts = await service.fetch(SPENDER, 56)
    assert facts["labels"] is None
    assert facts["coverage"] == {"code": True, "verification": True, "age": True, "labels": False}
    assert facts["reason"] == "Spender facts unknown: labels (GoPlus HTTP 429)"


@pytest.mark.asyncio
async def test_each_fact_is_decided_independently():
    service, _, _ = _service(code=None, verified=True, age=None)
    facts = await service.fetch(SPENDER, 56)
    assert facts["is_contract"] is None
    assert facts["is_verified"] is True
    assert facts["coverage"] == {"code": False, "verification": True, "age": False, "labels": True}
    assert facts["reason"] == "Spender facts unknown: code (RPC), age (explorer)"


@pytest.mark.asyncio
async def test_repeat_lookup_is_served_from_the_cache():
    service, web3, scam_db = _service()
    first = await service.fetch(SPENDER, 56)
    assert await service.fetch(SPENDER.upper().replace("0X", "0x"), 56) is first
    assert _calls(web3, scam_db) == 4
    await service.fetch(SPENDER, 8453)
    assert _calls(web3, scam_db) == 8


@pytest.mark.asyncio
async def test_concurrent_lookups_of_one_spender_share_the_providers():
    service, web3, scam_db = _service()
    first, second = await asyncio.gather(service.fetch(SPENDER, 56), service.fetch(SPENDER, 56))
    assert first is second
    assert _calls(web3, scam_db) == 4
    assert counterparty_module._FACTS_INFLIGHT == {}


@pytest.mark.asyncio
async def test_a_slow_provider_leaves_only_its_fact_unknown(monkeypatch):
    monkeypatch.setattr(counterparty_module, "PROVIDER_TIMEOUT", 0.05)

    async def hang(*args, **kwargs):
        await asyncio.sleep(60)

    service, web3, scam_db = _service(verified=False, age=30)
    web3.get_bytecode = hang
    scam_db.fetch_address_security = hang
    facts = await asyncio.wait_for(service.fetch(SPENDER, 56), 5)
    assert (facts["is_contract"], facts["labels"]) == (None, None)
    assert (facts["is_verified"], facts["age_days"]) == (False, 30)
    assert facts["reason"] == "Spender facts unknown: code (RPC), labels (GoPlus timed out)"


def _clock(monkeypatch, module, name, ttu):
    now = [0.0]
    monkeypatch.setattr(module, name, TLRUCache(maxsize=1024, ttu=ttu, timer=lambda: now[0]))
    return now


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "goplus, held",
    [
        ({"status": "ok", "reason": None, "data": CLEAN}, 300),
        ({"status": "unknown", "reason": "GoPlus HTTP 429", "data": {}}, 30),
    ],
    ids=["complete", "incomplete"],
)
async def test_complete_facts_are_held_five_minutes_and_incomplete_ones_thirty_seconds(
    monkeypatch, goplus, held
):
    assert counterparty_module._FACTS_CACHE.ttu is counterparty_module._facts_ttu
    now = _clock(monkeypatch, counterparty_module, "_FACTS_CACHE", counterparty_module._facts_ttu)
    service, web3, scam_db = _service(goplus=goplus)
    await service.fetch(SPENDER, 56)
    now[0] = held - 1
    await service.fetch(SPENDER, 56)
    assert _calls(web3, scam_db) == 4
    now[0] = held + 1
    await service.fetch(SPENDER, 56)
    assert _calls(web3, scam_db) == 8


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload, held",
    [({"code": 1, "message": "ok", "result": CLEAN}, 600), ({"code": 0, "message": "error"}, 30)],
    ids=["answered", "unknown"],
)
async def test_address_labels_are_held_ten_minutes_and_unknowns_thirty_seconds(monkeypatch, payload, held):
    assert scam_module._GOPLUS_ADDRESS_CACHE.ttu is scam_module._address_security_ttu
    now = _clock(monkeypatch, scam_module, "_GOPLUS_ADDRESS_CACHE", scam_module._address_security_ttu)
    result, session = await _address_security(payload)
    now[0] = held - 1
    assert await ScamDatabase.fetch_address_security(SPENDER) is result
    now[0] = held + 1
    _, again = await _address_security(payload)
    assert session.get.call_count == again.get.call_count == 1


def test_unknown_facts_have_no_coverage():
    facts = unknown_facts(SPENDER)
    assert not any(facts["coverage"].values())
    assert facts["reason"].startswith("Spender facts unknown")


@pytest.mark.asyncio
async def test_unavailable_counterparty_keeps_the_allowlist():
    unavailable = UnavailableCounterparty()
    assert unavailable.allowlisted_name(PERMIT2, 8453) == "Permit2"
    assert unavailable.allowlisted_name(ROUTER, 56) is None
    assert (await unavailable.fetch(SPENDER, 56))["coverage"]["code"] is False
    service, _, _ = _service()
    with_client = UnavailableCounterparty(service._web3)
    assert with_client.allowlisted_name(ROUTER, 56) == "PancakeSwap V2 Router"
    assert with_client.allowlisted_name(PERMIT2, 56) == "Permit2"


def _known(**overrides):
    return {
        **unknown_facts(SPENDER),
        "is_contract": True,
        "delegated": False,
        "is_verified": True,
        "age_days": 400,
        "labels": [],
        **overrides,
    }


WALLET_FLAG = "Approval to a wallet address, not a contract (drainer pattern)"
DELEGATED_FLAG = "Approval to an EIP-7702 delegated wallet, not a protocol contract"
LABEL_FLAG = "Spender flagged by GoPlus: phishing_activities, blacklist_doubt (SlowMist,GoPlus)"
LABELS = {"labels": ["phishing_activities", "blacklist_doubt"], "label_source": "SlowMist,GoPlus"}


@pytest.mark.parametrize(
    "facts, unlimited, expected",
    [
        # Wallets and labelled addresses never need an allowance.
        (_known(is_contract=False, is_verified=None, age_days=None), True, (100, WALLET_FLAG, False)),
        (_known(is_contract=False, is_verified=None, age_days=None), False, (100, WALLET_FLAG, False)),
        (_known(delegated=True, is_verified=None, age_days=None), False, (100, DELEGATED_FLAG, False)),
        (_known(**LABELS), False, (100, LABEL_FLAG, False)),
        # Unverified contracts.
        (_known(is_verified=False, age_days=2), False, (85, "Spender contract is unverified and 2 days old", False)),
        (_known(is_verified=False, age_days=30), True, (85, "Spender contract is unverified", False)),
        (_known(is_verified=False, age_days=30), False, (60, "Spender contract is unverified", False)),
        (_known(is_verified=False, age_days=None), True, (85, "Spender contract is unverified", False)),
        # A limited grant to an unverified contract of unknown age could still be under 7 days.
        (_known(is_verified=False, age_days=None), False, (60, "Spender contract is unverified", True)),
        # Verified contracts.
        (_known(age_days=3), True, (60, "Spender contract is 3 days old", False)),
        (_known(age_days=3), False, (None, None, False)),
        (_known(), True, (None, None, False)),
        (_known(age_days=None), True, (None, None, True)),
        (_known(age_days=None), False, (None, None, False)),
        # Unknown facts: a rule fires only on facts that are known.
        (_known(is_contract=None), True, (None, None, True)),
        (_known(is_verified=None), True, (None, None, True)),
        (_known(labels=None), False, (None, None, True)),
        (_known(is_contract=False, is_verified=None, age_days=None, labels=None), True, (100, WALLET_FLAG, True)),
        (_known(is_contract=None, **LABELS), True, (100, LABEL_FLAG, True)),
        # Code unknown, explorer answered: the verified-based tiers still fire as a lower bound (an
        # unverified address may be a wallet, which would be 100), and the verdict stays unknown.
        (_known(is_contract=None, is_verified=False, age_days=30), True, (85, "Spender contract is unverified", True)),
        (_known(is_contract=None, is_verified=False, age_days=30), False, (60, "Spender contract is unverified", True)),
        (_known(is_contract=None, is_verified=False, age_days=2), False,
         (85, "Spender contract is unverified and 2 days old", True)),
        (_known(is_contract=None, age_days=3), True, (60, "Spender contract is 3 days old", True)),
        (_known(is_contract=None, age_days=3), False, (None, None, True)),
        # A known wallet is 100 whatever the explorer said.
        (_known(is_contract=False, is_verified=False, age_days=None), False, (100, WALLET_FLAG, False)),
    ],
)
def test_judge_spender_table(facts, unlimited, expected):
    assert judge_spender(facts, unlimited) == expected


def _goplus_http(*payloads, status=200):
    responses = []
    for payload in payloads:
        response = MagicMock(status=status)
        response.json = AsyncMock(return_value=payload)
        responses.append(response)
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(side_effect=responses)
    session.get.return_value.__aexit__ = AsyncMock(return_value=False)
    factory = patch("utils.scam_db.aiohttp.ClientSession")
    return factory, session


async def _address_security(*payloads, status=200):
    factory, session = _goplus_http(*payloads, status=status)
    with factory as http, patch("utils.scam_db._GOPLUS_BACKOFF", 0):
        http.return_value.__aenter__ = AsyncMock(return_value=session)
        http.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await ScamDatabase.fetch_address_security(SPENDER)
    return result, session


@pytest.mark.asyncio
async def test_address_security_reads_the_record_without_a_chain():
    result, session = await _address_security({"code": 1, "message": "ok", "result": DRAINER})
    assert (result["status"], result["data"]) == ("ok", DRAINER)
    assert session.get.call_args.args[0] == (
        f"https://api.gopluslabs.io/api/v1/address_security/{SPENDER}"
    )
    assert await ScamDatabase.fetch_address_security(SPENDER) is result


@pytest.mark.asyncio
async def test_address_security_retries_rate_limits():
    result, session = await _address_security(
        {"code": 4029, "message": "too many requests"},
        {"code": 1, "message": "ok", "result": CLEAN},
    )
    assert result["status"] == "ok"
    assert session.get.call_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload, status, reason",
    [
        (None, 503, "GoPlus HTTP 503"),
        ({"code": 0, "message": "error"}, 200, "GoPlus returned an unsuccessful response"),
        ({"code": 1, "message": "ok", "result": {}}, 200, "GoPlus returned no address record"),
    ],
)
async def test_address_security_failures_are_unknown(payload, status, reason):
    result, _ = await _address_security(payload, status=status)
    assert (result["status"], result["reason"], result["data"]) == ("unknown", reason, {})


@pytest.mark.asyncio
async def test_address_security_rejects_an_invalid_address():
    result = await ScamDatabase.fetch_address_security("0xnot-an-address")
    assert result["status"] == "unknown"
