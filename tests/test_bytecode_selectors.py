"""Bytecode selector tables: every selector must be the keccak of the function it is labelled as."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_utils import keccak

from analyzers.structural import StructuralAnalyzer
from core.risk_engine import RiskEngine
from scanner.transaction_scanner import SUSPICIOUS_SIGNATURES, TransactionScanner
from services.contract_service import BYTECODE_PATTERNS, ContractService

# The function each table entry stands for, hashed below rather than trusted.
SIGNATURES = {
    "40c10f19": "mint(address,uint256)",
    "a0712d68": "mint(uint256)",
    "8456cb59": "pause()",
    "3f4ba83a": "unpause()",
    "44337ea1": "addToBlacklist(address)",
    "3659cfe6": "upgradeTo(address)",
    "4f1ef286": "upgradeToAndCall(address,bytes)",
    "83197ef0": "destroy()",
    "a9059cbb": "transfer(address,uint256)",
    "f2fde38b": "transferOwnership(address)",
    "715018a6": "renounceOwnership()",
    "fe575a87": "isBlacklisted(address)",
    "e47d6060": "isBlackListed(address)",
    "42966c68": "burn(uint256)",
    "79cc6790": "burnFrom(address,uint256)",
    "5c60da1b": "implementation()",
}

# Getters that say nothing about danger, once labelled backdoor and selfdestruct.
BENIGN_GETTERS = {"1694505e": "uniswapV2Router()", "7a9e5410": "versionMinor()"}

# contract_service label -> the word its hashed signature must contain.
LABEL_WORDS = {
    "mint": "mint",
    "pause": "pause",
    "blacklist": "blacklist",
    "proxy_upgrade": "upgrade",
    "destroy": "destroy",
}

HONEYPOT_FIELDS = ("is_honeypot", "buy_tax", "sell_tax", "can_buy", "can_sell")


def test_selector_hashes_match_their_signatures():
    for selector, signature in {**SIGNATURES, **BENIGN_GETTERS}.items():
        assert keccak(text=signature)[:4].hex() == selector, signature


@pytest.mark.parametrize("table", [BYTECODE_PATTERNS, SUSPICIOUS_SIGNATURES])
def test_every_table_selector_is_a_hashed_signature(table):
    assert set(table) <= set(SIGNATURES)
    assert not set(table) & set(BENIGN_GETTERS)


@pytest.mark.parametrize("table", [BYTECODE_PATTERNS, SUSPICIOUS_SIGNATURES])
def test_every_table_selector_is_pushed_with_push4(table):
    # solc pushes a selector with a leading zero byte with PUSH3 or smaller, which the scan never reads.
    assert not [selector for selector in table if selector.startswith("00")]


def test_contract_service_labels_name_the_hashed_function():
    for selector, label in BYTECODE_PATTERNS.items():
        assert LABEL_WORDS[label] in SIGNATURES[selector].lower(), (selector, label)


def test_transaction_scanner_labels_name_the_hashed_function():
    assert "destroy()" in SUSPICIOUS_SIGNATURES["83197ef0"]["warning"]
    assert "isBlacklisted(address)" in SUSPICIOUS_SIGNATURES["fe575a87"]["warning"]
    assert "isBlackListed(address)" in SUSPICIOUS_SIGNATURES["e47d6060"]["warning"]
    assert SUSPICIOUS_SIGNATURES["fe575a87"]["severity"] == "info"
    assert SUSPICIOUS_SIGNATURES["e47d6060"]["severity"] == "info"


def test_benign_getters_raise_no_legacy_warning():
    bytecode = "60806040" + "".join("63" + selector for selector in BENIGN_GETTERS)
    assert TransactionScanner(MagicMock())._detect_suspicious_patterns(bytecode) == []


async def _contract_data(*selectors, bytecode=None):
    web3_client = MagicMock()
    web3_client.is_contract = AsyncMock(return_value=True)
    web3_client.is_verified_contract = AsyncMock(return_value=(True, "contract Token {}"))
    web3_client.get_contract_creation_info = AsyncMock(return_value={"age_days": 730})
    web3_client.get_ownership_info = AsyncMock(
        return_value={"owner": "0x" + "1" * 40, "is_renounced": False}
    )
    web3_client.get_bytecode = AsyncMock(
        return_value=bytecode or "0x60806040" + "".join("63" + selector for selector in selectors)
    )
    scam_db = MagicMock()
    scam_db.check_address = AsyncMock(return_value=[])
    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        return await ContractService(web3_client, scam_db).fetch_contract_data("0x" + "ab" * 20)


@pytest.mark.asyncio
async def test_benign_getters_set_no_flags():
    data = await _contract_data(*BENIGN_GETTERS)
    assert data["bytecode_warnings"] == []
    assert data["has_proxy"] is False


@pytest.mark.asyncio
async def test_destroy_is_not_a_proxy_and_cannot_force_block_on_an_established_token():
    contract = await _contract_data("83197ef0", "40c10f19")
    assert contract["has_proxy"] is False
    assert contract["has_mint"] is True
    assert contract["bytecode_warnings"] == ["mint", "destroy"]
    honeypot = {
        "is_honeypot": False,
        "buy_tax": 1.0,
        "sell_tax": 1.0,
        "can_buy": True,
        "can_sell": True,
        "status": "ok",
        "coverage": {field: True for field in HONEYPOT_FIELDS},
    }
    market = {
        "liquidity_usd": 3_000_000,
        "pair_age_hours": 17_000,
        "fdv": 20_000_000,
        "volume_24h": 400_000,
    }
    risk = RiskEngine().compute_composite_risk(contract, honeypot, market, {"reputation_score": 80})
    assert risk["rug_probability"] < 85
    assert risk["risk_level"] != "HIGH"
    assert "Proxy/upgradeable contract" not in risk["critical_flags"]


@pytest.mark.asyncio
async def test_real_upgrade_selector_still_sets_proxy():
    data = await _contract_data("3659cfe6")
    assert data["has_proxy"] is True
    assert data["bytecode_warnings"] == ["proxy_upgrade"]


@pytest.mark.asyncio
async def test_destroy_sets_its_own_flag():
    assert (await _contract_data("83197ef0"))["has_destroy"] is True
    assert (await _contract_data("40c10f19"))["has_destroy"] is False


@pytest.mark.parametrize(
    "renounced,points",
    [(False, 15), (None, 15), (True, 0)],
)
def test_destroy_scores_as_an_owner_power_unless_ownership_is_renounced(renounced, points):
    analyzer = StructuralAnalyzer(MagicMock())
    base = {"is_contract": True, "is_verified": True, "contract_age_days": 400}
    without, _ = analyzer._compute({**base, "ownership_renounced": renounced}, {})
    score, flags = analyzer._compute(
        {**base, "ownership_renounced": renounced, "has_destroy": True}, {}
    )
    assert score - without == points
    assert ("destroy() function: the owner may be able to delete the contract" in flags) is (
        points > 0
    )


# mint(address,uint256) and upgradeTo(address) as data rather than as a dispatcher's PUSH4 operand:
# inside a PUSH32 constant (twice, the second time as a PUSH4 opcode and operand inside it), after a
# byte other than 0x63, and off a byte boundary (0x06 0x36 ...).
SELECTORS_AS_DATA = [
    "0x60806040" + "7f" + "00" * 28 + "40c10f19",
    "0x60806040" + "7f" + "00" * 27 + "63" + "40c10f19",
    "0x60806040" + "60" + "40c10f19" + "3659cfe6",
    "0x60806040" + "0" + "63" + "40c10f19" + "0",
    "0x60806040" + "0" + "63" + "3659cfe6" + "0",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("bytecode", SELECTORS_AS_DATA)
async def test_selector_bytes_outside_a_push4_raise_no_flag(bytecode):
    data = await _contract_data(bytecode=bytecode)
    assert data["bytecode_warnings"] == []
    assert data["has_mint"] is False and data["has_proxy"] is False


@pytest.mark.parametrize("bytecode", SELECTORS_AS_DATA)
def test_selector_bytes_outside_a_push4_raise_no_legacy_warning(bytecode):
    assert TransactionScanner(MagicMock())._detect_suspicious_patterns(bytecode) == []


@pytest.mark.parametrize("prefix", ["0x", ""])
def test_a_push4_selector_is_found_with_or_without_the_hex_prefix(prefix):
    warnings = TransactionScanner(MagicMock())._detect_suspicious_patterns(
        prefix + "6080604063" + "40c10f19"
    )
    assert warnings == [SUSPICIOUS_SIGNATURES["40c10f19"]["warning"]]
