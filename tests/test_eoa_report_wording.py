"""Contract verification does not apply to a confirmed wallet (EOA)."""

import ast
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from core.extension_formatter import is_scan_incomplete
from core.telegram_formatter import escape_markdown, escape_markdown_lines, format_full_report
from scanner.transaction_scanner import TransactionScanner


ADDRESS = "0x" + "a" * 40


@pytest.fixture
def format_scan_result():
    # Load the real formatter without importing the optional Telegram package.
    tree = ast.parse((Path(__file__).resolve().parents[1] / "bot.py").read_text(encoding="utf-8"))
    module = ast.Module(
        body=[
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "format_scan_result"
        ],
        type_ignores=[],
    )
    namespace = {
        "is_scan_incomplete": is_scan_incomplete,
        "escape_markdown": escape_markdown,
        "escape_markdown_lines": escape_markdown_lines,
    }
    exec(compile(module, "bot.py", "exec"), namespace)
    return namespace["format_scan_result"]


@pytest.mark.asyncio
async def test_bot_confirmed_wallet_verification_is_not_applicable(
    format_scan_result, mock_web3_client
):
    mock_web3_client.is_contract.return_value = False
    scanner = TransactionScanner(mock_web3_client)
    scanner.scam_db.check_address = AsyncMock(return_value=[])
    report = format_scan_result(await scanner.scan_address(ADDRESS))
    assert "**Verification Status:**\nNot applicable (wallet address, not a contract)\n" in report
    assert "Unknown (verification data unavailable)" not in report
    assert "🟢 LOW" in report


@pytest.mark.parametrize(
    "result",
    [
        {"is_contract": None, "status": "unknown", "coverage": {"is_contract": False}},
        {"is_contract": True, "is_verified": None},
    ],
)
def test_bot_unknown_contract_or_verification_stays_unknown(format_scan_result, result):
    report = format_scan_result({"address": ADDRESS, **result})
    assert "**Verification Status:**\nUnknown (verification data unavailable)\n" in report
    assert "Not applicable" not in report


@pytest.mark.parametrize(
    "contract_data, rendered",
    [
        ({"is_contract": False, "is_verified": None}, "  Verified: Not applicable (wallet or destroyed contract)"),
        ({"is_contract": None, "is_verified": None}, "  Verified: Unknown"),
        ({"is_contract": True, "is_verified": None}, "  Verified: Unknown"),
        ({"is_contract": True, "is_verified": True}, "  Verified: ✅"),
        ({"is_contract": True, "is_verified": False}, "  Verified: ❌"),
    ],
)
def test_telegram_report_verification_wording(contract_data, rendered):
    risk = {
        "status": "ok",
        "coverage": {"structural": 1},
        "rug_probability": 5,
        "risk_level": "LOW",
    }
    lines = format_full_report(risk, contract_data, {}, {}, address=ADDRESS).split("\n")
    assert rendered in lines
