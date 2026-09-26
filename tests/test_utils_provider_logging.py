"""Provider and RPC failures in utils must not log exception text."""

import ast
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

import utils.scam_db as scam_db
from utils.ai_analyzer import AIAnalyzer
from utils.scam_db import ScamDatabase


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUARDED_FILES = (
    "utils/scam_db.py", "utils/ai_analyzer.py",
    "analyzers/signature.py", "sdk/python/shieldbot/client.py", "services/guardian.py",
    "services/verdict_publisher.py",
)
ADDRESS = "0x89e5db8b5aa49aa85ac63f691524311aeb649eba"
TEST_KEY = "utils-log-test-key"
LOG_METHODS = {"debug", "info", "warning", "error", "critical", "exception", "log"}


def _connection_error():
    return aiohttp.ClientConnectionError(f"Cannot connect to host: {TEST_KEY}")


@pytest.fixture
def goplus_cache():
    scam_db._GOPLUS_CACHE.clear()
    yield
    scam_db._GOPLUS_CACHE.clear()


@pytest.mark.asyncio
async def test_goplus_failure_logs_class_only(caplog, goplus_cache):
    caplog.set_level(logging.DEBUG, logger="utils.scam_db")
    with patch("utils.scam_db.aiohttp.ClientSession", side_effect=_connection_error()):
        result = await ScamDatabase.fetch_token_security(ADDRESS, 4663)
    assert result["reason"] == "GoPlus request failed (ClientConnectionError)"
    assert TEST_KEY not in caplog.text
    assert "ClientConnectionError" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("method,args", [
    ("compute_ai_risk_score", (ADDRESS, {})),
    ("generate_forensic_report", (ADDRESS, {}, "contract")),
    ("generate_firewall_report", ({"to": ADDRESS}, {}, "CAUTION", 40)),
])
async def test_ai_provider_failure_logs_class_only(caplog, method, args):
    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    analyzer.client = MagicMock()
    analyzer.client.messages.create = AsyncMock(
        side_effect=RuntimeError(f"Invalid x-api-key: {TEST_KEY}")
    )
    analyzer._openai_client = None
    analyzer.model = "test-model"
    caplog.set_level(logging.DEBUG, logger="utils.ai_analyzer")
    assert await getattr(analyzer, method)(*args) is None
    analyzer.client.messages.create.assert_awaited_once()
    assert TEST_KEY not in caplog.text
    assert "RuntimeError" in caplog.text


def _handler_leaks(handler):
    def is_exception(node):
        return isinstance(node, ast.Name) and node.id == handler.name

    leaks = []
    for node in ast.walk(handler):
        if isinstance(node, ast.FormattedValue) and is_exception(node.value):
            leaks.append((node.lineno, "f-string exception"))
        elif not isinstance(node, ast.Call) or not any(is_exception(arg) for arg in node.args):
            continue
        elif isinstance(node.func, ast.Name) and node.func.id in ("str", "repr"):
            leaks.append((node.lineno, f"{node.func.id}() of exception"))
        elif isinstance(node.func, ast.Attribute) and node.func.attr in LOG_METHODS:
            leaks.append((node.lineno, "exception as log argument"))
    return leaks


def _exception_text_leaks(source):
    leaks = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.keyword) and node.arg == "exc_info":
            leaks.append((node.lineno, "exc_info keyword"))
        elif (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "exception"
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "logger"
        ):
            leaks.append((node.lineno, "logger.exception"))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            leaks.extend(_handler_leaks(node))
    return sorted(leaks)


@pytest.mark.parametrize("statement,expected", [
    ('logger.error(f"failed: {e}")', [(5, "f-string exception")]),
    ('logger.error("failed: %s", e)', [(5, "exception as log argument")]),
    ('logger.error("failed: " + str(e))', [(5, "str() of exception")]),
    ('logger.error("failed", exc_info=True)', [(5, "exc_info keyword")]),
    ('logger.exception("failed")', [(5, "logger.exception")]),
    ('logger.error("failed: %s", type(e).__name__)', []),
])
def test_exception_text_guard_detects_leaks(statement, expected):
    source = f"""
try:
    pass
except Exception as e:
    {statement}
"""
    assert _exception_text_leaks(source) == expected


@pytest.mark.parametrize("path", GUARDED_FILES)
def test_provider_utils_do_not_log_exception_text(path):
    source = (PROJECT_ROOT / path).read_text(encoding="utf-8")
    assert _exception_text_leaks(source) == []
