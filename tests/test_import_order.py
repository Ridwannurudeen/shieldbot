"""Each application module must import first in a fresh interpreter."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGES = (
    "adapters", "core", "services", "utils", "analyzers", "scanner",
    "agent", "mcp_server", "rpc", "scripts.census_4663",
)
MODULES = sorted({
    ".".join(
        (path.parent if path.name == "__init__.py" else path.with_suffix(""))
        .relative_to(PROJECT_ROOT).parts
    )
    for package in PACKAGES
    for path in (PROJECT_ROOT / package.replace(".", "/")).rglob("*.py")
})


@pytest.mark.parametrize("module", [
    *MODULES,
    "api",
    pytest.param("bot", marks=pytest.mark.skipif(
        importlib.util.find_spec("telegram") is None,
        reason="telegram is not installed",
    )),
])
def test_module_imports_first_in_fresh_interpreter(module):
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
