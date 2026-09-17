"""Each application module must import first in a fresh interpreter."""

import importlib.util
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
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
TELEGRAM_INSTALLED = importlib.util.find_spec("telegram") is not None


def _import_first(module):
    return subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )


@pytest.fixture(scope="module")
def fresh_imports():
    # Every module still gets its own interpreter; only the waiting is shared.
    modules = [*MODULES, "api", *(["bot"] if TELEGRAM_INSTALLED else [])]
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        yield {module: pool.submit(_import_first, module) for module in modules}


@pytest.mark.parametrize("module", [
    *MODULES,
    "api",
    pytest.param("bot", marks=pytest.mark.skipif(
        not TELEGRAM_INSTALLED,
        reason="telegram is not installed",
    )),
])
def test_module_imports_first_in_fresh_interpreter(fresh_imports, module):
    result = fresh_imports[module].result()
    assert result.returncode == 0, result.stderr
