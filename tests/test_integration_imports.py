"""Import regressions across the chain-routing and explorer services."""

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("module", ["agent.advisor", "utils.web3_client", "services.mempool_service"])
def test_chain_and_explorer_imports_in_fresh_process(module):
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
