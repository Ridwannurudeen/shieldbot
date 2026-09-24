"""Local-only checks for deployment address configuration."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def bash():
    executable = shutil.which("bash")
    if executable is None:
        pytest.skip("Bash is required for deployment script regression tests")
    return executable


@pytest.mark.parametrize("filename", ["setup-https.sh"])
@pytest.mark.parametrize("value", [None, ""])
def test_missing_address_fails_before_external_commands(bash, filename, value):
    environment = os.environ.copy()
    environment.pop("VPS_IP", None)
    if value is not None:
        environment["VPS_IP"] = value
    source = (ROOT / "deploy" / filename).read_text(encoding="utf-8")
    # Prevent the old scripts from performing operations while reproducing the bug.
    stubs = (
        "apt() { echo UNEXPECTED_SIDE_EFFECT >&2; return 99; };\n"
    )
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-s"],
        input=stubs + source,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "VPS_IP" in result.stderr
    assert "UNEXPECTED_SIDE_EFFECT" not in result.stderr
