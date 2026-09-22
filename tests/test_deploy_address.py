"""Local-only checks for deployment address configuration and nginx rendering."""

import os
from pathlib import Path
import re
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


@pytest.mark.parametrize("filename", ["setup-bare-domain.sh", "setup-https.sh"])
@pytest.mark.parametrize("value", [None, ""])
def test_missing_address_fails_before_external_commands(bash, filename, value):
    environment = os.environ.copy()
    environment.pop("VPS_IP", None)
    if value is not None:
        environment["VPS_IP"] = value
    source = (ROOT / "deploy" / filename).read_text(encoding="utf-8")
    # Prevent the old scripts from performing operations while reproducing the bug.
    stubs = (
        "dig() { return 0; }; apt() { echo UNEXPECTED_SIDE_EFFECT >&2; return 99; };\n"
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


@pytest.mark.parametrize("address", ["192.0.2.10", "198.51.100.20"])
def test_generated_nginx_listeners_use_environment(bash, address):
    source = (ROOT / "deploy/setup-bare-domain.sh").read_text(encoding="utf-8")
    heredoc = re.search(
        r"cat > /etc/nginx/sites-available/shieldbot (<<[^\n]+\n.*?\nNGINX)",
        source,
        re.S,
    )
    assert heredoc is not None
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-s"],
        input="set -eu\ncat " + heredoc.group(1) + "\n",
        env={**os.environ, "VPS_IP": address},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert re.findall(r"^\s*listen (.*);$", result.stdout, re.M) == [
        f"{address}:80",
        f"{address}:443 ssl http2",
        f"{address}:80",
        f"{address}:443 ssl http2",
    ]
    assert result.stdout.count("return 301 https://$server_name$request_uri;") == 2
    for variable in ("host", "remote_addr", "proxy_add_x_forwarded_for", "scheme"):
        assert result.stdout.count(f"${variable};") == 2
