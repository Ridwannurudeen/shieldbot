"""deploy/nginx-api.conf.example must forward the client address the way the API reads it."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_reference_api_vhost_forwards_the_client_address_and_adds_no_headers():
    from core.registry import RUN_ALL_DEADLINE_SECONDS

    vhost = (ROOT / "deploy" / "nginx-api.conf.example").read_text(encoding="utf-8")
    directives = [
        line.strip()
        for line in vhost.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    for header in (
        "Host $host",
        "X-Real-IP $remote_addr",
        "X-Forwarded-For $proxy_add_x_forwarded_for",
        "X-Forwarded-Proto $scheme",
    ):
        assert f"proxy_set_header {header};" in directives, header
    # The API unit listens where the vhost proxies to.
    assert "--host 127.0.0.1 --port 8000" in (ROOT / "shieldbot-api.service").read_text(
        encoding="utf-8"
    )
    assert "proxy_pass http://127.0.0.1:8000;" in directives
    # The app sets CORS and its security headers itself; nginx must not send them a second time.
    assert not [directive for directive in directives if directive.startswith("add_header")]
    read_timeout = re.search(r"^proxy_read_timeout (\d+)s;$", "\n".join(directives), re.MULTILINE)
    assert int(read_timeout.group(1)) > RUN_ALL_DEADLINE_SECONDS
