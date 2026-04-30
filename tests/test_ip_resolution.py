"""Tests for client IP resolution with trusted proxies."""

from types import SimpleNamespace
from starlette.requests import Request


def _make_request(client_ip: str, xff: str | None = None) -> Request:
    headers = []
    if xff:
        headers.append((b"x-forwarded-for", xff.encode()))
    scope = {
        "type": "http",
        "headers": headers,
        "client": (client_ip, 1234),
        "method": "GET",
        "path": "/",
        "scheme": "http",
        "server": ("testserver", 80),
    }
    return Request(scope)


def test_api_get_client_ip_trusted_proxy():
    import api as api_module
    api_module.container = SimpleNamespace(
        settings=SimpleNamespace(trusted_proxies=["10.0.0.1"])
    )
    req = _make_request("10.0.0.1", "1.2.3.4")
    assert api_module._get_client_ip(req) == "1.2.3.4"


def test_api_get_client_ip_untrusted_proxy():
    import api as api_module
    api_module.container = SimpleNamespace(
        settings=SimpleNamespace(trusted_proxies=["10.0.0.1"])
    )
    req = _make_request("10.0.0.2", "1.2.3.4")
    assert api_module._get_client_ip(req) == "10.0.0.2"


def test_api_get_client_ip_uses_nearest_untrusted_hop():
    import api as api_module
    api_module.container = SimpleNamespace(
        settings=SimpleNamespace(trusted_proxies=["10.0.0.1", "10.0.0.2"])
    )
    req = _make_request("10.0.0.1", "198.51.100.9, 203.0.113.7, 10.0.0.2")
    assert api_module._get_client_ip(req) == "203.0.113.7"


def test_rpc_get_client_ip_trusted_proxy():
    from rpc import router as rpc_router
    req = _make_request("10.0.0.1", "1.2.3.4")
    assert rpc_router._get_client_ip(req, {"10.0.0.1"}) == "1.2.3.4"


def test_rpc_get_client_ip_untrusted_proxy():
    from rpc import router as rpc_router
    req = _make_request("10.0.0.2", "1.2.3.4")
    assert rpc_router._get_client_ip(req, {"10.0.0.1"}) == "10.0.0.2"


def test_rpc_get_client_ip_uses_nearest_untrusted_hop():
    from rpc import router as rpc_router
    req = _make_request("10.0.0.1", "198.51.100.9, 203.0.113.7, 10.0.0.2")
    assert rpc_router._get_client_ip(req, {"10.0.0.1", "10.0.0.2"}) == "203.0.113.7"
