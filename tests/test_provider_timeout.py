"""Every EVM adapter's web3 HTTPProvider carries an explicit request timeout."""

import json
from unittest.mock import patch

import pytest
import requests

from adapters.eth import EthAdapter
from adapters.evm_base import RPC_REQUEST_TIMEOUT_SECONDS
from adapters.robinhood import RobinhoodAdapter


@pytest.mark.parametrize("build", [
    lambda: EthAdapter(rpc_url="https://rpc.invalid"),
    lambda: RobinhoodAdapter(rpc_url="https://rpc.invalid"),
])
def test_the_provider_is_built_with_the_explicit_timeout(build):
    with patch("adapters.evm_base.Web3") as web3:
        build()

    web3.HTTPProvider.assert_called_once_with(
        "https://rpc.invalid", request_kwargs={"timeout": RPC_REQUEST_TIMEOUT_SECONDS}
    )


def test_the_timeout_reaches_the_http_post_of_every_rpc_call():
    adapter = EthAdapter(rpc_url="https://rpc.invalid")
    timeouts = []

    def post(session, url, *args, **kwargs):
        timeouts.append(kwargs.get("timeout"))
        request = json.loads(kwargs["data"])
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": "0x10"}).encode()
        return response

    with patch("requests.Session.post", post):
        assert adapter.w3.eth.block_number == 16

    assert timeouts == [RPC_REQUEST_TIMEOUT_SECONDS]


def test_the_timeout_matches_the_web3_6_default_that_production_runs_today():
    # web3 6.15.1 (requirements.txt) posts with web3._utils.request.DEFAULT_TIMEOUT = 10 unless told
    # otherwise; web3 7 defaults to 30 s. Pinning 10 s keeps production unchanged on 6.15.1.
    assert RPC_REQUEST_TIMEOUT_SECONDS == 10
