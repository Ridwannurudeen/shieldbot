"""The BSC verifier writer and the Base attestor writer are retired: nothing in a scan writes to either."""

import importlib.util
from unittest.mock import patch

import pytest

from core.config import Settings
from tests.test_verdict_wiring import TOKEN, bot_scan_functions, update  # noqa: F401  (pytest fixture)

PATCHED = (
    "Web3Client", "AIAnalyzer", "ScamDatabase", "CalldataDecoder", "TransactionScanner", "TokenScanner",
    "DexService", "EthosService", "HoneypotService", "ContractService", "GreenfieldService",
    "TenderlySimulator", "RiskEngine",
)


@pytest.mark.parametrize("module", ["utils.onchain_recorder", "utils.base_attestor"])
def test_writer_module_is_removed(module):
    assert importlib.util.find_spec(module) is None


def test_settings_have_no_writer_key():
    assert "bot_wallet_private_key" not in Settings.model_fields


def test_container_builds_without_the_writers_and_keeps_the_reader():
    patches = [patch(f"core.container.{name}") for name in PATCHED]
    for active in patches:
        active.start()
    try:
        from core.container import ServiceContainer

        container = ServiceContainer(Settings(_env_file=None))
    finally:
        for active in patches:
            active.stop()

    assert not hasattr(container, "onchain_recorder")
    assert not hasattr(container, "base_attestor")
    # The records already on Base stay readable through /api/base/attestations.
    assert not container.base_attestation_reader.is_available()


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
async def test_a_complete_scan_replies_without_a_recorder_or_an_attestor(bot_scan_functions, handler):
    # The handlers run in a namespace that holds neither writer, so a reference to one would raise
    # NameError before the reply is sent.
    ns = bot_scan_functions
    assert "onchain_recorder" not in ns and "base_attestor" not in ns
    reply = update()
    await ns[handler](reply, TOKEN, chain_id=56)
    assert reply.message.reply_text.await_args.args[0] == "Report"
