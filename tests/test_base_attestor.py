"""Tests for BaseAttestor — Python bridge to ShieldBotAttestor on Base."""

import os
from unittest.mock import patch, MagicMock

import pytest
from utils.base_attestor import BaseAttestor, RISK_LEVEL_MAP


def test_disabled_when_no_address():
    with patch.dict(os.environ, {"BASE_ATTESTOR_ADDRESS": "", "BASE_VERIFIER_PRIVATE_KEY": ""}, clear=False):
        a = BaseAttestor()
        assert not a.is_available()


def test_disabled_when_no_key():
    with patch.dict(os.environ, {
        "BASE_ATTESTOR_ADDRESS": "0x1111111111111111111111111111111111111111",
        "BASE_VERIFIER_PRIVATE_KEY": "",
    }, clear=False):
        a = BaseAttestor()
        assert not a.is_available()


def test_initialized_with_both():
    with patch.dict(os.environ, {
        "BASE_ATTESTOR_ADDRESS": "0x1111111111111111111111111111111111111111",
        "BASE_VERIFIER_PRIVATE_KEY": "0x" + "11" * 32,
    }, clear=False):
        a = BaseAttestor()
        assert a.is_available()
        assert a.account is not None
        assert a.contract is not None


@pytest.mark.asyncio
async def test_attest_returns_none_when_disabled():
    a = BaseAttestor(contract_address="", private_key="")
    result = await a.attest("0xabc", "high", "contract")
    assert result is None


@pytest.mark.asyncio
async def test_attest_builds_and_sends_tx():
    a = BaseAttestor(
        contract_address="0x1111111111111111111111111111111111111111",
        private_key="0x" + "11" * 32,
    )

    mock_eth = MagicMock()
    mock_eth.get_transaction_count.return_value = 5
    mock_eth.gas_price = 1_000_000
    mock_eth.send_raw_transaction.return_value = b"\xab" * 32

    mock_signed = MagicMock()
    mock_signed.raw_transaction = b"\xcd" * 100
    mock_eth.account.sign_transaction.return_value = mock_signed

    a.web3.eth = mock_eth
    a.contract.functions = MagicMock()
    mock_tx = {"from": a.account.address, "nonce": 5, "gas": 350_000, "gasPrice": 1_000_000, "chainId": 8453}
    a.contract.functions.attest.return_value.build_transaction.return_value = mock_tx

    tx_hash = await a.attest(
        scanned_address="0x" + "ab" * 20,
        risk_level="danger",
        scan_type="contract",
        source_chain_id=56,
        evidence={"deployer": "0xdef", "honeypot": True},
        evidence_uri="ipfs://Qm...",
    )

    assert tx_hash == ("ab" * 32)
    a.contract.functions.attest.assert_called_once()
    call_args = a.contract.functions.attest.call_args[0]
    # checksum address, risk uint8, scan type, source chain id, evidence hash, evidence URI
    assert call_args[1] == 5  # danger -> 5
    assert call_args[2] == "contract"
    assert call_args[3] == 56
    assert len(call_args[4]) == 32  # bytes32 keccak hash
    assert call_args[5] == "ipfs://Qm..."


@pytest.mark.asyncio
async def test_attest_evidence_hash_zero_when_none():
    a = BaseAttestor(
        contract_address="0x1111111111111111111111111111111111111111",
        private_key="0x" + "11" * 32,
    )
    mock_eth = MagicMock()
    mock_eth.get_transaction_count.return_value = 0
    mock_eth.gas_price = 1
    mock_eth.send_raw_transaction.return_value = b"\xab" * 32
    mock_signed = MagicMock()
    mock_signed.raw_transaction = b""
    mock_eth.account.sign_transaction.return_value = mock_signed
    a.web3.eth = mock_eth
    a.contract.functions = MagicMock()
    a.contract.functions.attest.return_value.build_transaction.return_value = {}

    await a.attest("0x" + "ab" * 20, "low", "token")
    call_args = a.contract.functions.attest.call_args[0]
    assert call_args[4] == b"\x00" * 32


@pytest.mark.asyncio
async def test_attest_swallows_errors():
    a = BaseAttestor(
        contract_address="0x1111111111111111111111111111111111111111",
        private_key="0x" + "11" * 32,
    )
    mock_eth = MagicMock()
    mock_eth.get_transaction_count.side_effect = RuntimeError("rpc dead")
    a.web3.eth = mock_eth

    result = await a.attest("0x" + "ab" * 20, "high", "contract")
    assert result is None


def test_risk_level_map_matches_solidity():
    assert RISK_LEVEL_MAP == {"low": 0, "medium": 1, "high": 2, "safe": 3, "warning": 4, "danger": 5}
