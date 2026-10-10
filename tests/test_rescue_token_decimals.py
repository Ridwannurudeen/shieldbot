"""A rescue scan never scales a token's amounts by decimals it could not read.

get_token_info answers {} when any of its reads fails, or when a token's name or symbol cannot be
decoded. The scan used to assume 18 decimals then, so 1,000 USDC (6 decimals) under an unlimited
approval read as $0.00 at risk with status ok. Now that approval keeps its verdict and its raw
allowance, has no USD value, and the scan says why.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from services.rescue_service import APPROVAL_TOPIC, UNLIMITED_THRESHOLD, RescueService

WALLET = "0x" + "1" * 40
USDC = "0x" + "2" * 40
OTHER = "0x" + "4" * 40
SPENDER = "0x" + "3" * 40
LATEST = 1_000
USDC_INFO = {"name": "USD Coin", "symbol": "USDC", "decimals": 6, "total_supply": 1e9}
OTHER_INFO = {"name": "Other", "symbol": "OTH", "decimals": 18, "total_supply": 1e9}
THOUSAND_USDC = 1_000 * 10**6
DECIMALS_REASON = "Token decimals unavailable for 1 token(s)"


def approval_log(token):
    return {
        "address": token,
        "topics": [APPROVAL_TOPIC, "0x" + "0" * 24 + WALLET[2:], "0x" + "0" * 24 + SPENDER[2:]],
        "data": hex(UNLIMITED_THRESHOLD),
        "blockNumber": hex(LATEST),
    }


async def scan(infos, allowances, balances, prices):
    """A complete scan of the whole history (so nothing else is unknown) whose tokens have
    ``infos`` as their token info, and the given allowances, balances and USD prices."""
    web3_client = MagicMock()
    web3_client.get_token_info = AsyncMock(side_effect=lambda token, chain_id: infos[token])
    service = RescueService(web3_client, logs_rpc="https://rpc.invalid")
    service._fetch_all_approval_logs = AsyncMock(
        return_value=([approval_log(token) for token in infos], 0, LATEST)
    )
    service._verify_allowances = AsyncMock(
        return_value={(token, SPENDER): allowance for token, allowance in allowances.items()}
    )
    service._fetch_balances = AsyncMock(return_value=balances)
    service._fetch_prices = AsyncMock(return_value=prices)
    return await service.scan_approvals(WALLET, 56)


@pytest.mark.asyncio
async def test_a_token_with_unread_decimals_has_no_invented_value_and_the_scan_says_why():
    args = ({USDC: UNLIMITED_THRESHOLD}, {USDC: THOUSAND_USDC}, {USDC: 1.0})
    read = await scan({USDC: USDC_INFO}, *args)
    unread = await scan({USDC: {}}, *args)

    assert read["approvals"][0]["value_at_risk_usd"] == 1000.0
    assert read["status"] == "ok"
    assert read["total_value_at_risk_usd"] == 1000.0

    (approval,) = unread["approvals"]
    assert approval["risk_level"] == read["approvals"][0]["risk_level"] == "HIGH"
    assert approval["risk_reason"] == read["approvals"][0]["risk_reason"]
    assert approval["allowance"] == "Unlimited"
    assert approval["value_at_risk_usd"] is None
    assert [tx["value_at_risk_usd"] for tx in unread["revoke_txs"]] == [None]
    assert unread["status"] == "unknown"
    assert unread["coverage"] == {"allowances": True, "balances": True, "prices": False}
    assert unread["coverage_reasons"] == {"prices": DECIMALS_REASON}
    assert unread["total_value_at_risk_usd"] is None


@pytest.mark.asyncio
async def test_a_limited_allowance_with_unread_decimals_is_shown_unscaled():
    args = ({USDC: 500 * 10**6}, {USDC: THOUSAND_USDC}, {USDC: 1.0})
    read = await scan({USDC: USDC_INFO}, *args)
    unread = await scan({USDC: {}}, *args)

    assert read["approvals"][0]["allowance"] == "500.00"
    (approval,) = unread["approvals"]
    assert approval["allowance"] == "500000000"
    assert approval["risk_level"] == read["approvals"][0]["risk_level"]
    assert approval["value_at_risk_usd"] is None
    assert unread["coverage_reasons"] == {"prices": DECIMALS_REASON}


@pytest.mark.asyncio
async def test_unread_decimals_of_a_token_the_wallet_does_not_hold_leave_the_scan_complete():
    result = await scan({USDC: {}}, {USDC: UNLIMITED_THRESHOLD}, {USDC: 0}, {USDC: 1.0})

    assert result["approvals"][0]["value_at_risk_usd"] is None
    assert result["status"] == "ok"
    assert result["coverage_reasons"] == {}
    assert result["total_value_at_risk_usd"] == 0.0


@pytest.mark.asyncio
async def test_an_unpriced_token_is_counted_once_and_the_reasons_combine():
    # USDC's decimals are unread and OTHER has no price: each is one reason. An unpriced token with
    # unread decimals is counted only as unpriced, since without a price it has no USD value anyway.
    infos = {USDC: {}, OTHER: OTHER_INFO}
    allowances = {USDC: UNLIMITED_THRESHOLD, OTHER: UNLIMITED_THRESHOLD}
    balances = {USDC: THOUSAND_USDC, OTHER: 10**18}
    combined = await scan(infos, allowances, balances, {USDC: 1.0})
    unpriced_only = await scan({USDC: {}}, {USDC: UNLIMITED_THRESHOLD}, {USDC: THOUSAND_USDC}, {})

    assert combined["coverage_reasons"] == {
        "prices": f"USD price unavailable for 1 token(s); {DECIMALS_REASON}"
    }
    assert unpriced_only["coverage_reasons"] == {"prices": "USD price unavailable for 1 token(s)"}
