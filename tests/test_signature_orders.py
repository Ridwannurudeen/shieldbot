"""Marketplace orders in typed data: a Seaport order, a Seaport bulk order (a tree of orders) and
Blur Exchange's order and bulk listing, read through the types they declare.

An order gives its offer away; what it asks for back reaches the signer only through the
consideration paid to the signer (Seaport) or the price less fees paid to others (Blur). An order
whose declared types are not its standard's is Unknown and judged as a zero-price listing.
"""

import pytest

from analyzers.signature import SignaturePermitAnalyzer
from core.analyzer import AnalysisContext
from tests.test_consumer_unknowns import assert_unknown_response, consumer_api  # noqa: F401

SIGNER = "0x" + "a" * 40
ATTACKER = "0x" + "d" * 40
MARKET = "0x" + "f" * 40
NFT = "0x" + "c" * 40
ONE_ETH = str(10**18)


def _struct(*members):
    return [{"name": name, "type": kind} for name, kind in members]


SEAPORT_TYPES = {
    "OrderComponents": _struct(
        ("offerer", "address"),
        ("zone", "address"),
        ("offer", "OfferItem[]"),
        ("consideration", "ConsiderationItem[]"),
        ("orderType", "uint8"),
        ("startTime", "uint256"),
        ("endTime", "uint256"),
        ("zoneHash", "bytes32"),
        ("salt", "uint256"),
        ("conduitKey", "bytes32"),
        ("counter", "uint256"),
    ),
    "OfferItem": _struct(
        ("itemType", "uint8"),
        ("token", "address"),
        ("identifierOrCriteria", "uint256"),
        ("startAmount", "uint256"),
        ("endAmount", "uint256"),
    ),
    "ConsiderationItem": _struct(
        ("itemType", "uint8"),
        ("token", "address"),
        ("identifierOrCriteria", "uint256"),
        ("startAmount", "uint256"),
        ("endAmount", "uint256"),
        ("recipient", "address"),
    ),
}

BLUR_TYPES = {
    "Order": _struct(
        ("trader", "address"),
        ("side", "uint8"),
        ("matchingPolicy", "address"),
        ("collection", "address"),
        ("tokenId", "uint256"),
        ("amount", "uint256"),
        ("paymentToken", "address"),
        ("price", "uint256"),
        ("listingTime", "uint256"),
        ("expirationTime", "uint256"),
        ("fees", "Fee[]"),
        ("salt", "uint256"),
        ("extraParams", "bytes"),
        ("nonce", "uint256"),
    ),
    "Fee": _struct(("rate", "uint16"), ("recipient", "address")),
}


def _nft(item_type=2):
    return {
        "itemType": item_type,
        "token": NFT,
        "identifierOrCriteria": "1",
        "startAmount": "1",
        "endAmount": "1",
    }


def _pay(recipient, start=ONE_ETH, end=None, item_type=0):
    return {
        "itemType": item_type,
        "token": "0x" + "0" * 40,
        "identifierOrCriteria": "0",
        "startAmount": start,
        "endAmount": start if end is None else end,
        "recipient": recipient,
    }


def _order(offer, consideration, offerer=SIGNER):
    return {
        "offerer": offerer,
        "zone": "0x" + "0" * 40,
        "offer": offer,
        "consideration": consideration,
        "orderType": 0,
        "startTime": "0",
        "endTime": "9999999999",
        "zoneHash": "0x" + "0" * 64,
        "salt": "1",
        "conduitKey": "0x" + "0" * 64,
        "counter": "0",
    }


# A padding leaf, as Seaport fills a bulk order's tree.
EMPTY = _order([], [], offerer="0x" + "0" * 40)
LISTING = _order([_nft()], [_pay(SIGNER), _pay(MARKET, str(25 * 10**15))])


def _seaport(message, primary_type="OrderComponents", types=SEAPORT_TYPES):
    return {
        "types": types,
        "primaryType": primary_type,
        "domain": {"name": "Seaport", "version": "1.6"},
        "message": message,
    }


def _bulk(tree, height):
    return _seaport(
        {"tree": tree},
        "BulkOrder",
        {**SEAPORT_TYPES, "BulkOrder": _struct(("tree", "OrderComponents" + "[2]" * height))},
    )


def _blur(message, primary_type="Order", types=BLUR_TYPES):
    return {
        "types": types,
        "primaryType": primary_type,
        "domain": {"name": "Blur Exchange", "version": "1.0"},
        "message": message,
    }


def _blur_order(side=1, price=ONE_ETH, fees=None):
    return {
        "trader": SIGNER,
        "side": side,
        "matchingPolicy": "0x" + "1" * 40,
        "collection": NFT,
        "tokenId": "1",
        "amount": "1",
        "paymentToken": "0x" + "0" * 40,
        "price": price,
        "listingTime": "0",
        "expirationTime": "9999999999",
        "fees": [{"rate": 50, "recipient": MARKET}] if fees is None else fees,
        "salt": "1",
        "extraParams": "0x",
        "nonce": "0",
    }


async def _analyze(typed_data):
    return await SignaturePermitAnalyzer().analyze(
        AnalysisContext(
            address=MARKET,
            chain_id=1,
            from_address=SIGNER,
            extra={"typed_data": typed_data, "sign_method": "eth_signTypedData_v4"},
        )
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "typed, score, flag",
    [
        (_seaport(LISTING), 0, None),
        # A bid offers a token for an NFT paid to the bidder: nothing is given away for nothing.
        (
            _seaport(
                _order(
                    [_pay(SIGNER, item_type=1) | {"recipient": None}],
                    [_nft() | {"recipient": SIGNER}],
                )
            ),
            0,
            None,
        ),
        (_seaport(_order([_nft()], [])), 50, "zero-price"),
        # The price is paid, but to another address: the signer's NFT goes for nothing.
        (_seaport(_order([_nft()], [_pay(ATTACKER)])), 50, "goes to other addresses"),
        (_seaport(_order([_nft(3)], [_pay(SIGNER, "1"), _pay(ATTACKER)])), 30, "suspiciously low"),
        # A price that falls to 0 by the end of the auction is a zero price.
        (_seaport(_order([_nft()], [_pay(SIGNER, end="0")])), 50, "zero-price"),
        # An offer by criteria lets the buyer pick any matching NFT of the signer's.
        (_seaport(_order([_nft(4)], [_pay(ATTACKER)])), 50, "goes to other addresses"),
        (_seaport(_order([_nft()], [_pay(SIGNER, "an amount")])), 50, "zero-price"),
    ],
    ids=[
        "listing",
        "bid",
        "no-consideration",
        "paid-to-another-address",
        "near-zero",
        "falls-to-zero",
        "criteria-offer",
        "unreadable-amount",
    ],
)
async def test_a_seaport_order_is_judged_by_what_its_offerer_is_paid(typed, score, flag):
    result = await _analyze(typed)
    assert result.score == score
    assert result.data["sig_type"] == "seaport_order"
    assert result.data.get("status") != "unknown"
    assert (flag is None) == (not result.flags)
    if flag:
        assert any(flag in f for f in result.flags), result.flags


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "types",
    [
        None,
        {k: v for k, v in SEAPORT_TYPES.items() if k != "ConsiderationItem"},
        {
            **SEAPORT_TYPES,
            "ConsiderationItem": [
                m for m in SEAPORT_TYPES["ConsiderationItem"] if m["name"] != "recipient"
            ],
        },
        {
            **SEAPORT_TYPES,
            "OfferItem": [m for m in SEAPORT_TYPES["OfferItem"] if m["name"] != "endAmount"],
        },
    ],
    ids=["no-types", "no-consideration-type", "no-recipient", "no-end-amount"],
)
async def test_a_seaport_order_whose_types_are_not_seaports_is_unknown_and_worst_case(types):
    result = await _analyze(_seaport(LISTING, types=types))
    assert result.score == 50
    assert result.data["status"] == "unknown"
    assert result.data["coverage"]["typed_data"] is False
    assert any("zero-price" in f for f in result.flags)


@pytest.mark.asyncio
async def test_a_bulk_order_is_judged_order_by_order():
    tree = [[LISTING, LISTING], [_order([_nft()], [_pay(ATTACKER)]), EMPTY]]
    result = await _analyze(_bulk(tree, 2))
    assert result.data["sig_type"] == "seaport_bulk_order"
    assert result.score == 50
    assert result.data.get("status") != "unknown"
    assert any("goes to other addresses" in f and "1 of 4" in f for f in result.flags), result.flags


@pytest.mark.asyncio
async def test_a_bulk_order_of_ordinary_listings_is_not_flagged():
    result = await _analyze(_bulk([LISTING, EMPTY], 1))
    assert result.score == 0
    assert result.flags == []
    assert result.data.get("status") != "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "typed",
    [
        _bulk([LISTING, LISTING], 2),
        _bulk([[LISTING, LISTING], [LISTING]], 2),
        _bulk([LISTING, "not an order"], 1),
        _seaport(
            {"tree": [LISTING, EMPTY]},
            "BulkOrder",
            {**SEAPORT_TYPES, "BulkOrder": _struct(("tree", "OrderComponents[]"))},
        ),
        _seaport({"tree": [LISTING, EMPTY]}, "BulkOrder", SEAPORT_TYPES),
    ],
    ids=[
        "tree-shallower-than-declared",
        "uneven-tree",
        "leaf-not-an-order",
        "tree-not-pairs",
        "no-bulk-type",
    ],
)
async def test_a_bulk_order_that_is_not_seaports_tree_is_unknown_and_worst_case(typed):
    result = await _analyze(typed)
    assert result.score == 50
    assert result.data["status"] == "unknown"
    assert any("zero-price" in f for f in result.flags)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message, score, flag",
    [
        (_blur_order(), 0, None),
        (_blur_order(side=0, price="0"), 0, None),
        (_blur_order(price="0"), 50, "zero-price"),
        (
            _blur_order(fees=[{"rate": 10_000, "recipient": ATTACKER}]),
            50,
            "fees take the whole price",
        ),
        (_blur_order(price="500"), 30, "suspiciously low"),
        # A fee paid back to the seller leaves the seller the price.
        (_blur_order(fees=[{"rate": 10_000, "recipient": SIGNER}]), 0, None),
    ],
    ids=["listing", "bid", "zero-price", "fees-to-another-address", "near-zero", "fee-to-self"],
)
async def test_a_blur_order_is_judged_by_what_its_seller_is_paid(message, score, flag):
    result = await _analyze(_blur(message))
    assert result.data["sig_type"] == "blur_order"
    assert result.score == score
    assert result.data.get("status") != "unknown"
    if flag:
        assert any(flag in f for f in result.flags), result.flags
    else:
        assert result.flags == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "typed, sig_type",
    [
        # Blur's bulk listing signs only the Merkle root of its orders: none of them can be read.
        (
            _blur({"root": "0x" + "1" * 64}, "Root", {"Root": _struct(("root", "bytes32"))}),
            "blur_bulk_order",
        ),
        (_blur(_blur_order(), types={"Order": BLUR_TYPES["Order"]}), "blur_order"),
        (
            _blur(
                {"trader": SIGNER, "listingsRoot": "0x" + "1" * 64},
                types={
                    "Order": _struct(
                        ("trader", "address"),
                        ("collection", "address"),
                        ("listingsRoot", "bytes32"),
                        ("numberOfListings", "uint256"),
                    )
                },
            ),
            "blur_order",
        ),
    ],
    ids=["bulk-root", "no-fee-type", "listings-root-order"],
)
async def test_a_blur_order_that_cannot_be_read_is_unknown_and_worst_case(typed, sig_type):
    result = await _analyze(typed)
    assert result.data["sig_type"] == sig_type
    assert result.score == 50
    assert result.data["status"] == "unknown"
    assert result.data["coverage"]["typed_data"] is False


@pytest.mark.asyncio
async def test_an_order_named_order_outside_blur_is_not_read_as_blurs():
    typed = {**_blur(_blur_order(price="0")), "domain": {"name": "Another Exchange"}}
    result = await _analyze(typed)
    assert result.data["sig_type"] == "Order"
    assert result.score == 0


@pytest.mark.asyncio
async def test_the_api_answers_a_bulk_order_paying_another_address_as_high_risk(consumer_api):  # noqa: F811
    api, _ = consumer_api
    tree = [[LISTING, LISTING], [_order([_nft()], [_pay(ATTACKER)]), EMPTY]]
    req = api.FirewallRequest(
        to="", sender=SIGNER, signMethod="eth_signTypedData_v4", typedData=_bulk(tree, 2), chainId=1
    )
    response = await api._build_signature_only_response(req)
    assert response["classification"] == "HIGH_RISK"
    assert response["status"] == "ok"
    assert any("goes to other addresses" in signal for signal in response["danger_signals"])


@pytest.mark.asyncio
async def test_the_api_answers_a_blur_bulk_listing_as_unknown(consumer_api):  # noqa: F811
    api, _ = consumer_api
    typed = _blur({"root": "0x" + "1" * 64}, "Root", {"Root": _struct(("root", "bytes32"))})
    req = api.FirewallRequest(
        to="", sender=SIGNER, signMethod="eth_signTypedData_v4", typedData=typed, chainId=1
    )
    response = await api._build_signature_only_response(req)
    assert_unknown_response(response)
