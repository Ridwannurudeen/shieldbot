"""The extension's and the dashboard's chain tables must not drift from utils/chain_info.py.

tests/test_website_claims.py and tests/test_extension_popup.py already check that these tables name
every chain; this module checks they name no other chain, keep their order, and label each chain
with CHAIN_INFO's name or with the short label pinned here. The surfaces abbreviate on purpose
(a selector has little room), so a label that differs from CHAIN_INFO's name is listed rather than
forced to match. The dashboard is checked in its source and in the built page the API serves.
"""

import re
from pathlib import Path

import pytest

from utils.chain_info import CHAIN_INFO

ROOT = Path(__file__).resolve().parent.parent
POPUP = ROOT / "extension" / "popup.js"
SIDEPANEL = ROOT / "extension" / "sidepanel.html"
DASHBOARDS = [ROOT / "dashboard" / "index.src.html", ROOT / "dashboard" / "index.html"]
DASHBOARD_FILTER_ORDER = [1, 56, 8453, 42161, 137, 10, 204, 4663]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def labelled(short_labels: dict) -> dict:
    """CHAIN_INFO's names, with the chains a surface labels differently replaced by their label."""
    return {chain_id: short_labels.get(chain_id, info["name"]) for chain_id, info in CHAIN_INFO.items()}


def js_table(text: str, name: str) -> dict:
    """A `const NAME = { id: 'value', ... }` table; an entry of any other shape fails."""
    body = re.search(rf"const {name}\s*=\s*\{{([^}}]*)\}}", text).group(1)
    entries = [entry for entry in body.split(",") if entry.strip()]
    pairs = [re.fullmatch(r"\s*(\d+):\s*([\"'])([^\"']*)\2\s*", entry) for entry in entries]
    unread = [entry.strip() for entry, pair in zip(entries, pairs) if pair is None]
    assert not unread, f"{name} has entries this test cannot read: {unread}"
    chain_ids = [int(pair.group(1)) for pair in pairs]
    assert len(chain_ids) == len(set(chain_ids)), f"{name} repeats a chain"
    return {int(pair.group(1)): pair.group(3) for pair in pairs}


def chain_filters(text: str) -> list:
    """The dashboard's CHAIN_FILTERS as (label, val) pairs in order; an entry of any other shape fails."""
    body = re.search(r"const CHAIN_FILTERS = \[(.*?)\];", text, re.S).group(1)
    entries = re.findall(r"\{(.*?)\}", body, re.S)
    assert len(entries) == body.count("{"), "CHAIN_FILTERS has an entry this test cannot read"
    filters = [re.fullmatch(r"\s*label:\s*'([^']+)',\s*val:\s*'(\d*)'\s*", entry) for entry in entries]
    unread = [entry.strip() for entry, item in zip(entries, filters) if item is None]
    assert not unread, f"CHAIN_FILTERS has entries this test cannot read: {unread}"
    return [item.groups() for item in filters]


def sidepanel_options() -> list:
    select = re.search(r'<select id="chainSelect"[^>]*>(.*?)</select>', read(SIDEPANEL), re.S).group(1)
    return [(int(chain_id), label) for chain_id, label in re.findall(r'<option value="(\d+)">([^<]*)</option>', select)]


def check_dashboard_chain_tables(dashboard: str):
    assert js_table(dashboard, "CHAIN_NAMES") == labelled(
        {56: "BNB", 1: "ETH", 42161: "ARB", 10: "OP", 4663: "Robinhood"}
    )
    assert set(js_table(dashboard, "CHAIN_COLORS")) == set(CHAIN_INFO)
    assert js_table(dashboard, "EXPLORERS") == {
        chain_id: info["explorer_url"] for chain_id, info in CHAIN_INFO.items()
    }


def check_dashboard_chain_filter(dashboard: str):
    filters = chain_filters(dashboard)
    assert filters[0] == ("All Chains", "")
    chains = [(int(chain_id), label) for label, chain_id in filters[1:]]
    assert [chain_id for chain_id, _ in chains] == DASHBOARD_FILTER_ORDER
    assert set(DASHBOARD_FILTER_ORDER) == set(CHAIN_INFO)
    assert dict(chains) == labelled({56: "BNB", 1: "ETH", 4663: "Robinhood"})


def test_popup_chain_names_match_the_registry():
    assert js_table(read(POPUP), "CHAIN_NAMES") == labelled({1: "ETH"})


def test_popup_health_chain_order_lists_every_chain_in_the_side_panel_order():
    order = re.search(r"const HEALTH_CHAIN_ORDER = \[([\d,\s]+)\];", read(POPUP)).group(1)
    chain_ids = [int(chain_id) for chain_id in order.split(",")]
    assert len(chain_ids) == len(set(chain_ids))
    assert set(chain_ids) == set(CHAIN_INFO)
    # popup.js promises its selector matches the side panel's.
    assert chain_ids == [chain_id for chain_id, _ in sidepanel_options()]


def test_side_panel_chain_selector_labels_match_the_registry():
    options = sidepanel_options()
    assert len(options) == len(CHAIN_INFO)
    assert dict(options) == labelled({1: "ETH", 42161: "Arb", 137: "Poly", 10: "OP", 4663: "Robinhood"})


@pytest.mark.parametrize("page", DASHBOARDS, ids=lambda page: page.name)
def test_dashboard_chain_tables_match_the_registry(page):
    check_dashboard_chain_tables(read(page))


@pytest.mark.parametrize("page", DASHBOARDS, ids=lambda page: page.name)
def test_dashboard_chain_filter_matches_the_registry(page):
    check_dashboard_chain_filter(read(page))


@pytest.mark.parametrize("page", DASHBOARDS, ids=lambda page: page.name)
def test_dashboard_checks_reject_an_entry_they_cannot_read(page):
    dashboard = read(page)
    names = re.search(r"const CHAIN_NAMES\s*=\s*\{", dashboard)
    quoted_key = dashboard[: names.end()] + "\"999\": 'Other', " + dashboard[names.end() :]
    with pytest.raises(AssertionError, match="CHAIN_NAMES has entries this test cannot read"):
        check_dashboard_chain_tables(quoted_key)
    filters = re.search(r"const CHAIN_FILTERS = \[", dashboard)
    odd_filter = dashboard[: filters.end()] + "{ label:'Other', val:999 }, " + dashboard[filters.end() :]
    with pytest.raises(AssertionError, match="CHAIN_FILTERS has entries this test cannot read"):
        check_dashboard_chain_filter(odd_filter)


@pytest.mark.parametrize("page", DASHBOARDS, ids=lambda page: page.name)
def test_dashboard_filter_check_rejects_a_reordered_filter(page):
    dashboard = read(page)
    eth = re.search(r"\{\s*label:\s*'ETH',\s*val:\s*'1'\s*\}", dashboard).group(0)
    bnb = re.search(r"\{\s*label:\s*'BNB',\s*val:\s*'56'\s*\}", dashboard).group(0)
    swapped = dashboard.replace(eth, "\0").replace(bnb, eth).replace("\0", bnb)
    with pytest.raises(AssertionError):
        check_dashboard_chain_filter(swapped)
