"""The extension's and the dashboard's chain tables must not drift from utils/chain_info.py.

tests/test_website_claims.py and tests/test_extension_popup.py already check that these tables name
every chain; this module checks they name no other chain, keep their order, and label each chain
with CHAIN_INFO's name or with the short label pinned here. The surfaces abbreviate on purpose
(a selector has little room), so a label that differs from CHAIN_INFO's name is listed rather than
forced to match.
"""

import re
from pathlib import Path

from utils.chain_info import CHAIN_INFO

ROOT = Path(__file__).resolve().parent.parent
POPUP = ROOT / "extension" / "popup.js"
SIDEPANEL = ROOT / "extension" / "sidepanel.html"
DASHBOARD_SRC = ROOT / "dashboard" / "index.src.html"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def labelled(short_labels: dict) -> dict:
    """CHAIN_INFO's names, with the chains a surface labels differently replaced by their label."""
    return {chain_id: short_labels.get(chain_id, info["name"]) for chain_id, info in CHAIN_INFO.items()}


def js_table(text: str, name: str) -> dict:
    body = re.search(rf"const {name}\s*=\s*\{{([^}}]*)\}}", text).group(1)
    pairs = re.findall(r"\b(\d+):\s*[\"']([^\"']*)[\"']", body)
    assert len(pairs) == len({chain_id for chain_id, _ in pairs}), f"{name} repeats a chain"
    return {int(chain_id): value for chain_id, value in pairs}


def sidepanel_options() -> list:
    select = re.search(r'<select id="chainSelect"[^>]*>(.*?)</select>', read(SIDEPANEL), re.S).group(1)
    return [(int(chain_id), label) for chain_id, label in re.findall(r'<option value="(\d+)">([^<]*)</option>', select)]


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


def test_dashboard_chain_tables_match_the_registry():
    dashboard = read(DASHBOARD_SRC)
    assert js_table(dashboard, "CHAIN_NAMES") == labelled(
        {56: "BNB", 1: "ETH", 42161: "ARB", 10: "OP", 4663: "Robinhood"}
    )
    assert set(js_table(dashboard, "CHAIN_COLORS")) == set(CHAIN_INFO)
    assert js_table(dashboard, "EXPLORERS") == {
        chain_id: info["explorer_url"] for chain_id, info in CHAIN_INFO.items()
    }


def test_dashboard_chain_filter_matches_the_registry():
    options = re.findall(r"\{ label:'([^']+)',\s*val:'(\d*)' \}", read(DASHBOARD_SRC))
    assert options[0] == ("All Chains", "")
    chains = [(int(chain_id), label) for label, chain_id in options[1:]]
    assert len(chains) == len(CHAIN_INFO)
    assert dict(chains) == labelled({56: "BNB", 1: "ETH", 4663: "Robinhood"})
