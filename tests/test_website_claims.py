"""The public website must not drift from the code it describes.

These checks tie the landing page, the about page and the dashboard to the facts they state (chain
counts, tool counts, score bands, chain tables) and fail when a source changes without the site, or
when the committed builds fall behind their sources.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LANDING_SRC = ROOT / "landing-src"
COMPONENTS = LANDING_SRC / "src" / "components"
DASHBOARD_SRC = ROOT / "dashboard" / "index.src.html"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def landing_texts() -> dict:
    files = list(COMPONENTS.glob("*.tsx")) + [
        LANDING_SRC / "index.html",
        LANDING_SRC / "public" / "about.html",
        LANDING_SRC / "scripts" / "gen-og-image.mjs",
    ]
    return {path.name: read(path) for path in files}


def chain_info():
    from utils.chain_info import CHAIN_INFO

    return CHAIN_INFO


def mempool_chain_count() -> int:
    from services.mempool_service import supports_pending_transactions

    return sum(1 for chain_id in chain_info() if supports_pending_transactions(chain_id))


def test_every_chain_count_on_the_site_matches_the_registry():
    statements = 0
    for name, text in landing_texts().items():
        for match in re.finditer(r"\b(\d+) (?:chains|blockchains)\b", text):
            # "N chains with a public mempool" counts mempool chains; every other count is scan chains.
            mempool = "public" in text[match.end() : match.end() + 20]
            expected = mempool_chain_count() if mempool else len(chain_info())
            assert int(match.group(1)) == expected, (
                f"{name}: {match.group(0)!r}, expected {expected}"
            )
            statements += 1
    assert statements, "the site should state how many chains it supports"
    assert "SUPPORTED_CHAINS = %d;" % len(chain_info()) in read(COMPONENTS / "LiveStats.tsx")


def test_mempool_chain_count_matches_the_monitor():
    faq = read(COMPONENTS / "FAQ.tsx") + read(COMPONENTS / "Chains.tsx")
    stated = {int(n) for n in re.findall(r"(\d+)\s+chains with a public\s+mempool", faq)}
    assert stated == {mempool_chain_count()}


def test_chains_section_lists_every_scan_chain():
    names = re.findall(r'^\s+name: "([^"]+)",', read(COMPONENTS / "Chains.tsx"), re.MULTILINE)
    assert len(names) == len(chain_info())
    assert "Robinhood Chain" in names


def test_mcp_and_bot_counts_match_the_code():
    from mcp_server.prompts import PROMPT_DEFINITIONS
    from mcp_server.resources import RESOURCE_DEFINITIONS
    from mcp_server.tools import TOOL_DEFINITIONS

    agent = read(COMPONENTS / "AgentSecurity.tsx")
    roadmap = read(COMPONENTS / "Roadmap.tsx")
    assert f"{len(TOOL_DEFINITIONS)} security tools" in agent
    assert f"{len(RESOURCE_DEFINITIONS)} threat resources" in agent
    assert f"{len(PROMPT_DEFINITIONS)} analysis prompts" in agent
    assert (
        f"MCP Server ({len(TOOL_DEFINITIONS)} tools, {len(RESOURCE_DEFINITIONS)} resources"
        in roadmap
    )

    commands = len(re.findall(r'CommandHandler\("', read(ROOT / "bot.py")))
    assert f"Telegram bot ({commands} commands)" in roadmap


def _risk_bands() -> dict:
    """Probe the classifier the firewall uses for a complete scan: classification -> (min, max) risk."""
    from core.extension_formatter import format_extension_alert

    bands = {}
    for risk in range(101):
        alert = format_extension_alert(
            {
                "rug_probability": risk,
                "risk_level": "LOW",
                "status": "ok",
                "coverage": {"structural": 1},
            }
        )
        low, high = bands.get(alert["risk_classification"], (risk, risk))
        bands[alert["risk_classification"]] = (min(low, risk), max(high, risk))
    return bands


def test_score_bands_on_the_site_match_the_classifier():
    bands = _risk_bands()
    assert set(bands) == {"SAFE", "CAUTION", "HIGH_RISK", "BLOCK_RECOMMENDED"}

    about = read(LANDING_SRC / "public" / "about.html")
    for name, badge in (
        ("SAFE", "safe"),
        ("CAUTION", "caution"),
        ("HIGH_RISK", "high"),
        ("BLOCK_RECOMMENDED", "block"),
    ):
        low, high = bands[name]
        assert f'<td>{low} – {high}</td><td><span class="badge {badge}">' in about, name

    safety = {name: (100 - high, 100 - low) for name, (low, high) in bands.items()}
    sentence = (
        f"{safety['SAFE'][0]} or above is SAFE, "
        f"{safety['CAUTION'][0]} to {safety['CAUTION'][1]} is CAUTION, "
        f"{safety['HIGH_RISK'][0]} to {safety['HIGH_RISK'][1]} is HIGH RISK, "
        f"and {safety['BLOCK_RECOMMENDED'][1]} or below is BLOCK RECOMMENDED."
    )
    assert sentence in read(COMPONENTS / "FAQ.tsx")
    assert sentence in read(LANDING_SRC / "index.html")


def test_no_placeholder_numbers_stand_in_for_live_data():
    assert "FALLBACK" not in read(COMPONENTS / "LiveStats.tsx")
    dashboard = read(DASHBOARD_SRC)
    for placeholder in ("SEED_KPI", "FALLBACK_CHAIN_DATA", "* 180", "* 0.08"):
        assert placeholder not in dashboard, placeholder


def test_dashboard_chain_tables_cover_every_scan_chain():
    dashboard = read(DASHBOARD_SRC)
    for chain_id, info in chain_info().items():
        for table in ("CHAIN_NAMES", "CHAIN_COLORS"):
            row = re.search(rf"const {table}\s*=\s*\{{([^}}]*)\}}", dashboard).group(1)
            assert re.search(rf"\b{chain_id}:", row), f"{table} is missing chain {chain_id}"
        assert f"{chain_id}:'{info['explorer_url']}'" in dashboard, f"explorer for chain {chain_id}"
        assert f"val:'{chain_id}'" in dashboard, f"chain filter for {chain_id}"


def test_structured_data_is_valid_and_matches_the_visible_faq():
    html = read(LANDING_SRC / "index.html")
    faq_source = read(COMPONENTS / "FAQ.tsx")
    for block in re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.DOTALL):
        data = json.loads(block)
        for entity in data.get("mainEntity", []):
            assert json.dumps(entity["name"], ensure_ascii=False) in faq_source
            assert json.dumps(entity["acceptedAnswer"]["text"], ensure_ascii=False) in faq_source


@pytest.mark.parametrize(
    "name", ["about.html", "privacy.html", "sitemap.xml", ".well-known/security.txt"]
)
def test_built_landing_copies_the_current_public_files(name):
    source = read(LANDING_SRC / "public" / name).replace("\r\n", "\n")
    built = read(ROOT / "landing" / name).replace("\r\n", "\n")
    assert built == source, f"landing/{name} is stale: run `npm run build` in landing-src"


def test_built_landing_bundle_contains_the_current_faq():
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    for question in re.findall(r'^\s+q: "([^"]+)",', read(COMPONENTS / "FAQ.tsx"), re.MULTILINE):
        assert question in bundle, f"landing bundle is stale: missing FAQ question {question!r}"


def test_built_dashboard_contains_the_current_source_strings():
    built = read(ROOT / "dashboard" / "index.html")
    labels = re.findall(r"label:'([^']+)'", read(DASHBOARD_SRC))
    assert labels
    for label in labels:
        assert label in built, (
            f"dashboard/index.html is stale: missing {label!r}; run the dashboard build"
        )
