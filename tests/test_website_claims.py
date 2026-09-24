"""The public website must not drift from the code it describes.

These checks tie the landing page, the about page, the dashboard and the extension's welcome page to
the facts they state (chain counts, tool counts, score bands, chain tables, roadmap status) and fail
when a source changes without the site, or when the committed builds fall behind their sources.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LANDING_SRC = ROOT / "landing-src"
COMPONENTS = LANDING_SRC / "src" / "components"
DASHBOARD_SRC = ROOT / "dashboard" / "index.src.html"
WELCOME = ROOT / "extension" / "welcome.html"


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
        for match in re.finditer(r"\b(\d+)[ -](?:chains?|blockchains)\b", text):
            # "N chains with a public mempool" and "N-chain mempool" count mempool chains; every
            # other count is scan chains.
            following = text[match.end() : match.end() + 40].lstrip().lower()
            mempool = following.startswith(("with a public", "mempool"))
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
    from mcp_server.resources import RESOURCE_DEFINITIONS, RESOURCE_TEMPLATE_DEFINITIONS
    from mcp_server.tools import TOOL_DEFINITIONS

    agent = read(COMPONENTS / "AgentSecurity.tsx")
    roadmap = read(COMPONENTS / "Roadmap.tsx")
    # MCP lists parameterised resources as templates; the site counts both as resources.
    resources = len(RESOURCE_DEFINITIONS) + len(RESOURCE_TEMPLATE_DEFINITIONS)
    assert f"{len(TOOL_DEFINITIONS)} security tools" in agent
    assert f"{resources} threat resources" in agent
    assert f"{len(PROMPT_DEFINITIONS)} analysis prompts" in agent
    assert (
        f"MCP Server ({len(TOOL_DEFINITIONS)} tools, {resources} resources"
        in roadmap
    )

    commands = len(re.findall(r'CommandHandler\("', read(ROOT / "bot.py")))
    assert f"Telegram bot ({commands} commands)" in roadmap


def test_roadmap_marks_nothing_complete_that_is_still_open():
    roadmap = read(COMPONENTS / "Roadmap.tsx")
    done = [
        item
        for items in re.findall(r'status: "done",\s*items: \[(.*?)\]', roadmap, re.DOTALL)
        for item in re.findall(r'"([^"]+)"', items)
    ]
    still_open = re.findall(r"^- \[ \] \*\*([^*]+)\*\*", read(ROOT / "ROADMAP.md"), re.MULTILINE)
    assert done and still_open
    for item in done:
        assert not re.search(r"\b(?:deploying|proposed|planned|upcoming|in progress)\b", item, re.I)
        for title in still_open:
            assert title.lower() not in item.lower(), (
                f"Roadmap.tsx marks {item!r} Complete; ROADMAP.md leaves {title!r} open"
            )


def welcome_text() -> str:
    """The visible text of the extension's welcome page, without its styles and scripts."""
    html = re.sub(r"<(style|script)\b.*?</\1>", " ", read(WELCOME), flags=re.DOTALL)
    return re.sub(r"<[^>]+>", " ", html)


def test_welcome_page_does_not_claim_the_extension_blocks():
    # The extension warns and lets the user decide. It refuses a request on its own only when the request
    # times out or the wallet chain is unknown or changes (extension/inject.js), which the page may say.
    text = " ".join(welcome_text().split()).lower()
    overclaims = ("stopped in their tracks", "blocks the transaction", "blocks transactions", "are blocked")
    claims = [phrase for phrase in overclaims if phrase in text]
    assert not claims, f"welcome.html claims the extension blocks transactions: {claims}"


def extension_chain_ids() -> set:
    """The chains the extension names in popup.js CHAIN_NAMES.

    inject.js and background.js keep no chain list: they pass any wallet chain id to /api/firewall.
    """
    table = re.search(r"const CHAIN_NAMES = \{([^}]*)\}", read(ROOT / "extension" / "popup.js")).group(1)
    return {int(chain_id) for chain_id in re.findall(r"\b(\d+):", table)}


def test_welcome_page_chain_count_matches_the_extension():
    chains = extension_chain_ids()
    assert chains == set(chain_info()), "popup.js CHAIN_NAMES and the API chain registry disagree"
    counts = re.findall(r"\b(\d+)\s+(?:more\s+)?(?:EVM\s+)?(?:chains?|networks)\b", welcome_text())
    assert counts, "welcome.html should state how many chains it supports"
    assert {int(count) for count in counts} == {len(chains)}


def test_welcome_page_names_every_extension_chain():
    subtitle = re.search(r'<p class="subtitle">(.*?)</p>', read(WELCOME), re.DOTALL).group(1)
    listed = re.split(r",\s*|\s+and\s+", subtitle.split(":", 1)[1].strip().rstrip("."))
    aliases = {"BNB Chain": "BSC"}
    names = {chain_info()[chain_id]["name"] for chain_id in extension_chain_ids()}
    assert len(listed) == len(names)
    assert {aliases.get(name, name) for name in listed} == names


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
    from core.calibration import CalibrationConfig

    bands = _risk_bands()
    assert set(bands) == {"SAFE", "CAUTION", "HIGH_RISK", "BLOCK_RECOMMENDED"}
    # The risk engine's default level thresholds must agree with the bands the site states;
    # calibration can only make the shown verdict stricter (a MEDIUM level is never SAFE).
    defaults = CalibrationConfig()
    assert defaults.medium_threshold == bands["CAUTION"][0]
    assert defaults.high_threshold == bands["BLOCK_RECOMMENDED"][0]

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
    entities = []
    for block in re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.DOTALL):
        data = json.loads(block)
        if data["@type"] == "FAQPage":
            entities += data["mainEntity"]
    assert entities, "index.html should carry FAQ structured data"
    for entity in entities:
        assert json.dumps(entity["name"], ensure_ascii=False) in faq_source
        assert json.dumps(entity["acceptedAnswer"]["text"], ensure_ascii=False) in faq_source


@pytest.mark.parametrize(
    "name", ["about.html", "privacy.html", "terms.html", "sitemap.xml", ".well-known/security.txt"]
)
def test_built_landing_copies_the_current_public_files(name):
    source = read(LANDING_SRC / "public" / name).replace("\r\n", "\n")
    built = read(ROOT / "landing" / name).replace("\r\n", "\n")
    assert built == source, f"landing/{name} is stale: run `npm run build` in landing-src"


def test_built_landing_bundle_contains_the_current_faq():
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    faq = read(COMPONENTS / "FAQ.tsx")
    questions = re.findall(r'^\s+q: "([^"]+)",', faq, re.MULTILINE)
    answers = re.findall(r'^\s+a: "([^"]+)",', faq, re.MULTILINE)
    assert bundle and questions and len(answers) == len(questions)
    for question in questions:
        assert question in bundle, f"landing bundle is stale: missing FAQ question {question!r}"
    for answer in answers:
        assert answer in bundle, f"landing bundle is stale: missing FAQ answer {answer[:60]!r}"
    # Every mempool chain count the built site shows (FAQ, chains section, roadmap) is the monitor's.
    stated = re.findall(r"\b(\d+)[ -]chains?\s+(?:with a public\s+mempool|mempool)", bundle)
    assert stated and {int(n) for n in stated} == {mempool_chain_count()}


def test_built_dashboard_contains_the_current_source_strings():
    built = read(ROOT / "dashboard" / "index.html")
    labels = re.findall(r"label:'([^']+)'", read(DASHBOARD_SRC))
    assert labels
    for label in labels:
        assert label in built, (
            f"dashboard/index.html is stale: missing {label!r}; run the dashboard build"
        )
