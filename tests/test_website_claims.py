"""The public website must not drift from the code it describes.

These checks tie the landing page, the about page, the dashboard and the extension's welcome page to
the facts they state (chain counts, tool counts, score bands, chain tables, per-chain coverage) and
fail when a source changes without the site, or when the committed builds fall behind their sources.
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


def test_chains_section_coverage_matches_the_code():
    from adapters.arbitrum import ArbitrumAdapter
    from adapters.base_chain import BaseChainAdapter
    from adapters.bsc import BscAdapter
    from adapters.eth import EthAdapter
    from adapters.opbnb import OpBNBAdapter
    from adapters.optimism import OptimismAdapter
    from adapters.polygon import PolygonAdapter
    from adapters.robinhood import RobinhoodAdapter
    from services.launch_discovery import CHAIN_ID as LAUNCH_CHAIN_ID
    from services.mempool_service import supports_pending_transactions

    adapters = {
        adapter.chain_id: adapter
        for adapter in (
            cls(rpc_url="https://rpc.invalid")
            for cls in (
                ArbitrumAdapter,
                BaseChainAdapter,
                BscAdapter,
                EthAdapter,
                OpBNBAdapter,
                OptimismAdapter,
                PolygonAdapter,
                RobinhoodAdapter,
            )
        )
    }
    assert set(adapters) == set(chain_info())
    aliases = {"BSC": "BNB Chain"}
    ids = {aliases.get(info["name"], info["name"]): chain_id for chain_id, info in chain_info().items()}
    rows = re.findall(
        r'name: "([^"]+)",\s*simulation: ("[^"]+"|null),\s*mempool: (true|false),\s*launches: (true|false),',
        read(COMPONENTS / "Chains.tsx"),
    )
    # Web3Client.supports_honeypot_simulation reads the same flag; without honeypot.is or it, no
    # sell is simulated (adapters/evm_base.py HONEYPOT_IS_UNSUPPORTED).
    simulator = {
        chain_id: "ShieldBot"
        if getattr(adapter, "supports_honeypot_simulation", False) is True
        else "honeypot.is"
        if adapter._honeypot_chain_id is not None
        else None
        for chain_id, adapter in adapters.items()
    }
    assert len(rows) == len(chain_info())
    for name, simulation, mempool, launches in rows:
        assert json.loads(simulation) == simulator[ids[name]], name
        assert (mempool == "true") == supports_pending_transactions(ids[name]), name
        assert (launches == "true") == (ids[name] == LAUNCH_CHAIN_ID), name

    def listed(provider):
        names = [name for name, chain_id in ids.items() if simulator[chain_id] == provider]
        return " and ".join([", ".join(names[:-1]), names[-1]]) if len(names) > 1 else names[0]

    prose = " ".join(read(COMPONENTS / "Chains.tsx").split())
    assert (
        f"honeypot.is simulates a buy and a sell on {listed('honeypot.is')}, and ShieldBot runs its "
        f"own on supported {listed('ShieldBot')} pool routes."
    ) in prose


def test_mcp_counts_match_the_code():
    from mcp_server.prompts import PROMPT_DEFINITIONS
    from mcp_server.resources import RESOURCE_DEFINITIONS, RESOURCE_TEMPLATE_DEFINITIONS
    from mcp_server.tools import TOOL_DEFINITIONS

    agent = read(COMPONENTS / "AgentSecurity.tsx")
    # MCP lists parameterised resources as templates; the site counts both as resources.
    resources = len(RESOURCE_DEFINITIONS) + len(RESOURCE_TEMPLATE_DEFINITIONS)
    assert f"{len(TOOL_DEFINITIONS)} security tools" in agent
    assert f"{resources} threat resources" in agent
    assert f"{len(PROMPT_DEFINITIONS)} analysis prompts" in agent


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
    subtitle = re.search(r'<p class="subtitle"[^>]*>(.*?)</p>', read(WELCOME), re.DOTALL).group(1)
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


def test_dashboard_names_the_url_the_site_sends_visitors_to_as_canonical():
    nginx = read(ROOT / "deploy" / "nginx-shieldbotsecurity.conf")
    target = re.search(r"location = /dashboard \{\s*return 301 (\S+);", nginx).group(1)
    for page in (DASHBOARD_SRC, ROOT / "dashboard" / "index.html"):
        html = read(page)
        assert f'<link rel="canonical" href="{target}" />' in html, page.name
        assert '<meta name="description" content="' in html, page.name


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


def test_hero_image_describes_its_recorded_api_reply():
    # landing-src/scripts/capture-hero-overlay.py renders the extension's overlay from this reply.
    reply = json.loads(read(LANDING_SRC / "scripts" / "hero-overlay-response.json"))
    hero = read(COMPONENTS / "Hero.tsx")
    messages = json.loads(read(ROOT / "extension" / "locales" / "en" / "messages.json"))
    # The overlay's rules in extension/content.js, applied below to the recorded reply.
    content = " ".join(read(ROOT / "extension" / "content.js").split())
    for rule in (
        'const incomplete = result.status !== "ok" || result.partial === true || '
        'result.risk_level === "UNKNOWN" || result.classification === "UNKNOWN" || '
        "!Number.isFinite(result.risk_score) || "
        "Object.values(result.coverage || {}).some(value => Number(value) < 1);",
        "const classification = incomplete && "
        '!["HIGH_RISK", "BLOCK_RECOMMENDED"].includes(result.classification) '
        '? "UNKNOWN" : result.classification || "CAUTION";',
        'const scoreDisplay = incomplete ? "Unknown (incomplete provider coverage)" : '
        '`${_t("overlaySafety")} ${100 - result.risk_score}/100`;',
        '${escapeHtml(label)}${classification === "UNKNOWN" ? "" : ` &mdash; ${escapeHtml(scoreDisplay)}`}',
        'return Object.values(result.coverage_reasons || {}).filter(Boolean).join("; ") || '
        '_t("unknownNoReason");',
    ):
        assert rule in content, rule

    score = reply.get("risk_score")
    incomplete = (
        reply["status"] != "ok"
        or reply.get("partial") is True
        or reply.get("risk_level") == "UNKNOWN"
        or reply.get("classification") == "UNKNOWN"
        or type(score) not in (int, float)
        or any(float(value) < 1 for value in (reply.get("coverage") or {}).values())
    )
    shown = reply.get("classification") or "CAUTION"
    if incomplete and shown not in ("HIGH_RISK", "BLOCK_RECOMMENDED"):
        shown = "UNKNOWN"
    label = messages[
        {
            "BLOCK_RECOMMENDED": "classBlock",
            "HIGH_RISK": "classHighRisk",
            "CAUTION": "classCaution",
            "SAFE": "classSafe",
            "UNKNOWN": "classUnknown",
        }[shown]
    ]
    if shown != "UNKNOWN":
        score_display = (
            "Unknown (incomplete provider coverage)"
            if incomplete
            else f"{messages['overlaySafety']} {100 - score}/100"
        )
        label = f"{label} — {score_display}"
    assert f"The verdict badge reads {label}" in hero
    if incomplete:
        reasons = "; ".join(filter(None, reply["coverage_reasons"].values()))
        assert f"{messages['unknownWhy']} {reasons or messages['unknownNoReason']}" in hero
    for name in ("hero-overlay.webp", "hero-overlay-mobile.webp"):
        assert f'"/{name}"' in hero
        source = (LANDING_SRC / "public" / name).read_bytes()
        assert (ROOT / "landing" / name).read_bytes() == source, f"landing/{name} is stale"


@pytest.mark.parametrize(
    "name",
    [
        "about.html",
        "privacy.html",
        "terms.html",
        "security.html",
        "sitemap.xml",
        ".well-known/security.txt",
        "js/plausible-init.js",
    ],
)
def test_built_landing_copies_the_current_public_files(name):
    source = read(LANDING_SRC / "public" / name).replace("\r\n", "\n")
    built = read(ROOT / "landing" / name).replace("\r\n", "\n")
    assert built == source, f"landing/{name} is stale: run `npm run build` in landing-src"


ANALYTICS_TAGS = ('<script src="/js/plausible-init.js"></script>', '<script async src="/js/script.js"></script>')


@pytest.mark.parametrize("page", ["index.html", "about.html", "privacy.html", "security.html", "terms.html"])
def test_every_page_counts_visits_through_this_domain(page):
    html = read(ROOT / "landing" / page)
    init, script = (html.index(tag) for tag in ANALYTICS_TAGS)
    assert init < script, f"{page}: the init file must run before the Plausible script"


def test_analytics_are_proxied_so_the_content_security_policy_stays_self():
    conf = read(ROOT / "deploy" / "nginx-shieldbotsecurity-new.conf")
    assert "location = /js/script.js" in conf and "location = /stats/event" in conf
    assert "plausible.io" not in re.search(r'Content-Security-Policy "([^"]*)"', conf).group(1)
    assert 'endpoint: "/stats/event"' in read(LANDING_SRC / "public" / "js" / "plausible-init.js")


def test_privacy_policy_names_the_analytics():
    assert "Plausible Analytics" in read(LANDING_SRC / "public" / "privacy.html")


def test_security_policy_is_published_linked_and_listed():
    security_txt = read(LANDING_SRC / "public" / ".well-known" / "security.txt")
    policy = re.search(r"^Policy: https://shieldbotsecurity\.online/(\S+)$", security_txt, re.MULTILINE)
    assert policy, "security.txt should name the security policy page"
    page = policy.group(1)
    assert (LANDING_SRC / "public" / page).is_file()
    assert f'href="/{page}"' in read(COMPONENTS / "Footer.tsx")
    assert f"<loc>https://shieldbotsecurity.online/{page}</loc>" in read(LANDING_SRC / "public" / "sitemap.xml")


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
