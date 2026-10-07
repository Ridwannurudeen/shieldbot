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
        COMPONENTS / "verdictScenes.ts",
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
        for match in re.finditer(r"\b(\d+)[ -](?:EVM\s+)?(?:chains?|blockchains)\b", text):
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
        # The site leads every chain list with Ethereum; the rest keep the registry's order.
        names = sorted(names, key=lambda name: name != "Ethereum")
        return " and ".join([", ".join(names[:-1]), names[-1]]) if len(names) > 1 else names[0]

    prose = " ".join(read(COMPONENTS / "Chains.tsx").split())
    assert (
        f"honeypot.is simulates a buy and a sell on {listed('honeypot.is')}, and ShieldBot runs its "
        f"own on supported {listed('ShieldBot')} pool routes."
    ) in prose


def test_arbitrum_simulation_scope_matches_the_code():
    # services/arbitrum_simulation.py simulates only pools pairing the token with WETH: V3 pools through
    # SwapRouter02 and the pairs of each V2 route. A token with no such pool gets no simulation.
    from adapters.arbitrum import WETH_ADDRESS
    from services.arbitrum_simulation import V2_ROUTES, WETH

    exchanges = {"v3": "Uniswap V3", "uniswap-v2": "Uniswap V2", "sushiswap-v2": "SushiSwap"}
    assert set(exchanges) == {"v3", *V2_ROUTES}, "the Arbitrum simulation routes changed: update the site"
    assert WETH == WETH_ADDRESS.lower()
    names = list(exchanges.values())
    scope = f"pools pairing the token with WETH on {', '.join(names[:-1])} or {names[-1]}"
    chains = " ".join(read(COMPONENTS / "Chains.tsx").split())
    for path in (COMPONENTS / "Chains.tsx", LANDING_SRC / "public" / "about.html", ROOT / "README.md"):
        assert scope in " ".join(read(path).split()), path.name
    assert re.search(r'name: "Arbitrum", [^}]*simulationScope: "Some WETH pools, see below",', chains)


def test_mcp_counts_match_the_code():
    from mcp_server.prompts import PROMPT_DEFINITIONS
    from mcp_server.resources import RESOURCE_DEFINITIONS, RESOURCE_TEMPLATE_DEFINITIONS
    from mcp_server.tools import TOOL_DEFINITIONS

    agent = " ".join(read(COMPONENTS / "AgentSecurity.tsx").split())
    # MCP lists parameterised resources as templates. The site names every resource, and every tool or
    # resource whose definition says it is not implemented as a stub, so a count never includes a stub
    # unsaid and only one resource is a threat feed.
    resources = [definition["name"] for definition in RESOURCE_DEFINITIONS + RESOURCE_TEMPLATE_DEFINITIONS]
    assert resources == ["Threat Feed", "Agent Health", "Wallet Guardian"], "the MCP resources changed: update the site"
    stubs = [
        definition["name"]
        for definition in TOOL_DEFINITIONS + RESOURCE_TEMPLATE_DEFINITIONS
        if "not implemented" in definition["description"].lower()
    ]
    assert stubs == ["check_approval_risk", "query_threat_graph", "Wallet Guardian"], "an MCP stub changed: update the site"
    assert "get_robinhood_launches" in [tool["name"] for tool in TOOL_DEFINITIONS]
    assert (
        f"with {len(TOOL_DEFINITIONS)} tools (one lists Robinhood Chain launches), a threat feed resource, "
        f"an agent health resource and {len(PROMPT_DEFINITIONS)} analysis prompts. The approval risk and threat "
        "graph tools and the wallet guardian resource are stubs that return Unknown."
    ) in agent
    assert "threat resources" not in agent


def test_the_site_says_the_robinhood_contracts_are_deployed():
    # docs/DEPLOYMENTS.md: the verdict registry, the freshness guard and the guarded transfer were deployed on
    # Robinhood Chain on 2026-09-27. No page, source or built, may still call that deployment in progress.
    deployments = read(ROOT / "docs" / "DEPLOYMENTS.md")
    for contract in ("ShieldBotVerdictRegistry", "ShieldBotVerdictGuard", "ShieldBotGuardedTransfer"):
        row = rf"^\| `{contract}` \| Robinhood Chain \(4663\) \| .* \| 2026-09-27 "
        assert re.search(row, deployments, re.MULTILINE), contract
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    pages = {**landing_texts(), "landing/index.html": read(ROOT / "landing" / "index.html"), "bundle": bundle}
    for name, text in pages.items():
        stale = re.search(r"deployment[^.]*in progress", " ".join(text.split()), re.IGNORECASE)
        assert not stale, f"{name}: {stale.group(0)!r}"
    for component in ("FAQ.tsx", "HowItWorks.tsx"):
        prose = " ".join(read(COMPONENTS / component).split())
        assert "deployed on Robinhood Chain on 27 September 2026" in prose, component


def test_the_site_shows_the_robinhood_contract_addresses():
    # docs/DEPLOYMENTS.md records the deployment. The on-chain section must show each contract's address as
    # recorded there, link its explorer page and its Sourcify match, and the built bundle must carry the addresses.
    deployments = read(ROOT / "docs" / "DEPLOYMENTS.md")
    section = read(COMPONENTS / "OnChain.tsx")
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    for contract in ("ShieldBotVerdictRegistry", "ShieldBotVerdictGuard", "ShieldBotGuardedTransfer"):
        row = re.search(
            rf"^\| `{contract}` \| Robinhood Chain \(4663\) \| \[`(0x[0-9a-fA-F]{{40}})`\]", deployments, re.MULTILINE
        )
        assert row, contract
        address = row.group(1)
        assert contract in section and address in section, contract
        assert f"https://robin.etherscan.io/address/{address}" in section, contract
        assert f"https://sourcify.dev/server/v2/contract/4663/{address}" in section, contract
        assert address in bundle, f"landing bundle is stale: missing {contract}"
    assert "Deployed 27 September 2026" in read(COMPONENTS / "ContractCard.tsx")
    assert "0x7578ca9e…f0c772a4" in section
    assert "judge guide" in section
    verification_code = re.search(r"const verificationCode = `([^`]*)`;", section).group(1)
    export_lines = [line for line in verification_code.splitlines() if line.startswith("export ")]
    assert len(export_lines) == 4
    assert "#" not in verification_code
    source = "\n".join(read(path) for path in (LANDING_SRC / "src").rglob("*") if path.is_file())
    assert not re.search(r"0x[0-9a-fA-F]{64}", source)
    assert not re.search(r"0x[0-9a-fA-F]{64}", bundle)


def test_dashboard_links_the_registry_recorded_in_deployments():
    # The Registry Records tile links the ShieldBotVerdictRegistry as docs/DEPLOYMENTS.md records it.
    deployments = read(ROOT / "docs" / "DEPLOYMENTS.md")
    row = re.search(
        r"^\| `ShieldBotVerdictRegistry` \| Robinhood Chain \(4663\) \| \[`(0x[0-9a-fA-F]{40})`\]",
        deployments,
        re.MULTILINE,
    )
    assert row
    assert f"const REGISTRY_ADDRESS = '{row.group(1)}';" in read(DASHBOARD_SRC)


def test_evidence_links_are_not_fine_print():
    assert "text-faint" not in read(COMPONENTS / "VerdictDemo.tsx")
    assert "min-h-[44px]" in read(COMPONENTS / "ContractCard.tsx")
    assert read(COMPONENTS / "ContractCard.tsx").count('name="external"') == 1
    assert "text-[13px] text-emerald" not in read(COMPONENTS / "OnChain.tsx")


def test_verdict_badge_steps_down_where_the_column_is_narrowest():
    badge = read(COMPONENTS / "Badge.tsx")
    assert "min-[1024px]:text-xl" in badge
    assert "min-[1100px]:text-2xl" in badge
    assert badge.index("sm:text-2xl") < badge.index("min-[1024px]:text-xl")


def test_exactly_one_theme_switch_outside_the_mobile_menu():
    # Two switches would drift apart when the window crosses the breakpoint after a click,
    # because the component holds its own state and the hidden one would then read a stale value.
    navbar = read(COMPONENTS / "Navbar.tsx")
    assert navbar.count("<ThemeToggle") == 1
    assert navbar.index("<ThemeToggle") < navbar.index('id="mobile-menu"')
    toggle = read(COMPONENTS / "ThemeToggle.tsx")
    assert 'role="switch"' in toggle
    assert 'aria-label="Dark theme"' in toggle
    assert "h-11 w-11" in toggle


def test_the_theme_default_is_dark_and_the_switch_suppresses_transitions():
    assert 'data-theme="dark"' in read(LANDING_SRC / "index.html")
    css = read(LANDING_SRC / "src" / "index.css")
    assert ":root[data-theme-switching]" in css
    assert ":root[data-theme=\"light\"]" in css


def welcome_text() -> str:
    """The visible text of the extension's welcome page, without its styles and scripts."""
    html = re.sub(r"<(style|script)\b.*?</\1>", " ", read(WELCOME), flags=re.DOTALL)
    return re.sub(r"<[^>]+>", " ", html)


def test_welcome_page_does_not_claim_the_extension_blocks():
    # The extension warns and lets the user decide. It refuses some requests on its own (a timeout, an unknown or
    # mismatched chain, a frame or popup the page can script, send and sendAsync; extension/inject.js), which the
    # page may say.
    text = " ".join(welcome_text().split()).lower()
    overclaims = ("stopped in their tracks", "blocks the transaction", "blocks transactions", "are blocked")
    claims = [phrase for phrase in overclaims if phrase in text]
    assert not claims, f"welcome.html claims the extension blocks transactions: {claims}"


def test_no_page_says_the_extension_refuses_only_in_some_cases():
    # inject.js refuses more than a timeout and a chain it cannot confirm: a request from a frame or popup the
    # page can script, a checked method sent through send or sendAsync, and a wallet_sendCalls batch with a call
    # on another chain. No page may present its list of refusals as the only ones.
    inject = read(ROOT / "extension" / "inject.js")
    for refusal in ('type: "SHIELDAI_UNCHECKABLE"', 'type: "SHIELDAI_LEGACY_REFUSED"', "const callsOnAnotherChain = "):
        assert refusal in inject, refusal
    for name, text in {**landing_texts(), "welcome.html": welcome_text()}.items():
        for sentence in re.split(r"(?<=[.;:])\s", " ".join(text.split())):
            if re.search(r"\brefuse[sd]?\b", sentence, re.IGNORECASE):
                assert not re.search(r"\bonly\b", sentence, re.IGNORECASE), f"{name}: {sentence!r}"
    faq = " ".join(read(COMPONENTS / "FAQ.tsx").split())
    for case in ("frame or popup the page can script", "send or sendAsync", "wallet_sendCalls", "Strict mode"):
        assert case in faq, case


def test_approval_scans_are_described_as_erc20_only():
    # Wallet Health and the Portfolio Guardian read approvals from services/rescue_service.py, which asks the
    # chain for the ERC-20 Approval event only: NFT approvals (ApprovalForAll) are never scanned.
    rescue = read(ROOT / "services" / "rescue_service.py")
    assert rescue.count("APPROVAL_FOR_ALL_TOPIC") == 1, "rescue_service.py now uses ApprovalForAll: update the site"
    statements = 0
    for name, text in landing_texts().items():
        prose = " ".join(text.split())
        for match in re.finditer(r"\btoken approvals\b", prose):
            assert prose[: match.start()].endswith("ERC-20 "), f"{name}: {prose[match.start() - 40 : match.end()]!r}"
            statements += 1
    assert statements, "the site should say which approvals it scans"


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
    nginx = read(ROOT / "deploy" / "nginx-shieldbotsecurity-new.conf")
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
    # landing-src/scripts/capture-hero-overlay.py renders the extension's overlay from this reply; the figure lives in HowItWorks.tsx.
    reply = json.loads(read(LANDING_SRC / "scripts" / "hero-overlay-response.json"))
    figure = read(COMPONENTS / "HowItWorks.tsx")
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
        'const scoreDisplay = incomplete ? _t("overlayIncompleteCoverage") : '
        '`${_t("overlaySafety")} ${100 - result.risk_score}/100`;',
        # A verdict the overlay raised itself (a look-alike or a delegation) shows no score, and an
        # incomplete one leaves the coverage text to the analysis line; the recorded reply is neither,
        # so its badge follows the API's verdict.
        '${escapeHtml(label)}${classification === "UNKNOWN" || classification !== verdict || incomplete ? "" : ` &mdash; ${escapeHtml(scoreDisplay)}`}',
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
    if shown != "UNKNOWN" and not incomplete:
        label = f"{label} — {messages['overlaySafety']} {100 - score}/100"
    assert f"The verdict badge reads {label}" in figure
    if reply.get("danger_signals"):
        assert f"The danger signals include {reply['danger_signals'][0]}" in figure
    if incomplete:
        reasons = "; ".join(filter(None, reply["coverage_reasons"].values()))
        assert f"{messages['unknownWhy']} {reasons or messages['unknownNoReason']}" in figure
    for name in ("hero-overlay.webp", "hero-overlay-mobile.webp"):
        assert f'"/{name}"' in figure
        source = (LANDING_SRC / "public" / name).read_bytes()
        assert (ROOT / "landing" / name).read_bytes() == source, f"landing/{name} is stale"


@pytest.mark.parametrize(
    "name",
    [
        "404.html",
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


LANDING_PAGES = [LANDING_SRC / "index.html", *sorted((LANDING_SRC / "public").glob("*.html"))]


@pytest.mark.parametrize("page", LANDING_PAGES, ids=lambda page: page.name)
def test_every_page_counts_visits_through_this_domain(page):
    for html in (read(page), read(ROOT / "landing" / page.name)):
        init, script = (html.find(tag) for tag in ANALYTICS_TAGS)
        assert init >= 0 and script >= 0, f"{page.name}: analytics tags missing"
        assert init < script, f"{page.name}: the init file must run before the Plausible script"


def test_analytics_are_proxied_so_the_content_security_policy_stays_self():
    conf = read(ROOT / "deploy" / "nginx-shieldbotsecurity-new.conf")
    for path, upstream in (("/js/script.js", "https://plausible.io/js/"), ("/stats/event", "https://plausible.io/api/event")):
        block = re.search(r"location = " + re.escape(path) + r" \{(.*?)\n    \}", conf, re.DOTALL).group(1)
        assert upstream in block and "proxy_pass" in block and "proxy_ssl_verify on" in block, path
    assert "plausible.io" not in re.search(r'Content-Security-Policy "([^"]*)"', conf).group(1)
    assert 'endpoint: "/stats/event"' in read(LANDING_SRC / "public" / "js" / "plausible-init.js")


def test_missing_pages_use_the_custom_404_page():
    conf = read(ROOT / "deploy" / "nginx-shieldbotsecurity-new.conf")
    first_server = re.search(r"(?ms)^server \{\n(.*?)^\}", conf).group(1)
    assert "error_page 404 /404.html;" in first_server
    assert re.search(r"location = /404\.html \{\s*internal;\s*\}", first_server)
    assert 'name="robots" content="noindex"' in read(LANDING_SRC / "public" / "404.html")
    assert "404.html" not in read(LANDING_SRC / "public" / "sitemap.xml")


def test_the_theme_restore_script_is_allowed_by_the_content_security_policy():
    # script-src is 'self' with no 'unsafe-inline' (deploy/nginx-shieldbotsecurity-new.conf), so the one
    # inline script, which restores a stored light theme before first paint, is allowed by its hash.
    import base64
    import hashlib
    conf = read(ROOT / "deploy" / "nginx-shieldbotsecurity-new.conf")
    csp = re.search(r'Content-Security-Policy "([^"]*)"', conf).group(1)
    script_src = re.search(r"script-src ([^;]*);", csp).group(1)
    assert "'unsafe-inline'" not in script_src
    # One hash in the policy, and one script shared by every page: a conf carrying a stale hash
    # beside the current one would otherwise let a mismatched built copy pass unnoticed.
    assert script_src.count("'sha256-") == 1, script_src
    pages = sorted({LANDING_SRC / "index.html", ROOT / "landing" / "index.html",
                    *(LANDING_SRC / "public").glob("*.html"), *(ROOT / "landing").glob("*.html")})
    digests = {}
    for page in pages:
        scripts = re.findall(r"<script>(.*?)</script>", read(page), re.DOTALL)
        assert len(scripts) == 1, f"{page}: expected exactly one inline script"
        assert '"shieldbot-theme"' in scripts[0], page
        digests[page] = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode()
    assert len(set(digests.values())) == 1, {str(k): v for k, v in digests.items()}
    assert f"'sha256-{next(iter(digests.values()))}'" in script_src, "the inline script hash is not in the CSP"


def test_privacy_policy_names_the_analytics_and_what_it_does_not_keep():
    html = read(LANDING_SRC / "public" / "privacy.html")
    assert "Plausible Analytics" in html
    assert "sets no cookies and stores no IP addresses" in html


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


@pytest.mark.parametrize("component", ["HowItWorks.tsx", "AgentSecurity.tsx"])
def test_built_landing_bundle_contains_the_current_feature_copy(component):
    # The claims these sections make (what the extension refuses, ERC-20 approvals only) ship only in the
    # built bundle, so an edit to the source without `npm run build` must fail here, not go out stale.
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    descriptions = re.findall(r'^\s+desc: "([^"]+)",', read(COMPONENTS / component), re.MULTILINE)
    assert bundle and descriptions
    for text in descriptions:
        # The source may write a character as a JavaScript escape (0\\u2013100), which the build decodes.
        text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), text)
        escaped = "".join(ch if ord(ch) < 128 else f"\\u{ord(ch):04x}" for ch in text)
        assert text in bundle or escaped in bundle, (
            f"landing bundle is stale: missing {component} text {text[:60]!r}"
        )


def test_no_unbacked_marketing_claims_anywhere_on_the_site():
    # The brand is honesty: no detection rate, insurance or coverage promise, user or loss count, audit claim,
    # or aggregate figure that no document in this repository backs, in any source page or in the built bundle.
    banned = [
        r"detection rate", r"\binsured\b", r"\binsurance\b", r"\$[\d,]+ in coverage", r"zero losses", r"\baudited\b",
        r"\btrustless\b", r"\bunhackable\b", r"enterprise-grade", r"\b\d[\d,]*\+? users\b", r"10 of 66",
        r"0 false positives", r"818 tokens", r"3 honeypots", r"496,628", r"2,091",
        r"records each Robinhood Chain verdict",
    ]
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    pages = {
        **landing_texts(),
        "landing/index.html": read(ROOT / "landing" / "index.html"),
        "landing-src/public/privacy.html": read(LANDING_SRC / "public" / "privacy.html"),
        "landing-src/public/terms.html": read(LANDING_SRC / "public" / "terms.html"),
        "landing-src/public/security.html": read(LANDING_SRC / "public" / "security.html"),
        "landing-src/public/404.html": read(LANDING_SRC / "public" / "404.html"),
        "landing/privacy.html": read(ROOT / "landing" / "privacy.html"),
        "landing/terms.html": read(ROOT / "landing" / "terms.html"),
        "landing/security.html": read(ROOT / "landing" / "security.html"),
        "landing/404.html": read(ROOT / "landing" / "404.html"),
        "bundle": bundle,
    }
    for name, text in pages.items():
        prose = re.sub(r'\bd[:=]"[^"]*"', "", text)  # SVG path data is not prose
        for pattern in banned + ([] if name == "bundle" else [r"\b99\.[0-9]"]):
            found = re.search(pattern, prose, re.IGNORECASE)
            assert not found, f"{name}: {found.group(0)!r}"


def test_fonts_are_self_hosted_and_the_build_copies_them():
    # The site's Content-Security-Policy is font-src 'self' (deploy/nginx-shieldbotsecurity-new.conf), so every
    # font comes from this origin, and the build must copy the current files next to the page.
    conf = read(ROOT / "deploy" / "nginx-shieldbotsecurity-new.conf")
    assert "font-src 'self'" in re.search(r'Content-Security-Policy "([^"]*)"', conf).group(1)
    pages = [LANDING_SRC / "index.html", ROOT / "landing" / "index.html", *sorted((LANDING_SRC / "public").glob("*.html"))]
    for page in pages:
        html = read(page)
        assert "fonts.googleapis.com" not in html and "fonts.gstatic.com" not in html, page.name
    fonts = sorted(path.name for path in (LANDING_SRC / "public" / "fonts").glob("*.woff2"))
    assert fonts == [
        "jetbrains-mono-latin-400-normal.woff2",
        "jetbrains-mono-latin-700-normal.woff2",
        "manrope-latin-wght-normal.woff2",
    ]
    for name in fonts:
        built = (ROOT / "landing" / "fonts" / name).read_bytes()
        assert built == (LANDING_SRC / "public" / "fonts" / name).read_bytes(), f"landing/fonts/{name} is stale"
    assert 'href="/fonts/manrope-latin-wght-normal.woff2" as="font"' in read(LANDING_SRC / "index.html")


def test_every_static_page_declares_its_manrope_face():
    for name in ("404.html", "about.html", "privacy.html", "terms.html", "security.html"):
        for page in (LANDING_SRC / "public" / name, ROOT / "landing" / name):
            html = read(page)
            assert not any(line.startswith("+") for line in html.splitlines()), page
            assert re.search(r"^\s*@font-face\s*\{[^}]*Manrope Variable", html, re.MULTILINE), page


def test_the_site_describes_the_quick_scan_as_the_readme_does():
    text = "a token it recognises reads Unknown there"
    assert text in read(ROOT / "README.md")
    assert text in read(COMPONENTS / "AgentSecurity.tsx")


def test_the_site_says_which_verdicts_reach_the_registry():
    # Only Telegram scans, guard rescans, and launches that are blocked or guard-watched are recorded on-chain
    # (docs/SUBMISSION.md); a launch the hunter is merely watching is stored as off.
    text = "Telegram scans, guard rescans, and launches it blocks or the guard watches"
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert "guard-watched" in read(ROOT / "docs" / "SUBMISSION.md")
    assert text in read(COMPONENTS / "OnChain.tsx")
    assert text in bundle


def test_hero_demo_shows_documented_examples_and_makes_no_request():
    # The demo in the hero plays recorded examples. Each address must be the one the repository documents, the
    # labels must say the examples are recorded or modelled, and the component must not talk to the network.
    scenes = read(COMPONENTS / "verdictScenes.ts")
    demo = read(COMPONENTS / "VerdictDemo.tsx")
    fixture = json.loads(read(ROOT / "tests" / "fixtures" / "arbitrum_simulation" / "v2_honeypot.json"))
    assert fixture["token"] in scenes
    deployments = read(ROOT / "docs" / "DEPLOYMENTS.md")
    subject = re.search(r"`subject\(\)` is VIRTUAL \(`(0x[0-9a-fA-F]{40})`\)", deployments).group(1)
    assert subject.lower() in scenes.lower()
    assert "Recorded examples, not live scans" in demo
    assert "Modelled example from the judge guide" in scenes
    assert "allowed=True, reason=0" in scenes and "allowed=True, reason=0" in read(ROOT / "docs" / "SUBMISSION.md")
    for source in (scenes, demo):
        for forbidden in ("fetch(", "XMLHttpRequest", "WebSocket", "EventSource"):
            assert forbidden not in source, forbidden


def test_built_dashboard_contains_the_current_source_strings():
    built = read(ROOT / "dashboard" / "index.html")
    labels = re.findall(r"label:'([^']+)'", read(DASHBOARD_SRC))
    assert labels
    for label in labels:
        assert label in built, (
            f"dashboard/index.html is stale: missing {label!r}; run the dashboard build"
        )
