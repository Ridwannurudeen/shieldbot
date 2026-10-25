"""The public website must not drift from the code it describes.

These checks tie the landing page, the about page, the dashboard and the extension's welcome page to
the facts they state (chain counts, tool counts, score bands, chain tables, per-chain coverage) and
fail when a source changes without the site, or when the committed builds fall behind their sources.
"""

import gzip
import json
import re
from html.parser import HTMLParser
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
    files = list(COMPONENTS.glob("*.tsx")) + list((LANDING_SRC / "src").glob("*.ts")) + [
        LANDING_SRC / "index.html",
        LANDING_SRC / "public" / "about.html",
        LANDING_SRC / "public" / "safety.html",
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
    assert "SUPPORTED_CHAINS = %d;" % len(chain_info()) in read(COMPONENTS / "Chains.tsx")


def test_mempool_chain_count_matches_the_monitor():
    faq = read(COMPONENTS / "FAQ.tsx") + read(COMPONENTS / "Chains.tsx")
    stated = {int(n) for n in re.findall(r"(\d+)\s+chains with a public\s+mempool", faq)}
    assert stated == {mempool_chain_count()}


def test_chains_section_lists_every_scan_chain():
    names = re.findall(r'^\s+name: "([^"]+)",', read(COMPONENTS / "Chains.tsx"), re.MULTILINE)
    assert len(names) == len(chain_info())
    assert "Robinhood Chain" in names


def test_mechanism_and_try_it_chain_maps_match_the_registry():
    # Mechanism names the chains /api/stats reports; TryIt offers the chains POST /api/scan accepts.
    mechanism = re.search(r"const chainNames: Record<number, string> = \{(.*?)\};", read(COMPONENTS / "Mechanism.tsx"), re.S)
    mechanism_ids = [int(chain_id) for chain_id in re.findall(r"^\s+(\d+): \"[^\"]+\",$", mechanism.group(1), re.M)]
    try_it = re.search(r"const chainOptions = \[(.*?)\];", read(COMPONENTS / "TryIt.tsx"), re.S)
    try_it_ids = [int(chain_id) for chain_id in re.findall(r"\{ id: (\d+), name: \"[^\"]+\" \}", try_it.group(1))]
    for ids in (mechanism_ids, try_it_ids):
        assert len(ids) == len(set(ids))
        assert set(ids) == set(chain_info())


def test_bot_chain_row_does_not_claim_goplus_flags():
    # GoPlus does not cover BOT Chain tokens and nothing simulates a sell there, so its cell reads Unknown.
    row = re.search(r'\{\s*//[^\n]*\n\s*chainId: 677,(.*?)logo:', read(COMPONENTS / "Chains.tsx"), re.S)
    assert row, "Chains.tsx should have a BOT Chain row"
    assert 'simulation: null,' in row.group(1)
    assert 'unavailableLabel: "Unknown",' in row.group(1)
    assert 'label: chain.unavailableLabel ?? "GoPlus flags only"' in read(COMPONENTS / "Chains.tsx")


def test_chains_section_coverage_matches_the_code():
    from adapters.arbitrum import ArbitrumAdapter
    from adapters.base_chain import BaseChainAdapter
    from adapters.botchain import BotChainAdapter
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
                BotChainAdapter,
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
    for component in ("FAQ.tsx", "FeatureTabs.tsx"):
        prose = " ".join(read(COMPONENTS / component).split())
        assert "deployed on Robinhood Chain on 27 September 2026" in prose, component


def test_the_site_shows_the_robinhood_contract_addresses():
    # docs/DEPLOYMENTS.md records the deployment. The on-chain section must show each contract's address as
    # recorded there, link its explorer page and its Sourcify match, and the built bundle must carry the addresses.
    deployments = read(ROOT / "docs" / "DEPLOYMENTS.md")
    section = read(COMPONENTS / "OnChain.tsx")
    # The footer lists the same three contracts, shortened, each linked to its explorer page.
    footer = read(COMPONENTS / "Footer.tsx")
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
        assert f'address: "{address}"' in footer, f"Footer.tsx: {contract}"
    assert "Deployed 27 September 2026" in read(COMPONENTS / "ContractCard.tsx")
    assert "0x7578ca9e…f0c772a4" in section
    assert "judge guide" in section
    verification_code = re.search(r"const verificationCode = `([^`]*)`;", section).group(1)
    export_lines = [line for line in verification_code.splitlines() if line.startswith("export ")]
    assert len(export_lines) == 4
    assert "#" not in verification_code
    # Recorded fixture JSON under landing-src/scripts/ is excluded on purpose: these are verbatim API replies whose only 64-hex values are public evidence hashes and calldata.
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
    assert "min-h-[44px]" in read(COMPONENTS / "ContractCard.tsx")
    assert read(COMPONENTS / "ContractCard.tsx").count('name="external"') == 1
    assert "text-[13px] text-emerald" not in read(COMPONENTS / "OnChain.tsx")


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
    for component in ("Mechanism.tsx", "TryIt.tsx", "WhyUnknown.tsx"):
        assert "FALLBACK" not in read(COMPONENTS / component), component
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


HERO_CAPTURES = [
    # (recorded reply, component whose alt text describes it, captures made from the reply)
    ("hero-overlay-response.json", "HeroRecord.tsx", ("hero-overlay.webp", "hero-overlay-mobile.webp")),
    ("hero-overlay-unknown-response.json", "HeroRecord.tsx", ("hero-overlay-unknown.webp",)),
    ("hero-overlay-safe-response.json", "HeroRecord.tsx", ("hero-overlay-safe.webp",)),
    ("hero-overlay-unknown-response.json", "FeatureTabs.tsx", ("hero-overlay-unknown.webp",)),
    ("hero-overlay-safe-response.json", "FeatureTabs.tsx", ("hero-overlay-safe.webp",)),
]


@pytest.mark.parametrize("fixture, component, captures", HERO_CAPTURES)
def test_hero_image_describes_its_recorded_api_reply(fixture, component, captures):
    # landing-src/scripts/capture-hero-overlay.py renders the extension's overlay from each reply; each
    # component showing a capture describes it in its alt text.
    reply = json.loads(read(LANDING_SRC / "scripts" / fixture))
    figure = read(COMPONENTS / component)
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
    for name in captures:
        assert f'"/{name}"' in figure
        source = (LANDING_SRC / "public" / name).read_bytes()
        assert (ROOT / "landing" / name).read_bytes() == source, f"landing/{name} is stale"


def test_hero_story_shows_the_real_loading_dialog():
    # The hero's "Checking" frame is a capture of the extension's loading overlay (showLoadingOverlay in
    # extension/content.js), so its alt text quotes that overlay's own string.
    messages = json.loads(read(ROOT / "extension" / "locales" / "en" / "messages.json"))
    assert '<p>${_t("overlayAnalyzing")}</p>' in read(ROOT / "extension" / "content.js")
    story = read(COMPONENTS / "HeroRecord.tsx")
    assert f"It reads {messages['overlayAnalyzing']}" in story
    assert '"/hero-overlay-loading.webp"' in story
    source = (LANDING_SRC / "public" / "hero-overlay-loading.webp").read_bytes()
    built = (ROOT / "landing" / "hero-overlay-loading.webp").read_bytes()
    assert built == source, "landing/hero-overlay-loading.webp is stale"


@pytest.mark.parametrize(
    "name",
    [
        "404.html",
        "about.html",
        "privacy.html",
        "terms.html",
        "security.html",
        "safety.html",
        "sitemap.xml",
        ".well-known/security.txt",
        "js/plausible-init.js",
        "try/index.html",
        "try/harness.js",
    ],
)
def test_built_landing_copies_the_current_public_files(name):
    source = read(LANDING_SRC / "public" / name).replace("\r\n", "\n")
    built = read(ROOT / "landing" / name).replace("\r\n", "\n")
    assert built == source, f"landing/{name} is stale: run `npm run build` in landing-src"


ANALYTICS_TAGS = ('<script src="/js/plausible-init.js"></script>', '<script async src="/js/script.js"></script>')


LANDING_PAGES = [LANDING_SRC / "index.html", *sorted((LANDING_SRC / "public").glob("*.html"))]
TWELVE_PAGES = [*LANDING_PAGES, *(ROOT / "landing" / page.name for page in LANDING_PAGES)]


class InlineScriptChecker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.has_disallowed_inline_script = False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            attributes = dict(attrs)
            if "src" not in attributes and attributes.get("type", "").lower() != "application/ld+json":
                self.has_disallowed_inline_script = True


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
    first_server = re.search(r"^server \{\n(.*?)^\}", conf, re.MULTILINE | re.DOTALL).group(1)
    assert "error_page 404 /404.html;" in first_server
    assert re.search(r"location = /404\.html \{\s*internal;\s*\}", first_server)
    assert "proxy_intercept_errors" not in conf
    assert 'name="robots" content="noindex"' in read(LANDING_SRC / "public" / "404.html")
    assert "404.html" not in read(LANDING_SRC / "public" / "sitemap.xml")


def test_no_inline_script_and_no_hash_in_the_policy():
    # script-src is 'self' with no 'unsafe-inline' and no hash (deploy/nginx-shieldbotsecurity-new.conf), so no
    # page may carry an inline script except JSON-LD; external scripts with src are allowed.
    conf = read(ROOT / "deploy" / "nginx-shieldbotsecurity-new.conf")
    csp = re.search(r'Content-Security-Policy "([^"]*)"', conf).group(1)
    script_src = re.search(r"script-src ([^;]*);", csp).group(1)
    assert "'unsafe-inline'" not in script_src
    assert script_src.count("'sha256-") == 0, script_src
    for page in [*TWELVE_PAGES, LANDING_SRC / "public" / "try" / "index.html", ROOT / "landing" / "try" / "index.html"]:
        parser = InlineScriptChecker()
        parser.feed(read(page))
        parser.close()
        assert not parser.has_disallowed_inline_script, page


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


def test_built_landing_bundle_stays_inside_its_budget():
    # The budget the audits hold the landing script to (landing-src/vite.config.ts): 320,000 B raw and 100,000 B
    # gzipped at level 9. A section that pushes past it has to cut something or argue for a new budget.
    bundles = list((ROOT / "landing" / "assets").glob("index-*.js"))
    assert len(bundles) == 1
    raw = bundles[0].read_bytes()
    assert len(raw) <= 320_000, f"landing JS is {len(raw):,} B raw, over the 320,000 B budget"
    packed = len(gzip.compress(raw, compresslevel=9))
    assert packed <= 100_000, f"landing JS is {packed:,} B gzipped, over the 100,000 B budget"


@pytest.mark.parametrize("component", ["HowItWorks.tsx", "AgentSecurity.tsx", "FeatureTabs.tsx"])
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


HERO_SECTION_COPY = {
    "HeroRecord.tsx": (
        "Recorded reply of 26 September 2026, chain 1, BLOCK RECOMMENDED.",
        "Recorded reply of 11 October 2026, chain 4663, UNKNOWN.",
        "Recorded reply of 11 October 2026, chain 42161, SAFE.",
        "Recorded examples, not live scans.",
        "overlay at unreleased commit 2b54a1b, fed that reply.",
    ),
    "TryIt.tsx": (
        "Checking, this can take up to 25 seconds",
        "Too many checks from this connection. Wait a minute and try again.",
        "Quick check: no sell simulation, so a token reads Unknown here.",
    ),
    "Mechanism.tsx": (
        "Each check runs, or it says it did not.",
        "A source that is not running reads Unavailable, never 0.",
        "GET /api/stats did not answer, so every figure reads Unavailable.",
    ),
    "WhyUnknown.tsx": (
        "A check that did not run is not a pass.",
        "The typed data could not be read, so the overlay says Unknown and why.",
        "did not answer.",
    ),
    "Chains.tsx": (
        "Contract scans run on all 9 chains. The other checks depend on the chain, and a check that cannot run is "
        "reported as Unknown, never as Safe.",
        "It has been tested with Rabby; MetaMask testing is still outstanding.",
    ),
    "WorkedExample.tsx": (
        "One token. Two transactions.",
        "1 · Simulated sell to the pool",
        "2 · Simulated transfer to a fresh address",
    ),
    "OnChain.tsx": (
        "Newest confirmed records in the registry",
        "Records of the newest launches ShieldBot blocked",
        "/api/verdicts/recent?chain_id=4663&limit=",
        # The guard's MEDIUM caveat sits beside the visible guard description, not only in a non-default tab.
        "A guard contract allows only a fresh LOW or MEDIUM record; everything else is denied. Permission is not a "
        "safety guarantee: the guard accepts MEDIUM risk.",
    ),
    "CtaCard.tsx": (
        "Check before you sign.",
        "Ask the registry before funds move.",
    ),
}


@pytest.mark.parametrize("component", sorted(HERO_SECTION_COPY))
def test_built_landing_bundle_contains_the_current_hero_section_copy(component):
    # The hero, try-it, mechanism and chain sections ship only in the built bundle, so their copy is pinned in
    # both the source and the bundle: a source edit without `npm run build` fails here.
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    source = read(COMPONENTS / component)
    assert bundle
    for text in HERO_SECTION_COPY[component]:
        assert text in source, f"{component} no longer says {text[:60]!r}; update the pin"
        assert text in bundle, f"landing bundle is stale: missing {component} text {text[:60]!r}"


def test_no_unbacked_marketing_claims_anywhere_on_the_site():
    # The brand is honesty: no detection rate, insurance or coverage promise, user or loss count, audit claim,
    # or aggregate figure that no document in this repository backs, in any source page or in the built bundle.
    banned = [
        r"detection rate", r"\binsured\b", r"\binsurance\b", r"\$[\d,]+ in coverage", r"zero losses", r"\baudited\b",
        r"\btrustless\b", r"\bunhackable\b", r"enterprise-grade", r"\b\d[\d,]*\+? users\b", r"10 of 66",
        r"0 false positives", r"818 tokens", r"3 honeypots", r"496,628", r"2,091",
        r"records each Robinhood Chain verdict",
        # Others already cover Robinhood Chain and agents (plan section 0): never "first" or "only" about either.
        r"\b(first|only) (transaction firewall|firewall|security (tool|layer)|product)\b[^.]*Robinhood",
        r"\b(first|only)\b[^.]*\b(MCP|agents?)\b",
    ]
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    pages = {
        **landing_texts(),
        "landing/index.html": read(ROOT / "landing" / "index.html"),
        "landing-src/public/privacy.html": read(LANDING_SRC / "public" / "privacy.html"),
        "landing-src/public/terms.html": read(LANDING_SRC / "public" / "terms.html"),
        "landing-src/public/security.html": read(LANDING_SRC / "public" / "security.html"),
        "landing-src/public/safety.html": read(LANDING_SRC / "public" / "safety.html"),
        "landing-src/public/404.html": read(LANDING_SRC / "public" / "404.html"),
        "landing-src/public/try/index.html": read(LANDING_SRC / "public" / "try" / "index.html"),
        "landing-src/public/try/harness.js": read(LANDING_SRC / "public" / "try" / "harness.js"),
        "landing/privacy.html": read(ROOT / "landing" / "privacy.html"),
        "landing/terms.html": read(ROOT / "landing" / "terms.html"),
        "landing/security.html": read(ROOT / "landing" / "security.html"),
        "landing/safety.html": read(ROOT / "landing" / "safety.html"),
        "landing/404.html": read(ROOT / "landing" / "404.html"),
        "landing/try/index.html": read(ROOT / "landing" / "try" / "index.html"),
        "landing/try/harness.js": read(ROOT / "landing" / "try" / "harness.js"),
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
        "geist-latin-400-normal.woff2",
        "geist-latin-500-normal.woff2",
        "ibm-plex-mono-latin-400-normal.woff2",
    ]
    for name in fonts:
        built = (ROOT / "landing" / "fonts" / name).read_bytes()
        assert built == (LANDING_SRC / "public" / "fonts" / name).read_bytes(), f"landing/fonts/{name} is stale"
    assert 'href="/fonts/geist-latin-400-normal.woff2" as="font"' in read(LANDING_SRC / "index.html")


def test_every_static_page_declares_its_geist_face():
    for name in ("404.html", "about.html", "privacy.html", "terms.html", "security.html", "safety.html"):
        for page in (LANDING_SRC / "public" / name, ROOT / "landing" / name):
            html = read(page)
            assert not any(line.startswith("+") for line in html.splitlines()), page
            assert re.search(r"^\s*@font-face\s*\{[^}]*Geist", html, re.MULTILINE), page


def test_the_site_ships_without_framer_motion():
    # Plan 1.2 and row D2: every animation is CSS in the bundle, so the motion library is gone from the
    # dependencies, the sources and the built bundle.
    package = json.loads(read(LANDING_SRC / "package.json"))
    assert "framer-motion" not in {**package.get("dependencies", {}), **package.get("devDependencies", {})}
    source = "\n".join(read(path) for path in (LANDING_SRC / "src").rglob("*") if path.is_file())
    assert "framer-motion" not in source and "MotionConfig" not in source
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert bundle and "framer" not in bundle


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
    # The hero plays captures of recorded replies and draws their records, says so, and does not talk to the
    # network. TryIt.tsx, the section after the hero, calls the API (POST /api/scan). The VIRTUAL guard example left the page with
    # verdictScenes.ts in PR C and is in FeatureTabs.tsx since PR D1 (plan 3.3).
    story = read(COMPONENTS / "HeroRecord.tsx")
    assert "Recorded examples, not live scans" in story
    for name in ("HeroRecord.tsx", "VerdictRecord.tsx", "CheckRow.tsx"):
        for forbidden in ("fetch(", "XMLHttpRequest", "WebSocket", "EventSource"):
            assert forbidden not in read(COMPONENTS / name), (name, forbidden)
    try_it = read(COMPONENTS / "TryIt.tsx")
    assert "https://api.shieldbotsecurity.online/api/scan" in try_it
    for forbidden in ("XMLHttpRequest", "WebSocket", "EventSource"):
        assert forbidden not in try_it, forbidden
    # The VIRTUAL guard example is in the feature tabs, with the answer docs/SUBMISSION.md records (plan 3.3).
    tabs = read(COMPONENTS / "FeatureTabs.tsx")
    deployments = read(ROOT / "docs" / "DEPLOYMENTS.md")
    subject = re.search(r"`subject\(\)` is VIRTUAL \(`(0x[0-9a-fA-F]{40})`\)", deployments).group(1)
    assert subject.lower() in tabs.lower()
    assert "allowed=True, reason=0" in tabs and "allowed=True, reason=0" in read(ROOT / "docs" / "SUBMISSION.md")
    assert "Derived, not a recorded call" in tabs
    for forbidden in ("fetch(", "XMLHttpRequest", "WebSocket", "EventSource"):
        assert forbidden not in tabs, forbidden
    # ARBROKER, the documented Arbitrum honeypot, is shown in the Arbitrum coverage note.
    fixture = json.loads(read(ROOT / "tests" / "fixtures" / "arbitrum_simulation" / "v2_honeypot.json"))
    assert fixture["token"] in read(COMPONENTS / "Chains.tsx")
    # The SAFE fixture is the ARB approval of docs/SUBMISSION.md; the UNKNOWN one has incomplete coverage.
    scripts = LANDING_SRC / "scripts"
    safe = json.loads(read(scripts / "hero-overlay-safe-request.json"))
    assert safe["chainId"] == 42161 and f"(`{safe['to']}`)" in read(ROOT / "docs" / "SUBMISSION.md")
    assert json.loads(read(scripts / "hero-overlay-safe-response.json"))["classification"] == "SAFE"
    unknown = json.loads(read(scripts / "hero-overlay-unknown-response.json"))
    assert unknown["status"] != "ok" and any(unknown["coverage_reasons"].values())


def test_live_chain_matrix_and_check_definitions_use_reported_fields():
    # The matrix sends no request of its own: sell simulation and launch scans are the pinned rows above (the
    # adapter configuration GET /api/coverage/{chain_id} serves), and the mempool column reads the one
    # GET /api/stats the page already makes, so a page load stays well inside the API's per-IP limit.
    chains = read(COMPONENTS / "Chains.tsx")
    for forbidden in ("fetch(", "XMLHttpRequest", "setTimeout("):
        assert forbidden not in chains, forbidden
    assert "useStats()" in chains
    assert "**adapter.capabilities()," in read(ROOT / "api.py")
    assert "GoPlus flags only" in chains
    # Three mempool readings, kept apart as the API keeps them (public_mempool yes / unobservable / no): a public
    # mempool the monitor did not read on its last poll is the legend's outline, not the dashed "does not run here".
    assert '{ state: "unavailable", label: "No public mempool" }' in chains
    assert '{ state: "available", label: "Observed on last poll" }' in chains
    assert '{ state: "unknown", label: "Not read on last poll" }' in chains
    assert "Not observable" not in chains
    assert "Dashed: does not run on this chain" in chains and "Outline: Unavailable" in chains
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert "Not read on last poll" in bundle
    # /api/coverage serves sell simulation but no launch scan field: the footnote keeps the two sources apart.
    assert "Sell simulation: from the code, the chain adapters, the configuration GET /api/coverage/" in chains
    assert "Launch scans: from the code, services/launch_discovery.py, Robinhood Chain only." in chains
    assert "Sell simulation and launch scans: from the code" not in chains
    assert 'label: "/launchalerts"' in chains
    assert "<CapabilityCell {...launchCell(chain)} />" in chains
    assert 'label="Unavailable"' not in chains
    assert "Public mempool: Unavailable. GET /api/stats did not answer" in chains
    assert "Where it says None" not in chains
    # One legend vocabulary with Mechanism's check cells: Filled, Dashed, Outline: Unavailable.
    assert "Outline: Unavailable" in chains and "Not available" not in chains
    assert '"None"' not in read(COMPONENTS / "WhyUnknown.tsx")
    assert "table-fixed" in chains
    assert "min-w-[720px]" not in chains

    stats = read(LANDING_SRC / "src" / "liveStats.ts")
    assert 'fetch("https://api.shieldbotsecurity.online/api/stats"' in stats
    assert "setTimeout(() => current.abort(), 10_000)" in stats
    assert "controller.abort();" in stats
    assert "if (!r.ok) throw" in stats

    mechanism = read(COMPONENTS / "Mechanism.tsx")
    assert "useStats()" in mechanism and "fetch(" not in mechanism
    assert "CHECK_ORDER.map((key)" in mechanism
    for key in ("structural", "market", "behavioral", "honeypot", "intent", "signature"):
        assert f"{key}:" in mechanism
    assert "Dashed: partial or no run" in mechanism
    assert "A dashed cell is not a pass." in mechanism
    assert "GET /api/stats did not answer, so every figure reads Unavailable." in mechanism


def test_registry_records_use_full_and_compact_verdict_records():
    worked = read(COMPONENTS / "WorkedExample.tsx")
    rows = read(COMPONENTS / "OnChain.tsx")
    why = read(COMPONENTS / "WhyUnknown.tsx")
    assert "<VerdictRecord" in worked
    assert 'variant="full"' in worked
    assert "evidenceHash={record.evidence_hash}" in worked
    assert "short(record.subject)" in worked
    assert "<VerdictRecord" in rows
    assert 'variant="compact"' in rows
    assert "evidenceHash={record.evidence_hash}" in rows
    assert "record.onchain_status" in rows
    # One chain line for a registry record, from the route, in every section that draws one.
    assert 'export const REGISTRY_CHAIN = { id: 4663, name: "Robinhood Chain" };' in read(LANDING_SRC / "src" / "registryFeed.ts")
    for source in (worked, rows, why):
        assert "chain={REGISTRY_CHAIN}" in source
        assert '"Robinhood Chain" }' not in source


def run_typescript(script: str, *args: str) -> str:
    # Run a Node script that can require landing-src's .ts and .tsx files (transpiled by its own typescript).
    import shutil
    import subprocess

    node = shutil.which("node")
    modules = LANDING_SRC / "node_modules"
    if node is None or not (modules / "typescript").is_dir() or not (modules / "react-dom").is_dir():
        pytest.skip("Node.js and landing-src/node_modules (npm ci) are required to run the sources")
    prelude = r"""
const fs = require("fs");
const path = require("path");
const root = process.argv[1];
const ts = require(path.join(root, "node_modules", "typescript"));
for (const ext of [".ts", ".tsx"]) {
  require.extensions[ext] = (module, filename) => {
    const options = {module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2020, esModuleInterop: true};
    module._compile(ts.transpileModule(fs.readFileSync(filename, "utf8"), {compilerOptions: options, fileName: filename}).outputText, filename);
  };
}
"""
    result = subprocess.run(
        [node, "-e", prelude + script, str(LANDING_SRC), *args],
        cwd=LANDING_SRC, capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_registry_verdicts_have_one_mapping_and_low_or_medium_is_never_a_firewall_verdict():
    # A registry LOW or MEDIUM is a token risk level the guard allows alike while fresh, not an extension SAFE or
    # CAUTION verdict: both take the neutral registry shape. One module maps the registry's words, for every section.
    script = r"""
const {registryChip} = require(path.join(root, "src", "registryVerdict.ts"));
const words = ["LOW", "MEDIUM", "HIGH", "HONEYPOT", "UNKNOWN", "SAFE", "constructor", "low", null];
process.stdout.write(JSON.stringify(words.map((word) => [word, registryChip(word, 1), registryChip(word, null)])));
"""
    chips = {word: (with_code, without) for word, with_code, without in json.loads(run_typescript(script))}
    expected = {
        "LOW": "registry", "MEDIUM": "registry", "HIGH": "high", "HONEYPOT": "block", "UNKNOWN": "unknown",
        "SAFE": "unknown", "constructor": "unknown", "low": "unknown", None: "unknown",
    }
    for word, shape in expected.items():
        with_code, without = chips[word]
        assert with_code["verdict"] == without["verdict"] == shape, word
        assert with_code["verdict"] not in ("safe", "caution") or word not in ("LOW", "MEDIUM"), word
    assert chips["LOW"][0]["label"] == "LOW · 1" and chips["MEDIUM"][1]["label"] == "MEDIUM"
    assert chips[None][0]["label"] == "Unavailable"
    assert '  registry: { classes: "' in read(COMPONENTS / "Badge.tsx")
    assert "registry" not in read(LANDING_SRC / "src" / "firewallVerdict.ts")
    for name in ("WhyUnknown.tsx", "OnChain.tsx", "WorkedExample.tsx"):
        source = read(COMPONENTS / name)
        assert 'import { registryChip } from "../registryVerdict";' in source, name
        assert "registryChip(record.verdict, record.verdict_code)" in source, name
        assert not re.search(r"\b(LOW|MEDIUM|HONEYPOT)\b\s*:", source), name
        assert "function registryChip" not in source, name


def test_registry_requests_are_shared_and_the_strip_loads_its_records_near_the_viewport():
    # The API allows 10 requests in 5 seconds and 30 a minute per IP (api.py rate_limiter). The why-unknown record
    # goes through the feed, so an address is fetched once; the strip's other records wait for the strip.
    assert "RateLimiter(requests_per_minute=30, burst=10)" in read(ROOT / "api.py")
    feed = read(LANDING_SRC / "src" / "registryFeed.ts")
    assert "}, 10_000)," in feed and "controller.abort();" in feed
    assert "if (current.asked.has(address)) continue;" in feed
    assert "want(current, addresses.slice(0, 1));" in feed
    assert "if (current.restWanted) want(current, current.rest);" in feed
    why = read(COMPONENTS / "WhyUnknown.tsx")
    assert "const record = useRecord(SUBJECT);" in why
    assert "/api/verdict/4663/${SUBJECT}`)" not in why
    strip = read(COMPONENTS / "OnChain.tsx")
    assert "new IntersectionObserver(" in strip and "loadRecentRecords();" in strip
    assert "fetch(" not in strip


def test_try_it_uses_a_verdict_record_without_repeated_hero_captures():
    try_it = read(COMPONENTS / "TryIt.tsx")
    assert 'import VerdictRecord from "./VerdictRecord";' in try_it
    assert "<VerdictRecord" in try_it
    assert 'variant="full"' in try_it
    assert "evidenceHash={reply.evidence_hash}" in try_it
    assert "hero-overlay-safe.webp" not in try_it
    assert "hero-overlay-unknown.webp" not in try_it
    assert "rounded-md" in try_it
    assert "border-secondary" in try_it
    assert "border-hairline-strong" not in try_it
    assert "rounded-full" not in try_it
    assert "rounded-2xl" not in try_it
    assert "before:h-px" not in try_it
    assert "after:h-px" not in try_it
    for kind in ("idle", "invalid", "loading", "result", "bad-request", "rate-limited", "unavailable"):
        assert f'kind: "{kind}"' in try_it
    assert "const TIMEOUT_MS = 30_000;" in try_it
    assert "setTimeout(() => controller.abort(), TIMEOUT_MS)" in try_it
    assert "useEffect(() => () => request.current?.abort(), [])" in try_it
    assert "signal: controller.signal," in try_it
    # An Unknown from /api/scan says which check did not run: its coverage keys are not the six checks, so the
    # reasons are printed on their own.
    assert "reasons={reply.coverage_reasons}" in try_it
    assert "coverage={reply.coverage}" not in try_it
    assert 'if (!/^0x[0-9a-fA-F]{40}$/.test(value))' in try_it


def test_a_verdict_record_with_reasons_and_no_coverage_prints_each_reason():
    # The shape of an /api/scan Unknown: coverage keys outside the six checks, reasons for those not run.
    script = r"""
const React = require(path.join(root, "node_modules", "react"));
const {renderToStaticMarkup} = require(path.join(root, "node_modules", "react-dom", "server"));
const VerdictRecord = require(path.join(root, "src", "components", "VerdictRecord.tsx")).default;
const props = JSON.parse(process.argv[2]);
process.stdout.write(renderToStaticMarkup(React.createElement(VerdictRecord, props)));
"""
    reason = "Sellability unknown: this quick scan does not simulate a sell; /api/firewall runs the full token check"
    assert f'"{reason}"' in " ".join(read(ROOT / "api.py").split())
    props = {
        "chip": {"verdict": "unknown", "label": "UNKNOWN"},
        "reasons": {"is_verified": None, "sellability": reason},
        "variant": "full",
    }
    markup = run_typescript(script, json.dumps(props))
    assert ">Not checked</p>" in markup
    assert ">sellability</dt>" in markup and reason in markup
    assert "is_verified" not in markup
    assert "<ol" not in markup


def test_a_null_check_reads_unavailable_with_the_legends_ink_outline():
    # A coverage value served as null is not a 0: its cell reads Unavailable, drawn as the legend's ink outline,
    # which clears 3:1 on white; 0 still reads as a check that did not run.
    script = r"""
const React = require(path.join(root, "node_modules", "react"));
const {renderToStaticMarkup} = require(path.join(root, "node_modules", "react-dom", "server"));
const CheckRow = require(path.join(root, "src", "components", "CheckRow.tsx")).default;
const out = {};
for (const variant of ["full", "compact"]) {
  out[variant] = renderToStaticMarkup(React.createElement(CheckRow, {coverage: JSON.parse(process.argv[2]), variant}));
}
process.stdout.write(JSON.stringify(out));
"""
    coverage = {"structural": 1, "market": None, "behavioral": 0, "honeypot": 0.5}
    markup = json.loads(run_typescript(script, json.dumps(coverage)))
    cells = dict(zip(CHECK_ORDER, markup["full"].split("<li")[1:]))
    assert "Unavailable" in cells["market"] and not re.search(r">\s*0</span>", cells["market"])
    assert "border-ink bg-ground" in cells["market"] and "border-edge" not in cells["market"]
    assert re.search(r">\s*0</span>", cells["behavioral"]) and "border-edge" in cells["behavioral"]
    for key in ("intent", "signature"):
        assert "Unavailable" in cells[key] and "border-ink bg-ground" in cells[key], key
    assert "market: Unavailable" in markup["compact"] and "market: did not run" not in markup["compact"]
    legend = read(COMPONENTS / "Mechanism.tsx")
    assert re.search(r'border border-ink bg-ground" />\s*Outline: Unavailable', legend)


def test_a_code_block_says_when_its_lines_scroll_sideways():
    block = read(COMPONENTS / "CodeBlock.tsx")
    assert "new ResizeObserver(measure)" in block
    assert "setOverflows(element.scrollWidth > element.clientWidth)" in block
    assert "Scroll the block sideways to read each line in full" in block


def test_the_feature_index_is_a_vertical_tablist_with_roving_focus():
    tabs = " ".join(read(COMPONENTS / "FeatureTabs.tsx").split())
    for text in (
        'role="tablist"',
        'aria-orientation="vertical"',
        'role="tab"',
        'role="tabpanel"',
        "tabIndex={selected ? 0 : -1}",
        "const next = current === last ? 0 : current + 1;",
        "const previous = current === 0 ? last : current - 1;",
        "ArrowDown: next, ArrowRight: next, ArrowUp: previous, ArrowLeft: previous, Home: 0, End: last,",
        "event.preventDefault(); select(target);",
        "tabs.current[i]?.focus();",
    ):
        assert text in tabs, text


def test_the_faq_opens_one_native_button_answer_at_a_time():
    faq = " ".join(read(COMPONENTS / "FAQ.tsx").split())
    for text in (
        '<button type="button"',
        "onClick={() => setOpen(expanded ? null : i)}",
        "aria-expanded={expanded}",
        "aria-controls={`faq-answer-${i}`}",
        'role="region"',
        "inert={!expanded}",
    ):
        assert text in faq, text
    # No unbacked comparison with other tools.
    assert "Many tools" not in faq


def test_the_footer_health_line_reads_unavailable_when_the_api_does_not_answer():
    # /api/health is exempt from the rate limiter, so the footer's request costs no allowance.
    assert 'if request.url.path in ("/", "/api/health",' in read(ROOT / "api.py")
    footer = " ".join(read(COMPONENTS / "Footer.tsx").split())
    for text in (
        'fetch("https://api.shieldbotsecurity.online/api/health", { signal: controller.signal })',
        "const timeout = setTimeout(() => controller.abort(), 10_000);",
        "if (!r.ok) throw new Error(`HTTP ${r.status}`);",
        "if (active) setHealth(null);",
        "active = false; clearTimeout(timeout); controller.abort();",
        '"Unavailable. GET /api/health did not answer."',
    ):
        assert text in footer, text


def test_built_dashboard_contains_the_current_source_strings():
    built = read(ROOT / "dashboard" / "index.html")
    labels = re.findall(r"label:'([^']+)'", read(DASHBOARD_SRC))
    assert labels
    for label in labels:
        assert label in built, (
            f"dashboard/index.html is stale: missing {label!r}; run the dashboard build"
        )


CHECK_ORDER = ["structural", "market", "behavioral", "honeypot", "intent", "signature"]


def recorded_replies() -> dict:
    # landing-src/src/recordedReplies.ts is one object literal; read it as JSON (quote the keys, drop trailing
    # commas) so each transcribed field can be compared with its fixture.
    source = read(LANDING_SRC / "src" / "recordedReplies.ts")
    body = source[source.index("> = {") + 4 : source.rindex("};") + 1]
    body = re.sub(r"(?m)^(\s*)(\w+):", r'\1"\2":', body)
    body = re.sub(r",(\s*[}\]])", r"\1", body)
    return json.loads(body)


def test_the_hero_records_are_the_recorded_replies_field_for_field():
    # The hero's verdict records are drawn from the three recorded /api/firewall replies. The JSON is not imported
    # (it carries full evidence hashes), so every field the page renders is transcribed and checked here.
    replies = recorded_replies()
    assert sorted(replies) == ["block", "safe", "unknown"]
    recordings = {
        entry["fixture"]: entry for entry in json.loads(read(LANDING_SRC / "scripts" / "hero-overlay-recordings.json"))["recordings"]
    }
    for name, record in replies.items():
        fixture = json.loads(read(LANDING_SRC / "scripts" / record["fixture"]))
        assert record["sent_at"] == recordings[record["fixture"].removesuffix("-response.json")]["sent_at"], name
        for field in ("status", "partial", "classification", "risk_score", "coverage", "chain_id", "network", "plain_english"):
            assert record[field] == fixture[field], (name, field)
        assert list(record["coverage"]) == list(fixture["coverage"]) == CHECK_ORDER, name
        assert record.get("coverage_reasons") == fixture.get("coverage_reasons"), name
        digest = fixture["evidence_hash"]
        assert record["evidence_hash"] == f"{digest[:6]}…{digest[-4:]}", name
    unknown = replies["unknown"]
    assert unknown["coverage"]["market"] == 0 and 0 < unknown["coverage"]["honeypot"] < 1
    assert set(unknown["coverage_reasons"]) == {"market", "honeypot"}


def test_the_check_row_order_is_fixed():
    # One cell per coverage key, always in the order the API serves the keys in, whatever order an object has.
    source = read(COMPONENTS / "CheckRow.tsx")
    declared = re.search(r"export const CHECK_ORDER = \[([^\]]*)\] as const;", source).group(1)
    assert re.findall(r'"(\w+)"', declared) == CHECK_ORDER
    assert "CHECK_ORDER.map(" in source and "Object.keys(" not in source and "Object.entries(" not in source
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert json.dumps(CHECK_ORDER, separators=(",", ":")) in bundle, "landing bundle is stale: missing CHECK_ORDER"


def test_a_verdict_record_never_renders_a_full_hash():
    # Render VerdictRecord (both variants) with a 64-hex value in every text field and the coverage keys in
    # reverse order: no 64-hex string may reach the markup, and the cells keep CHECK_ORDER.
    import shutil
    import subprocess

    node = shutil.which("node")
    modules = LANDING_SRC / "node_modules"
    if node is None or not (modules / "typescript").is_dir() or not (modules / "react-dom").is_dir():
        pytest.skip("Node.js and landing-src/node_modules (npm ci) are required to render the component")
    script = r"""
const fs = require("fs");
const path = require("path");
const root = process.argv[1];
const ts = require(path.join(root, "node_modules", "typescript"));
for (const ext of [".ts", ".tsx"]) {
  require.extensions[ext] = (module, filename) => {
    const options = {module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2020, esModuleInterop: true};
    module._compile(ts.transpileModule(fs.readFileSync(filename, "utf8"), {compilerOptions: options, fileName: filename}).outputText, filename);
  };
}
const React = require(path.join(root, "node_modules", "react"));
const {renderToStaticMarkup} = require(path.join(root, "node_modules", "react-dom", "server"));
const VerdictRecord = require(path.join(root, "src", "components", "VerdictRecord.tsx")).default;
const props = JSON.parse(process.argv[2]);
const out = {};
for (const variant of ["full", "compact"]) out[variant] = renderToStaticMarkup(React.createElement(VerdictRecord, {...props, variant}));
process.stdout.write(JSON.stringify(out));
"""
    digest = "0x" + "ab12" * 16
    coverage = dict(zip(reversed(CHECK_ORDER), (1, 0.5, 0, 1, 1, 0)))
    props = {
        "chip": {"verdict": "unknown", "label": "UNKNOWN"},
        "coverage": coverage,
        "reasons": {key: f"reason for {key}: {digest}" for key in CHECK_ORDER},
        "reason": f"served reason {digest}",
        "recordedAt": "2026-10-11T09:21:20Z",
        "chain": {"id": 4663, "name": "Robinhood Chain"},
        "block": 85035031,
        "publishedAt": 1760000000,
        "evidenceHash": digest,
        "guard": f"guard.check({digest}, 900)",
        "request": f"approve(address,uint256) · to {digest}",
        "source": "test",
    }
    result = subprocess.run(
        [node, "-e", script, str(LANDING_SRC), json.dumps(props)],
        cwd=LANDING_SRC, capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    for variant, markup in json.loads(result.stdout).items():
        assert not re.search(r"0x[0-9a-fA-F]{64}", markup), variant
        assert "0xab12…ab12" in markup, variant
        row = markup[: markup.index("</ol>")]
        assert sorted(CHECK_ORDER, key=lambda key: row.index(f">{key}")) == CHECK_ORDER, variant
        for label in ("Recorded", "Chain", "Block", "Published", "Evidence", "Guard"):
            assert f">{label}</dt>" in markup, (variant, label)
        assert "approve(address,uint256) · to 0xab12…ab12" in markup, variant


def test_the_hero_request_lines_are_the_recorded_calls():
    # The hero record opens with the recorded request: the method its selector names and its target, shortened,
    # transcribed from hero-overlay{,-unknown,-safe}-request.json (the calldata itself is never transcribed).
    selectors = {"0x095ea7b3": "approve(address,uint256)"}
    for name, record in recorded_replies().items():
        request = json.loads(read(LANDING_SRC / "scripts" / record["fixture"].replace("-response.json", "-request.json")))
        assert request["chainId"] == record["chain_id"], name
        assert record["request"]["method"] == selectors[request["data"][:10]], name
        assert record["request"]["to"] == f"{request['to'][:6]}…{request['to'][-4:]}", name
        # approve(address,uint256): the spender is the first argument, the last 40 hex digits of its 32-byte word.
        spender = "0x" + request["data"][34:74]
        assert record["request"]["spender"] == f"{spender[:6]}…{spender[-4:]}", name
    hero = " ".join(read(COMPONENTS / "HeroRecord.tsx").split())
    assert "request={`${reply.request.method} · to ${reply.request.to}`}" in hero
    # The signing card is an illustration of the recorded call, under a placeholder dApp, and says so.
    assert "<dd>{reply.request.spender}</dd>" in hero and "<span>app.example</span>" in hero
    assert "The signing card is an illustration: a placeholder dApp asking to sign the recorded call." in hero


def test_the_hero_says_lines_are_the_recorded_replies():
    # What the hero says on each verdict field is fields of the recorded reply, never a paraphrase: one sentence of
    # plain_english (the first, or for an incomplete reply its last, since the first lists the coverage reasons the
    # record prints), then risk_score, or each coverage key below 1 with its value, and the chain.
    def js(number):
        return str(int(number)) if float(number).is_integer() else str(number)

    says = {}
    for name, record in recorded_replies().items():
        reply = json.loads(read(LANDING_SRC / "scripts" / record["fixture"]))
        incomplete = reply["status"] != "ok" or reply.get("partial") is True or any(
            float(value) < 1 for value in reply["coverage"].values()
        )
        sentences = re.split(r"(?<=\.) ", reply["plain_english"])
        measure = (
            [f"{key} {js(reply['coverage'][key])}" for key in CHECK_ORDER if reply["coverage"][key] < 1]
            if incomplete
            else [f"risk_score {js(reply['risk_score'])}"]
        )
        says[name] = (sentences[-1] if incomplete else sentences[0], " · ".join([*measure, f"chain {reply['chain_id']}"]))
    assert says == {
        "block": ("Do not proceed with this transaction.", "risk_score 100 · chain 1"),
        "unknown": ("Review the missing data before proceeding.", "market 0 · honeypot 0.4 · chain 4663"),
        "safe": ("No major risks detected.", "risk_score 6.4 · chain 42161"),
    }
    hero = " ".join(read(COMPONENTS / "HeroRecord.tsx").split())
    for line in (
        "const sentences = reply.plain_english.split(/(?<=\\.) /);",
        "CHECK_ORDER.filter((key) => reply.coverage[key] < 1).map( (key) => `${key} ${reply.coverage[key]}`, )",
        ": [`risk_score ${reply.risk_score}`];",
        "sentence: incomplete ? sentences[sentences.length - 1] : sentences[0],",
        "measure: [...measure, `chain ${reply.chain_id}`].join(\" · \"),",
        "{says.sentence}",
        "{says.measure}",
    ):
        assert line in hero, line


def test_the_hero_commit_card_shows_a_live_record_never_the_recorded_request():
    # The recorded replies were never published, so the hero's commit beat shows the newest registry record the
    # shared feed already fetched, labelled as another token's live record; it sends no request and prints no block
    # of its own.
    hero = " ".join(read(COMPONENTS / "HeroRecord.tsx").split())
    assert "useFeed()" in hero and "fetch(" not in hero
    assert "{label} · live, not the request above" in hero
    assert '"Newest confirmed registry record"' in hero
    assert '"Registry record of the newest launch ShieldBot blocked"' in hero
    assert "value(record?.observed_block)" in hero
    assert 'record?.onchain_status === "confirmed"' in hero
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert "live, not the request above" in bundle


def media_blocks(css: str):
    # Yield (enclosing @media conditions, declaration block) for every rule in a stylesheet, by brace depth.
    stack, start = [], 0
    for i, ch in enumerate(css):
        if ch == "{":
            stack.append(css[start:i].strip())
            start = i + 1
        elif ch == "}":
            yield [p for p in stack[:-1] if p.startswith("@media")], stack[-1] if stack else "", css[start:i]
            if stack:
                stack.pop()
            start = i + 1


def animated_rules(css: str):
    # Yield (selector, inside @media (prefers-reduced-motion: no-preference)) for every rule that declares an animation.
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    for media, selector, body in media_blocks(css):
        if selector.startswith("@keyframes") or selector.startswith("from") or selector.startswith("to") or "%" in selector:
            continue
        if re.search(r"(^|;)\s*animation(-name)?:", body) and not re.search(r"(^|;)\s*animation(-name)?:\s*none", body):
            yield selector, any("prefers-reduced-motion:no-preference" in m.replace(" ", "") for m in media)


def test_every_animation_runs_only_when_motion_is_allowed():
    # Reduced motion shows every final frame at once: in the source CSS and in the built CSS, each animation
    # declaration sits inside @media (prefers-reduced-motion: no-preference), so with reduce no element starts hidden
    # or waits for a reading. Checking the source too catches a violation even while landing/ is stale.
    built = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.css"))
    source = read(LANDING_SRC / "src" / "index.css")
    for css in (built, source):
        rules = list(animated_rules(css))
        assert len(rules) >= 10
        for selector, allowed in rules:
            assert allowed, selector
    assert "animation-duration: 0.01ms !important;" in source
    # The pre-states that hide, clip, offset or hold something before it plays (a slot's clip, a transparent rule,
    # a paused wait) exist only when motion is allowed too, so with reduce nothing starts hidden or frozen. The source
    # only: the built CSS also holds Tailwind's static utilities (border-l-transparent).
    for css in (source,):
        stripped = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        held = [
            (media, selector)
            for media, selector, body in media_blocks(stripped)
            if not selector.startswith("@keyframes") and not re.match(r"(from|to|\d)", selector)
            and re.search(r"clip-path:|animation-play-state:|border(-left)?-color:\s*transparent", body)
        ]
        assert len(held) >= 4
        for media, selector in held:
            assert any("prefers-reduced-motion:no-preference" in m.replace(" ", "") for m in media), selector
    # What keeps moving (the hero's replay, the strip's re-reading, the orbits) starts only through useAlive, which
    # never turns on with reduced motion, and its Pause button is hidden there.
    reading = read(LANDING_SRC / "src" / "reading.ts")
    assert 'if (paused || matchMedia("(prefers-reduced-motion: reduce)").matches) {' in reading
    assert "document.hidden" in reading and "new IntersectionObserver(" in reading
    assert "motion-reduce:hidden" in read(COMPONENTS / "Button.tsx")
    for name in ("HeroRecord.tsx", "OnChain.tsx", "Chains.tsx"):
        component = read(COMPONENTS / name)
        assert "useAlive<" in component and "<PauseButton paused={paused} setPaused={setPaused} />" in component, name
    # The only animation that repeats is the orbit. The hero, the strip and the orbit each hold their frame
    # (data-paused) whenever useAlive is off: paused, off screen or in a hidden tab, not only before the next replay.
    for css in (built, source):
        assert sorted(set(re.findall(r"animation:\s*([\w-]+)[^;}]*infinite", css))) == ["orbit-arm", "orbit-up"]
    for name in ("HeroRecord.tsx", "OnChain.tsx", "Chains.tsx"):
        assert 'data-paused={on ? undefined : ""}' in read(COMPONENTS / name), name


def test_the_footer_legend_explains_the_registry_chip():
    # The five firewall verdicts stay the legend; one sentence keys the neutral registry shape LOW and MEDIUM take.
    footer = " ".join(read(COMPONENTS / "Footer.tsx").split())
    text = "Registry records keep their own words: LOW, MEDIUM, HIGH, HONEYPOT, UNKNOWN. LOW and MEDIUM are drawn plain,"
    assert text in footer
    assert '<Badge verdict="registry">LOW</Badge>; the guard allows both while fresh.' in footer
    assert "Object.values(labels).map(" in footer
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert text in bundle


def test_stylesheets_hold_no_c1_control_characters():
    # A CSS escape mangled on its way to disk (the minus \2212 read as the octal \221 plus "2") leaves a C1
    # control in the file, which renders as a box. No stylesheet, source or built, holds U+0080..U+009F.
    source = LANDING_SRC / "src" / "index.css"
    built = list((ROOT / "landing" / "assets").glob("index-*.css"))
    assert built
    for path in [source, *built]:
        bad = sorted({f"U+{ord(ch):04X}" for ch in read(path) if 0x80 <= ord(ch) <= 0x9F})
        assert not bad, f"{path.name} holds C1 control characters {bad}"
    assert '.disclose[open] > summary::before { content: "' + chr(92) + '2212"; }' in read(source)
