"""The public website must not drift from the code it describes.

These checks tie the landing page, the about page, the dashboard and the extension's welcome page to
the facts they state (chain counts, tool counts, score bands, chain tables, per-chain coverage) and
fail when a source changes without the site, or when the committed builds fall behind their sources.
"""

import gzip
import json
import re
from datetime import date
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
    chains = read(COMPONENTS / "Chains.tsx")
    table = re.search(r"const chains: Chain\[\] = \[(.*?)\n\];", chains, re.S).group(1)
    assert len(re.findall(r"chainId:", table)) == len(chain_info())


def test_mempool_chain_count_matches_the_monitor():
    faq = read(COMPONENTS / "FAQ.tsx") + read(COMPONENTS / "Chains.tsx")
    stated = {int(n) for n in re.findall(r"(\d+)\s+chains with a public\s+mempool", faq)}
    assert stated == {mempool_chain_count()}


def test_chains_section_lists_every_scan_chain():
    chains = read(COMPONENTS / "Chains.tsx")
    rows = re.findall(r'chainId: (\d+),\s*name: "([^"]+)"', chains)
    assert len(rows) == len(chain_info())
    assert {int(chain_id) for chain_id, _ in rows} == set(chain_info())
    aliases = {"BSC": "BNB Chain"}
    assert {name for _, name in rows} == {
        aliases.get(info["name"], info["name"]) for info in chain_info().values()
    }


def test_mechanism_and_try_it_chain_maps_match_the_registry():
    # Proof names the chains /api/stats reports; TryIt offers the chains POST /api/scan accepts.
    proof = re.search(r"const chainNames: Record<number, string> = \{(.*?)\};", read(COMPONENTS / "Proof.tsx"), re.S)
    proof_ids = [int(chain_id) for chain_id in re.findall(r"^\s+(\d+): \"[^\"]+\",$", proof.group(1), re.M)]
    try_it = re.search(r"const chainOptions = \[(.*?)\];", read(COMPONENTS / "TryIt.tsx"), re.S)
    try_it_ids = [int(chain_id) for chain_id in re.findall(r"\{ id: (\d+), name: \"[^\"]+\" \}", try_it.group(1))]
    for ids in (proof_ids, try_it_ids):
        assert len(ids) == len(set(ids))
        assert set(ids) == set(chain_info())


def test_bot_chain_row_claims_only_its_own_bdex_simulation():
    # GoPlus token security does not cover BOT Chain; sell simulation there is ShieldBot's own, on BDEX
    # pools with WBOT, while address labels are checked separately.
    row = re.search(r'\{\s*chainId: 677,(.*?)\n\s*\}', read(COMPONENTS / "Chains.tsx"), re.S)
    assert row, "Chains.tsx should have a BOT Chain row"
    assert 'simulation: "ShieldBot",' in row.group(1)
    assert 'simulationScope: "BDEX V2 and V3 pools pairing the token with WBOT",' in row.group(1)
    assert 'return "GoPlus flags only";' in read(COMPONENTS / "Chains.tsx")


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
    chains_source = read(COMPONENTS / "Chains.tsx")
    rows = []
    for match in re.finditer(r'\{\s*chainId: (\d+),\s*name: "([^"]+)"', chains_source):
        row = chains_source[match.start() : chains_source.index("}", match.start())]
        simulation = re.search(r'simulation: ("[^"]+"|null)', row).group(1)
        mempool = re.search(r"mempool: (true|false)", row).group(1)
        launches = re.search(r"launches: (true|false)", row).group(1)
        rows.append((match.group(1), match.group(2), simulation, mempool, launches))
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
    for chain_id, name, simulation, mempool, launches in rows:
        chain_id = int(chain_id)
        assert ids[name] == chain_id
        assert json.loads(simulation) == simulator[ids[name]], name
        assert (mempool == "true") == supports_pending_transactions(ids[name]), name
        assert (launches == "true") == (ids[name] == LAUNCH_CHAIN_ID), name

    chains = read(COMPONENTS / "Chains.tsx")
    assert 'return "GoPlus flags only";' in chains
    assert '"Observed on last poll"' in chains and '"Not read on last poll"' in chains
    assert '<span className="whitespace-nowrap">/launchalerts</span>' in chains


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
    assert scope in chains



def test_botchain_simulation_scope_matches_the_code():
    # services/botchain_simulation.py simulates only BDEX pools pairing the token with WBOT: the V3 pools
    # through the original SwapRouter and the V2 pairs. A token with no such pool stays Unknown.
    from adapters.botchain import WBOT as ADAPTER_WBOT
    from services.botchain_simulation import V2_ROUTES, WBOT

    assert set(V2_ROUTES) == {"BDEX"}, "the BOT Chain simulation routes changed: update the site"
    assert WBOT == ADAPTER_WBOT
    scope = "BDEX V2 and V3 pools pairing the token with WBOT"
    for path in (COMPONENTS / "Chains.tsx", LANDING_SRC / "public" / "about.html", ROOT / "README.md"):
        assert scope in " ".join(read(path).split()), path.name
    unknown = {
        LANDING_SRC / "public" / "about.html": (
            "GoPlus token security does not cover BOT Chain. ShieldBot checks GoPlus address labels "
            "for the token and, when Blockscout supplies its creator, the creator; a BOT Chain token "
            "with no supported BDEX pool reads Unknown for sellability."
        ),
        ROOT / "README.md": (
            "GoPlus token security does not cover BOT Chain. ShieldBot checks GoPlus address labels "
            "for the token and, when Blockscout supplies its creator, the creator; a token with no "
            "supported BDEX pool still reads Unknown for sellability."
        ),
    }
    for path, sentence in unknown.items():
        assert sentence in " ".join(read(path).split()), path.name

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
    faq = " ".join(read(COMPONENTS / "FAQ.tsx").split())
    registry = read(COMPONENTS / "Registry.tsx")
    assert "deployed on Robinhood Chain on 27 September 2026" in faq
    assert registry.count('chain: "Robinhood Chain"') == 3
    assert registry.count('deployed: "27 September 2026"') == 3


def test_the_site_shows_the_robinhood_contract_addresses():
    # docs/DEPLOYMENTS.md records the deployment. The on-chain section must show each contract's address as
    # recorded there, link its explorer page and its Sourcify match, and the built bundle must carry the addresses.
    deployments = read(ROOT / "docs" / "DEPLOYMENTS.md")
    section = read(COMPONENTS / "Registry.tsx")
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
        assert f'address: "{address}"' in section, f"Registry.tsx: {contract}"
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
    registry = read(COMPONENTS / "Registry.tsx")
    assert registry.count("min-h-11 shrink-0 items-center whitespace-nowrap") >= 2
    assert "Sourcify" in registry and "Explorer" in registry
    assert "evidence_hash" in registry


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
    how = read(COMPONENTS / "HowItWorks.tsx")
    statement = "Lists risky ERC-20 allowances. It never revokes them."
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert statement in how and statement in bundle
    for name, text in landing_texts().items():
        prose = " ".join(text.split())
        for match in re.finditer(r"\btoken approvals\b", prose):
            assert prose[: match.start()].endswith("ERC-20 "), (
                f"{name}: {prose[match.start() - 40 : match.end()]!r}"
            )


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
    for component in ("Proof.tsx", "TryIt.tsx", "Chains.tsx"):
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
    visible = list(zip(
        re.findall(r'^\s+q: "([^"]+)",', faq_source, re.MULTILINE),
        re.findall(r'^\s+a: "([^"]+)",', faq_source, re.MULTILINE),
    ))
    assert entities, "index.html should carry FAQ structured data"
    assert [(entity["name"], entity["acceptedAnswer"]["text"]) for entity in entities] == visible


HERO_CAPTURES = [
    # The hero shows one recorded reply and one final verdict capture.
    ("hero-overlay-response.json", "HeroRecord.tsx", ("hero-overlay.webp",)),
]


def readable_reason(reason):
    """content.js's readableReason: one coverage reason part as the overlay reads it to a user."""
    from core.chat_coverage import FIELD_LABELS  # the labels content.js carries, by design the same

    clean = re.sub(r"(?:initialize logs scanned over )?blocks?\s+\d+\s*-\s*\d+;?", "", reason, flags=re.I)
    clean = re.sub(r"\b0x[0-9a-fA-F]{8,}\b", "a contract address", clean)
    clean = re.sub(r"^[\s;]+|[\s;]+$", "", clean)
    fields = re.match(r"^unknown fields:\s*(.+)$", clean, re.I)
    if not fields:
        return clean
    labels = [FIELD_LABELS[field.strip().lower()] for field in fields.group(1).split(",")
              if field.strip().lower() in FIELD_LABELS]
    if not labels:
        return "some scan details are unknown"
    if len(labels) == 1:
        return f"{labels[0]} is unknown"
    return f"{', '.join(labels[:-1])} and {labels[-1]} are unknown"


def unknown_reason(reply):
    """content.js's unknownReason: the API's coverage_gaps when sent, else its coverage reasons read part by part."""
    gaps = reply.get("coverage_gaps")
    if not isinstance(gaps, list):
        gaps = [
            readable_reason(part)
            for reason in filter(None, (reply.get("coverage_reasons") or {}).values())
            for part in str(reason).split(";")
        ]
    return "; ".join(filter(None, gaps))


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
        # The Unknown "why" line: the API's readable coverage_gaps, else the reasons read as the overlay
        # reads them (block ranges dropped, addresses named, field names as labels), ported below.
        "const gaps = Array.isArray(result.coverage_gaps) ? result.coverage_gaps.filter(Boolean) : "
        "Object.values(result.coverage_reasons || {}).filter(Boolean) "
        '.flatMap(reason => String(reason).split(";")).map(readableReason).filter(Boolean); '
        'return gaps.join("; ") || _t("unknownNoReason");',
        r'.replace(/(?:initialize logs scanned over )?blocks?\s+\d+\s*-\s*\d+;?/gi, "")',
        r'.replace(/\b0x[0-9a-fA-F]{8,}\b/g, "a contract address")',
        r'const fields = /^unknown fields:\s*(.+)$/i.exec(clean);',
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
    assert f"The verdict badge reads {label}" in figure
    if not incomplete:
        assert f"Safety: {100 - score}/100" in figure
    if reply.get("danger_signals"):
        assert f"The danger signals include {reply['danger_signals'][0]}" in figure
    if incomplete:
        assert f"{messages['unknownWhy']} {unknown_reason(reply) or messages['unknownNoReason']}" in figure
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
        "css/pages.css",
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
    footer = read(COMPONENTS / "Footer.tsx")
    assert f'href: "/{page}"' in footer
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


@pytest.mark.parametrize("component", ["HowItWorks.tsx", "Registry.tsx"])
def test_built_landing_bundle_contains_the_current_feature_copy(component):
    # The merged interfaces and commands ship in the built bundle, not only in source files.
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    copy = {
        "HowItWorks.tsx": (
            "Chrome extension", "Telegram bot", "REST API", "MCP server",
            "/token <address>", "/scan <address>", "/rescue <wallet>",
            "/report <address> <reason>", "/launchalerts",
            "Token checks, contract scans, ERC-20 allowances, reports and launch alerts.",
            "Model Context Protocol server for AI agents, over SSE.",
            "Telegram bot commands",
        ),
        "Registry.tsx": (
            "Recent registry records", "Deployed contracts", "Guard call",
            "ShieldBotVerdictRegistry", "ShieldBotVerdictGuard",
            "ShieldBotGuardedTransfer", "Explorer", "Sourcify",
        ),
    }[component]
    source = read(COMPONENTS / component)
    assert bundle
    if component == "HowItWorks.tsx":
        assert 'aria-label="Telegram bot commands"' in source
    for text in copy:
        assert text in source, f"{component} no longer contains {text!r}"
        assert text in bundle, f"landing bundle is stale: missing {component} structure {text!r}"


LANDING_SECTION_PINS = {
    "Hero.tsx": ("Know before you sign.", "Add to Chrome", "Open in Telegram"),
    "HowItWorks.tsx": ("Intercept", "Check", "Report"),
    "TryIt.tsx": ("Token or contract address", "Check now"),
    "Proof.tsx": ("One token. Two simulated transactions.", "transactions_monitored"),
    "Registry.tsx": ("Recent registry records", "Deployed contracts"),
    "Chains.tsx": ("Sell simulation", "Public mempool", "Launch scans"),
    "FAQ.tsx": ("What is ShieldBot?", "I think I signed something bad. What now?"),
}


def test_landing_uses_the_approved_section_map_and_shared_shell():
    app = read(LANDING_SRC / "src" / "App.tsx")
    order = [app.index(f"<{name} />") for name in ("Hero", "HowItWorks", "TryIt", "Proof", "Registry", "Chains", "FAQ")]
    assert order == sorted(order)
    assert all(f'<Section id="{anchor}" title=' in app or f'<Section id="{anchor}"' in read(COMPONENTS / component)
               for anchor, component in (
                   ("how", "HowItWorks.tsx"), ("try", "TryIt.tsx"), ("proof", "Proof.tsx"),
                   ("registry", "Registry.tsx"), ("coverage", "Chains.tsx"), ("faq", "FAQ.tsx"),
               ))
    section = read(COMPONENTS / "Section.tsx")
    assert '"pt-20 pb-12 md:pt-20 md:pb-11"' in section
    assert "eyebrow" not in section.lower() and "subtitle" not in section.lower()
    assert "Contract scans run on all" not in read(COMPONENTS / "Chains.tsx")
    assert "The Chrome Web Store serves extension 3.4.0" not in read(COMPONENTS / "Chains.tsx")
    assert "The Chrome Web Store serves extension 3.4.0" in read(COMPONENTS / "FAQ.tsx")
    assert 'id="top"' in app and 'id="main"' in app


def test_landing_navigation_and_footer_follow_the_shared_spec():
    navbar = read(COMPONENTS / "Navbar.tsx")
    nav_items = re.findall(r'\{ label: "([^"]+)", href: "([^"]+)" \}', navbar)
    assert nav_items == [
        ("How it works", "#how"),
        ("Registry", "#registry"),
        ("Coverage", "#coverage"),
        ("Safety", "/safety.html"),
        ("Docs", "https://api.shieldbotsecurity.online/docs"),
    ]
    assert 'href="#top"' in navbar
    assert navbar.count("<NavLinks") == 2
    assert navbar.count("<ThemeToggle />") == 2
    footer = read(COMPONENTS / "Footer.tsx")
    footer_items = re.findall(r'\{ label: "([^"]+)", href: "([^"]+)" \}', footer)
    assert footer_items == [
        ("About", "/about.html"),
        ("Safety guide", "/safety.html"),
        ("Privacy", "/privacy.html"),
        ("Terms", "/terms.html"),
        ("Security", "/security.html"),
        ("Dashboard", "/dashboard"),
        ("Telegram bot", "https://t.me/shieldbot_bnb_bot"),
        ("GitHub", "https://github.com/Ridwannurudeen/shieldbot"),
        ("support@shieldbotsecurity.online", "mailto:support@shieldbotsecurity.online"),
    ]
    assert 'placeholder="Email for updates"' in footer
    assert 'aria-label="Email for updates"' in footer
    assert "© 2026 ShieldBot. ShieldBot does not issue, sell or endorse any token." in footer


@pytest.mark.parametrize("component", sorted(LANDING_SECTION_PINS))
def test_built_landing_bundle_contains_the_current_hero_section_copy(component):
    # Each section heading and its main content structure ship in both source and the built bundle.
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    source = read(COMPONENTS / component)
    assert bundle
    for text in LANDING_SECTION_PINS[component]:
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
    # The static pages share one stylesheet, css/pages.css, which declares the Geist face from this origin's fonts:
    # every page links it, source and built, and no line of a page or of the stylesheet is a stray patch line.
    for name in ("404.html", "about.html", "privacy.html", "terms.html", "security.html", "safety.html"):
        for page in (LANDING_SRC / "public" / name, ROOT / "landing" / name):
            html = read(page)
            assert not any(line.startswith("+") for line in html.splitlines()), page
            assert html.count('<link rel="stylesheet" href="/css/pages.css">') == 1, page
    # A Geist face that loads a local /fonts/geist- file (the Arial based Geist Fallback face alone does not count),
    # no @import, and every url(), however it is quoted, a file in public/fonts.
    for sheet in (LANDING_SRC / "public" / "css" / "pages.css", ROOT / "landing" / "css" / "pages.css"):
        css = read(sheet)
        assert not any(line.startswith("+") for line in css.splitlines()), sheet
        faces = re.findall(r"^\s*@font-face\s*\{([^}]*)\}", css, re.MULTILINE)
        assert any(
            re.search(r"font-family:\s*([\"']?)Geist\1\s*;", face) and re.search(r"url\(\s*[\"']?/fonts/geist-", face)
            for face in faces
        ), sheet
        assert "@import" not in css.lower(), sheet
        urls = [url.strip("\"'") for url in re.findall(r"url\(\s*([^)]*?)\s*\)", css, re.IGNORECASE)]
        assert urls and all(
            re.fullmatch(r"/fonts/[\w.-]+", url) and (LANDING_SRC / "public" / url[1:]).is_file() for url in urls
        ), urls


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
    # The try-it form uses the quick scan route; the API reply keeps its no-sell result Unknown with its reason.
    api = " ".join(read(ROOT / "api.py").split())
    try_it = read(COMPONENTS / "TryIt.tsx")
    verdicts = read(LANDING_SRC / "src" / "firewallVerdict.ts")
    assert 'SCAN_URL = "https://api.shieldbotsecurity.online/api/scan"' in try_it
    assert '_QUICK_SCAN_SELLABILITY_UNKNOWN = (' in api
    assert '"Sellability unknown: this quick scan does not simulate a sell; /api/firewall runs the full token check"' in api
    assert 'UNKNOWN: { verdict: "unknown", text: "UNKNOWN" }' in verdicts
    assert 'reply.classification === "UNKNOWN"' in verdicts
    assert "reasons={reply.coverage_reasons}" in try_it


def test_registry_uses_recent_verdicts_and_blocked_launch_fallback():
    # The Registry lists confirmed records from its route, with blocked launches only as the documented fallback.
    docs = " ".join(read(ROOT / "docs" / "SUBMISSION.md").split())
    source = read(COMPONENTS / "Registry.tsx")
    feed = read(LANDING_SRC / "src" / "registryFeed.ts")
    assert "guard-watched" in docs
    assert "GET /api/verdicts/recent?chain_id=4663&limit=3" in feed
    assert 'outcome=blocked&limit=3' in feed
    assert "/api/verdicts/recent?chain_id=4663&limit=3" in source
    assert "outcome=blocked&limit=3" in source
    assert 'fallback ? "Records of the newest launches ShieldBot blocked" : "Recent registry records"' in " ".join(source.split())


def test_hero_demo_shows_documented_examples_and_makes_no_request():
    # The hero shows one dated extension capture without requesting data; API-backed examples sit in Proof and Registry.
    story = read(COMPONENTS / "HeroRecord.tsx")
    assert story.count('src="/hero-overlay.webp"') == 1
    assert "Recorded reply," in story
    for name in ("HeroRecord.tsx", "VerdictRecord.tsx", "CheckRow.tsx"):
        for forbidden in ("fetch(", "XMLHttpRequest", "WebSocket", "EventSource"):
            assert forbidden not in read(COMPONENTS / name), (name, forbidden)
    try_it = read(COMPONENTS / "TryIt.tsx")
    assert "https://api.shieldbotsecurity.online/api/scan" in try_it
    registry = read(COMPONENTS / "Registry.tsx")
    assert "useFeed()" in registry and "Recent registry records" in registry
    assert "fetch(" not in registry
    for forbidden in ("XMLHttpRequest", "WebSocket", "EventSource"):
        assert forbidden not in try_it, forbidden
    assert "live, not the request above" not in story
    assert "useFeed()" not in story
    for forbidden in ("XMLHttpRequest", "WebSocket", "EventSource"):
        assert forbidden not in registry, forbidden


def test_guard_example_matches_the_deployment_and_submission_records():
    deployments = read(ROOT / "docs" / "DEPLOYMENTS.md")
    virtual = re.search(
        r"subject\(\)\W+is VIRTUAL\W+(0x[0-9a-fA-F]{40})\W+",
        deployments,
    )
    assert virtual, "docs/DEPLOYMENTS.md should record the guarded transfer's VIRTUAL subject"
    submission = read(ROOT / "docs" / "SUBMISSION.md")
    result = re.search(
        r"guard\.check\(subject, maxAge\): (allowed=(?:True|False), reason=\d+)`? for VIRTUAL",
        submission,
    )
    assert result, "docs/SUBMISSION.md should record the deployment verifier result"
    address = virtual.group(1)
    registry = read(COMPONENTS / "Registry.tsx")
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    recorded = f"guard.check(VIRTUAL, 900)  // {result.group(1)}"
    derived = "guard.check(0x3435\u202626dd, 900)  // allowed=False, reason=4 HONEYPOT"
    caveat = (
        "Permission is not a safety guarantee: the guard accepts MEDIUM risk. "
        "Permission lasts only while a subject is actively watched and republished."
    )
    assert 'href={`https://robin.etherscan.io/address/${VIRTUAL}`}' in registry
    virtual_constant = re.search(
        rf'([A-Za-z_$][\w$]*)="{re.escape(address)}"', bundle, re.IGNORECASE
    )
    assert virtual_constant
    assert (
        f'href:`https://robin.etherscan.io/address/${{{virtual_constant.group(1)}}}`'
        in bundle
    )
    assert address.casefold() in registry.casefold()
    assert address.casefold() in bundle.casefold()
    for text in (
        "// Recorded on Robinhood Chain, 27 September 2026",
        recorded,
        "// Derived, not a recorded call",
        derived,
        caveat,
        "https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/SUBMISSION.md",
    ):
        assert text in registry, text
        assert text in bundle, text


def test_registry_records_link_each_onchain_transaction():
    registry = read(COMPONENTS / "Registry.tsx")
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    for text in ("https://robin.etherscan.io/tx/", "record.tx_hash", "tx {short(record.tx_hash)}"):
        assert text in registry, text
    assert 'aria-label={`Transaction ${record.tx_hash}`}' in registry
    assert "https://robin.etherscan.io/tx/" in bundle
    assert "tx " in bundle


def test_registry_links_the_judge_guide_and_limits_the_claim():
    registry = read(COMPONENTS / "Registry.tsx")
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    for text in (
        "https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api",
        "Verify a verdict without trusting the API",
        "A match proves the recorder committed those bytes. It does not prove the scan was right, that an issuer is genuine, or that a token will stay sellable.",
    ):
        assert text in registry, text
        assert text in bundle, text


def test_guard_permission_caveats_keep_their_scope():
    caveat = (
        "Permission is not a safety guarantee: the guard accepts MEDIUM risk. "
        "Permission lasts only while a subject is actively watched and republished."
    )
    registry = read(COMPONENTS / "Registry.tsx")
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert caveat in registry
    assert caveat in bundle


def test_guarded_transfer_row_disclaims_a_live_usdg_payment():
    note = (
        "Asks the guard, then moves approved USDG. Its subject is VIRTUAL; "
        "no live guarded USDG payment is claimed."
    )
    registry = read(COMPONENTS / "Registry.tsx")
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert note in registry
    assert note in bundle


def test_live_chain_matrix_and_check_definitions_use_reported_fields():
    # The table uses the existing stats request for mempool readings and has no legend or in-component fetch.
    chains = read(COMPONENTS / "Chains.tsx")
    for forbidden in ("fetch(", "XMLHttpRequest", "setTimeout("):
        assert forbidden not in chains, forbidden
    assert "useStats()" in chains
    assert "**adapter.capabilities()," in read(ROOT / "api.py")
    assert "GoPlus flags only" in chains
    assert 'return "No public mempool";' in chains
    assert '"Observed on last poll"' in chains
    assert '"Not read on last poll"' in chains
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert "Not read on last poll" in bundle
    assert "table-fixed" in chains
    assert "min-w-[720px]" not in chains

    stats = read(LANDING_SRC / "src" / "liveStats.ts")
    assert 'fetch("https://api.shieldbotsecurity.online/api/stats"' in stats
    assert "setTimeout(() => current.abort(), 10_000)" in stats
    assert "controller.abort();" in stats
    assert "if (!r.ok) throw" in stats

    assert 'href="https://api.shieldbotsecurity.online/api/stats"' in chains
    assert 'stats.mempool_chains_observable.includes(chain.chainId)' in chains


def test_registry_records_use_full_and_compact_verdict_records():
    proof = read(COMPONENTS / "Proof.tsx")
    registry = read(COMPONENTS / "Registry.tsx")
    assert "<VerdictRecord" in proof
    assert "evidenceHash={record.evidence_hash}" in proof
    assert "observed_block={record.observed_block}" not in proof
    assert "record.onchain_status" in proof
    assert "<table" in registry and "<th scope=\"col\"" in registry
    assert "short(subject)" in registry
    assert "record?.onchain_status" in registry
    assert "record?.observed_block" in registry
    assert "record?.evidence_hash" in registry
    # Both live views use the same route's chain identity and verdict mapping.
    assert 'export const REGISTRY_CHAIN = { id: 4663, name: "Robinhood Chain" };' in read(LANDING_SRC / "src" / "registryFeed.ts")
    assert "chain={REGISTRY_CHAIN}" in proof
    for source in (proof, registry):
        assert '"Robinhood Chain" }' not in source
        assert 'registryChip(record.verdict, record.verdict_code)' in source


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
    for name in ("Proof.tsx", "Registry.tsx"):
        source = read(COMPONENTS / name)
        assert 'import { registryChip } from "../registryVerdict";' in source, name
        assert "registryChip(record.verdict, record.verdict_code)" in source, name
        assert not re.search(r"\b(LOW|MEDIUM|HONEYPOT)\b\s*:", source), name
        assert "function registryChip" not in source, name


def test_registry_requests_are_shared_and_recent_records_load_near_the_viewport():
    # The API allows 10 requests in 5 seconds and 30 a minute per IP (api.py rate_limiter). The why-unknown record
    # goes through the feed, so an address is fetched once; other records wait for the table.
    assert "RateLimiter(requests_per_minute=30, burst=10)" in read(ROOT / "api.py")
    feed = read(LANDING_SRC / "src" / "registryFeed.ts")
    assert "}, 10_000)," in feed and "controller.abort();" in feed
    assert "if (current.asked.has(address)) continue;" in feed
    assert "want(current, addresses.slice(0, 1));" in feed
    assert "if (current.restWanted) want(current, current.rest);" in feed
    proof = read(COMPONENTS / "Proof.tsx")
    registry = read(COMPONENTS / "Registry.tsx")
    assert "useFeed()" in proof and "useFeed()" in registry
    assert "new IntersectionObserver(" in registry and "loadRecentRecords();" in registry
    assert "fetch(" not in proof and "fetch(" not in registry


def test_try_it_uses_a_verdict_record_without_repeated_hero_captures():
    try_it = read(COMPONENTS / "TryIt.tsx")
    assert 'import VerdictRecord from "./VerdictRecord";' in try_it
    assert "<VerdictRecord" in try_it
    assert "evidenceHash={reply.evidence_hash}" in try_it
    assert "reasons={reply.coverage_reasons}" in try_it
    assert "reply.evidence_url" in try_it
    for kind in ("idle", "invalid", "loading", "result", "bad-request", "rate-limited", "unavailable"):
        assert f'kind: "{kind}"' in try_it
    assert "const TIMEOUT_MS = 30_000;" in try_it
    assert "setTimeout(() => controller.abort(), TIMEOUT_MS)" in try_it
    assert "useEffect(() => () => request.current?.abort(), [])" in try_it
    assert "signal: controller.signal," in try_it
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


def test_a_null_check_reads_unavailable_and_zero_reads_did_not_run():
    # Missing coverage remains distinct from a check whose API value is zero.
    script = r"""
const React = require(path.join(root, "node_modules", "react"));
const {renderToStaticMarkup} = require(path.join(root, "node_modules", "react-dom", "server"));
const CheckRow = require(path.join(root, "src", "components", "CheckRow.tsx")).default;
process.stdout.write(renderToStaticMarkup(React.createElement(CheckRow, {
  coverage: JSON.parse(process.argv[2]),
  reasons: {market: "sell route unavailable"},
})));
"""
    coverage = {"structural": 1, "market": None, "behavioral": 0, "honeypot": 0.5}
    markup = run_typescript(script, json.dumps(coverage))
    visible = " ".join(re.sub(r"<[^>]+>", " ", markup).split())
    assert "market Unavailable" in visible
    assert "behavioral did not run" in visible
    assert "honeypot partial" in visible
    assert "sell route unavailable" in visible
    assert "market: Unavailable" not in visible


def test_a_code_block_wraps_long_lines_without_a_scroll_hint():
    block = read(COMPONENTS / "CodeBlock.tsx")
    assert "whitespace-pre-wrap break-words" in block
    assert "Scroll the block sideways" not in block
    assert "ResizeObserver" not in block


def test_the_feature_index_is_a_three_step_process_with_four_surfaces():
    how = read(COMPONENTS / "HowItWorks.tsx")
    assert "<ol" in how and "</ol>" in how
    for step in ("Intercept", "Check", "Report"):
        assert f">{step}</h3>" in how
    for surface in ("Chrome extension", "Telegram bot", "REST API", "MCP server"):
        assert f'name: "{surface}"' in how
    assert len(re.findall(r'\["/(?:token|scan|rescue|report|launchalerts)[^\"]*"', how)) == 5
    assert "<CheckRow coverage={recordedReply.coverage} />" in how


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
        'fetch("https://api.shieldbotsecurity.online/api/health", { signal: controller.signal, })',
        "const timeout = setTimeout(() => controller.abort(), 10_000);",
        "if (!response.ok) throw new Error(`HTTP ${response.status}`);",
        "if (active) setHealth(null);",
        "active = false; clearTimeout(timeout); controller.abort();",
        '"API unavailable"',
        '"API checking"',
        "API up, ${health.supported_chains.length} chains",
    ):
        assert text in footer, text
    assert 'className={message ? "mt-2 text-xs text-secondary" : "sr-only"}' in footer
    assert 'role="status"' in footer


def test_built_dashboard_contains_the_current_source_strings():
    built = read(ROOT / "dashboard" / "index.html")
    labels = re.findall(r"label:'([^']+)'", read(DASHBOARD_SRC))
    assert labels
    for label in labels:
        assert label in built, (
            f"dashboard/index.html is stale: missing {label!r}; run the dashboard build"
        )


CHECK_ORDER = ["structural", "market", "behavioral", "honeypot", "intent", "signature"]


def test_the_hero_records_are_the_recorded_replies_field_for_field():
    # Both visible dates follow the timestamp of the captured hero reply.
    fixture = json.loads(read(LANDING_SRC / "scripts" / "hero-overlay-response.json"))
    recordings = json.loads(
        read(LANDING_SRC / "scripts" / "hero-overlay-recordings.json")
    )["recordings"]
    sent_at = next(
        recording["sent_at"]
        for recording in recordings
        if recording["fixture"] == "hero-overlay"
    )
    year, month, day = (int(part) for part in sent_at[:10].split("-"))
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    recorded_date = f"{day} {months[month - 1]} {year}"
    story = read(COMPONENTS / "HeroRecord.tsx")
    recorded = read(LANDING_SRC / "src" / "recordedReplies.ts")
    coverage_block = re.search(r"coverage: \{(.*?)\}", recorded, re.S).group(1)
    coverage = {key: float(value) for key, value in re.findall(r"(\w+): ([0-9.]+)", coverage_block)}
    assert fixture["classification"] == "BLOCK_RECOMMENDED" and fixture["chain_id"] == 1
    assert fixture["risk_score"] == 100 and all(value == 1 for value in fixture["coverage"].values())
    assert 'fixture: "hero-overlay-response.json"' in recorded
    assert coverage == fixture["coverage"]
    assert f"Recorded checks, {recorded_date}" in read(COMPONENTS / "HowItWorks.tsx")
    assert 'src="/hero-overlay.webp"' in story
    assert f"Recorded reply, {recorded_date}" in story
    assert "BLOCK RECOMMENDED" in story and "Safety: 0/100" in story


def test_the_check_row_order_is_fixed():
    # One cell per coverage key, always in the order the API serves the keys in, whatever order an object has.
    source = read(COMPONENTS / "CheckRow.tsx")
    declared = re.search(r"export const CHECK_ORDER = \[([^\]]*)\] as const;", source).group(1)
    assert re.findall(r'"(\w+)"', declared) == CHECK_ORDER
    assert "CHECK_ORDER.map(" in source and "Object.keys(" not in source and "Object.entries(" not in source
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert json.dumps(CHECK_ORDER, separators=(",", ":")) in bundle, "landing bundle is stale: missing CHECK_ORDER"


def test_a_verdict_record_never_renders_a_full_hash():
    # A served reason and every registry field may contain a 64-hex value; none reaches the markup in full.
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
process.stdout.write(renderToStaticMarkup(React.createElement(VerdictRecord, props)));
"""
    digest = "0x" + "ab12" * 16
    props = {
        "chip": {"verdict": "unknown", "label": "UNKNOWN"},
        "reasons": {key: f"reason for {key}: {digest}" for key in CHECK_ORDER},
        "chain": {"id": 4663, "name": "Robinhood Chain"},
        "block": 85035031,
        "publishedAt": 1760000000,
        "evidenceHash": digest,
    }
    result = subprocess.run(
        [node, "-e", script, str(LANDING_SRC), json.dumps(props)],
        cwd=LANDING_SRC, capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    markup = result.stdout
    assert not re.search(r"0x[0-9a-fA-F]{64}", markup)
    assert "0xab12" in markup and ">Not checked</p>" in markup
    row = markup[: markup.index("</dl>")]
    assert sorted(CHECK_ORDER, key=lambda key: row.index(f">{key}</dt>")) == CHECK_ORDER
    for label in ("Chain", "Block", "Published", "Evidence"):
        assert f">{label}</dt>" in markup


def test_the_hero_request_lines_are_the_recorded_calls():
    # The visible screenshot is the same Ethereum unlimited USDC approval recorded by the one hero fixture.
    fixture = json.loads(read(LANDING_SRC / "scripts" / "hero-overlay-request.json"))
    response = json.loads(read(LANDING_SRC / "scripts" / "hero-overlay-response.json"))
    story = read(COMPONENTS / "HeroRecord.tsx")
    assert fixture["chainId"] == response["chain_id"] == 1
    assert fixture["data"].startswith("0x095ea7b3")
    assert "approves unlimited USDC spending on Ethereum" in story
    assert "fetch(" not in story


def test_the_hero_says_lines_are_the_recorded_replies():
    # The screenshot alt text retains the verdict and score shown in its captured API reply.
    reply = json.loads(read(LANDING_SRC / "scripts" / "hero-overlay-response.json"))
    hero = read(COMPONENTS / "HeroRecord.tsx")
    messages = json.loads(read(ROOT / "extension" / "locales" / "en" / "messages.json"))
    assert reply["classification"] == "BLOCK_RECOMMENDED" and reply["risk_score"] == 100
    assert f"The verdict badge reads {messages['classBlock']}" in hero
    assert f"Safety: {100 - reply['risk_score']}/100" in hero


def test_the_hero_commit_card_shows_a_live_record_never_the_recorded_request():
    # The hero no longer mixes recorded and live data; the latest live row is in Registry.
    hero = read(COMPONENTS / "HeroRecord.tsx")
    registry = read(COMPONENTS / "Registry.tsx")
    feed = read(LANDING_SRC / "src" / "registryFeed.ts")
    assert "useFeed()" not in hero and "fetch(" not in hero
    assert "Recent registry records" in registry
    assert "useFeed()" in registry and "recent.map" in registry
    assert "/api/verdicts/recent?chain_id=4663&limit=" in feed
    assert "live, not the request above" not in registry
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    assert "Recent registry records" in bundle


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
    # Only the loading-to-verdict story animates, and only when reduced motion is not requested.
    built = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.css"))
    source = read(LANDING_SRC / "src" / "index.css")
    for css in (built, source):
        rules = list(animated_rules(css))
        assert len(rules) >= 2
        for selector, allowed in rules:
            assert allowed, selector
    assert "animation-duration: 0.01ms !important;" in source
    assert "@media (prefers-reduced-motion: no-preference)" in source
    assert ".hero-loading {\n  display: none;" in source
    assert ".hero-loading {\n    display: block;" in source
    assert "hero-commit" not in source
    assert "PauseButton" not in read(COMPONENTS / "HeroRecord.tsx")


def test_the_hero_loading_frame_rests_hidden_after_its_animation():
    # The loading frame animates with backwards fill, so when the animation ends it falls back to its resting
    # style. That style must be hidden, or the loading dialog stays on top of the verdict for good.
    source = read(LANDING_SRC / "src" / "index.css")
    built = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.css"))
    assert ".hero-loading {\n    display: block;\n    opacity: 0;\n    animation: hero-loading" in source
    assert ".hero-loading{display:block;opacity:0;animation:hero-loading" in built

def test_the_footer_health_chip_states_its_value_without_a_legend():
    footer = read(COMPONENTS / "Footer.tsx")
    assert '"API unavailable"' in footer
    assert '"API checking"' in footer
    assert "API up, ${health.supported_chains.length} chains" in footer
    assert "Badge" not in footer and "legend" not in footer.lower()


def test_stylesheets_hold_no_c1_control_characters():
    # A CSS escape mangled on its way to disk (the minus \2212 read as the octal \221 plus "2") leaves a C1
    # control in the file, which renders as a box. No stylesheet, source or built, holds U+0080..U+009F.
    source = LANDING_SRC / "src" / "index.css"
    built = list((ROOT / "landing" / "assets").glob("index-*.css"))
    assert built
    for path in [source, *built]:
        bad = sorted({f"U+{ord(ch):04X}" for ch in read(path) if 0x80 <= ord(ch) <= 0x9F})
        assert not bad, f"{path.name} holds C1 control characters {bad}"
    assert '.acc-panel[data-open="true"]' in read(source)


def test_the_site_shows_the_bot_chain_registry():
    # Every BOT Chain contract row, including its own explorer address and deployment date, follows DEPLOYMENTS.md.
    deployments = read(ROOT / "docs" / "DEPLOYMENTS.md")
    contract_names = (
        "ShieldBotVerdictRegistry",
        "ShieldBotVerdictGuard",
        "ShieldBotGuardedTransfer",
    )
    months = ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December")
    bot_rows = {}
    for name in contract_names:
        row = re.search(
            rf"^\| \x60{name}\x60 \| BOT Chain \(677\) \| \[\x60(0x[0-9a-fA-F]{{40}})\x60\]\((https://scan\.botchain\.ai/address/0x[0-9a-fA-F]{{40}})\) \| (\d{{4}}-\d{{2}}-\d{{2}}) ",
            deployments,
            re.MULTILINE,
        )
        assert row, f"docs/DEPLOYMENTS.md should record the BOT Chain {name}"
        address, url, deployed = row.groups()
        assert url.endswith(address)
        deployed_date = date.fromisoformat(deployed)
        bot_rows[name] = (
            address,
            url,
            f"{deployed_date.day} {months[deployed_date.month - 1]} {deployed_date.year}",
        )

    registry = read(COMPONENTS / "Registry.tsx")
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    contract_source = registry.split("const contracts: Contract[] = [", 1)[1].split("];", 1)[0]
    contract_rows = re.findall(
        r'\{\s*name: "([^"]+)"(.*?)\n  \},', contract_source, re.S
    )
    verification_note = "Source verified on the explorer. No Sourcify on 677."
    for name, (address, url, deployed) in bot_rows.items():
        row = next(
            (
                fields
                for row_name, fields in contract_rows
                if row_name == name and 'chain: "BOT Chain"' in fields
            ),
            None,
        )
        assert row, f"Registry.tsx should have the BOT Chain {name} row"
        for field in (
            f'address: "{address}"',
            'chain: "BOT Chain"',
            "chainId: 677",
            f'deployed: "{deployed}"',
            f'explorer: "{url}"',
            verification_note,
        ):
            assert field in row, (name, field)
        assert (
            name in bundle
            and address in bundle
            and url in bundle
            and deployed in bundle
            and verification_note in bundle
        ), name
    assert 'chain: "BOT Chain"' in registry and 'chainId: 677' in registry
    assert registry.count("sourcify: null") == 3
    assert "Source verified on the explorer" in registry and "Source verified on the explorer" in bundle
    assert "No Sourcify on 677" in registry and "No Sourcify on 677" in bundle
    contract_links = registry[
        registry.index("function ContractLinks"):registry.index("export default function Registry")
    ]
    assert "Source verified on the explorer" not in contract_links
    assert "No Sourcify on 677" not in contract_links
    assert "Not supported" not in registry
    assert "A guard and a guarded transfer that read it were deployed on BOT Chain on 29 October 2026." in " ".join(
        read(COMPONENTS / "FAQ.tsx").split()
    )
    about = " ".join(read(LANDING_SRC / "public" / "about.html").split())
    _, registry_url, _ = bot_rows["ShieldBotVerdictRegistry"]
    assert f'<a href="{registry_url}"' in about and "On BOT Chain (677) a verdict registry was deployed on 26 October 2026" in about
    assert "A freshness guard and a guarded transfer contract that read it were deployed there on 29 October 2026" in about
    assert "The source of all three BOT Chain contracts is verified on BOT Chain's explorer" in about
    assert "cannot verify" not in about


def test_coverage_scope_notes_and_launch_alert_command_stay_readable():
    chains = read(COMPONENTS / "Chains.tsx")
    how = read(COMPONENTS / "HowItWorks.tsx")
    assert 'simulationScope: "supported pool routes only"' in chains
    assert '"pools pairing the token with WETH on Uniswap V3, Uniswap V2 or SushiSwap"' in chains
    assert '<span className="whitespace-nowrap">/launchalerts</span>' in chains
    assert '<code className="whitespace-nowrap font-mono text-xs leading-5 text-ink">' in how


def test_the_registry_figures_read_each_chain_from_the_stats_reply():
    # api.py public_stats serves registry_records_confirmed_by_chain for 4663 and 677; after JSON the keys are strings.
    api = " ".join(read(ROOT / "api.py").split())
    assert '"confirmed", 0) for chain_id in (4663, 677)' in api
    assert '"registry_records_confirmed_by_chain": registry_records_confirmed_by_chain,' in api
    stats = read(LANDING_SRC / "src" / "liveStats.ts")
    assert "registry_records_confirmed_by_chain: Record<string, number> | null;" in stats
    proof = " ".join(read(COMPONENTS / "Proof.tsx").split())
    assert 'stats?.registry_records_confirmed_by_chain?.["4663"] ?? stats?.registry_records_confirmed,' in proof
    assert 'value={count(stats?.registry_records_confirmed_by_chain?.["677"])}' in proof
    bundle = "".join(read(path) for path in (ROOT / "landing" / "assets").glob("index-*.js"))
    for label in (
        "Verdict records confirmed in the Robinhood Chain registry, all time",
        "Verdict records confirmed in the BOT Chain registry, all time",
    ):
        assert label in proof and label in bundle, label
    # The dashboard's BOT Chain tile reads the same key, an absent count is unknown, and it links the 677 explorer.
    dashboard = read(DASHBOARD_SRC)
    assert "const BOT_CHAIN = 677;" in dashboard
    assert "byChain && byChain[BOT_CHAIN] != null ? byChain[BOT_CHAIN] : null" in dashboard
    assert "677:'https://scan.botchain.ai'" in dashboard
    assert "${EXPLORERS[BOT_CHAIN]}/address/${REGISTRY_ADDRESS}" in dashboard
    assert "confirmed on-chain · BOT Chain (677)" in read(ROOT / "dashboard" / "index.html")


def test_the_bot_chain_faq_and_meta_description_match_their_structured_data():
    question = "What does ShieldBot do on BOT Chain?"
    html = read(LANDING_SRC / "index.html")
    faq = read(COMPONENTS / "FAQ.tsx")
    entities = [
        entity
        for block in re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.DOTALL)
        for entity in json.loads(block).get("mainEntity", [])
    ]
    answers = [entity["acceptedAnswer"]["text"] for entity in entities if entity["name"] == question]
    assert len(answers) == 1, "index.html JSON-LD should carry the BOT Chain question once"
    assert f'q: "{question}",' in faq and f'a: "{answers[0]}",' in faq
    for clause in (
        "BDEX V2 and V3 pools paired with WBOT",
        "/rescue bot: scans BOT Chain approvals",
        "Telegram /scan and /token results can be recorded in the verdict registry deployed on BOT Chain on 26 October 2026.",
        "A guard and a guarded transfer that read it were deployed on BOT Chain on 29 October 2026.",
    ):
        assert clause in answers[0], clause
    description = (
        "Contract scans on 9 EVM chains, with verdict registries on Robinhood Chain and BOT Chain. "
        "A check that cannot run is reported as Unknown."
    )
    for page in (html, read(ROOT / "landing" / "index.html")):
        assert page.count(description) == 4
        assert "On BOT Chain, checks that cannot run" not in page
        assert "BOT Chain security" in re.search(r'<meta name="keywords" content="([^"]*)"', page).group(1)
