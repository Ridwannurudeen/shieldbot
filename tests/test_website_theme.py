"""The site is dark by default with a light option (THEME-SPEC.md, 12 October 2026).

Dark is the no-attribute state; light is :root[data-theme="light"], restored before first paint by one same-origin
blocking script, /js/theme.js, so the policy stays script-src 'self' with no hash. The tokens live in three copies
(the landing app's channel triplets, the static pages' hex file, the dashboard's own block) that must agree. UNKNOWN
is grey in both themes and never amber.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LANDING_SRC = ROOT / "landing-src"
COMPONENTS = LANDING_SRC / "src" / "components"
INDEX_CSS = LANDING_SRC / "src" / "index.css"
THEME_JS = LANDING_SRC / "public" / "js" / "theme.js"
DASHBOARD_SRC = ROOT / "dashboard" / "index.src.html"
STATIC_PAGES = sorted((LANDING_SRC / "public").glob("*.html"))
LANDING_PAGES = [LANDING_SRC / "index.html", *STATIC_PAGES]
TRY_PAGES = [
    LANDING_SRC / "public" / "try" / "index.html",
    ROOT / "landing" / "try" / "index.html",
]
THEME_TAG = '<script src="/js/theme.js"></script>'


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def first_style(html: str) -> int:
    found = [
        i for i in (html.find('<link rel="stylesheet"'), html.find("<style")) if i >= 0
    ]
    return min(found) if found else len(html)


def token_blocks(text: str, parse) -> dict:
    # The :root block holding the colour tokens (the one with the ground token) and the light block, each parsed by
    # parse into name -> #RRGGBB. Other :root blocks (the motion easings) and other declarations are ignored.
    blocks = {}
    for selector, body in re.findall(r'(:root(?:\[data-theme="light"\])?)\s*\{([^}]*)\}', text):
        tokens = parse(body)
        if "ground" not in tokens:
            continue
        theme = "light" if "data-theme" in selector else "dark"
        assert theme not in blocks, f"two {theme} token blocks"
        blocks[theme] = tokens
    assert sorted(blocks) == ["dark", "light"], sorted(blocks)
    return blocks


def triplets(body: str) -> dict:
    # The landing app's form: --c-name: R G B;
    return {
        name: "#" + "".join(f"{int(channel):02X}" for channel in rgb)
        for name, *rgb in re.findall(r"--c-([\w-]+):\s*(\d+) (\d+) (\d+);", body)
    }


def hexes(body: str) -> dict:
    # The static pages' and the dashboard's form: --name: #RRGGBB;
    return {name: value.upper() for name, value in re.findall(r"--([\w-]+):\s*(#[0-9A-Fa-f]{6})\s*;", body)}



def test_dark_is_the_default_and_light_is_an_attribute():
    css = read(INDEX_CSS)
    dark = re.search(r":root \{([^}]*--c-ground:[^}]*)\}", css).group(1)
    assert "--c-ground: 11 11 10;" in dark and "color-scheme: dark;" in dark
    light = re.search(r':root\[data-theme="light"\] \{([^}]*)\}', css).group(1)
    assert "--c-ground: 255 255 255;" in light and "color-scheme: light;" in light
    # The owner's default is black whatever the OS says: the colour-scheme media query is never consulted.
    assert "prefers-color-scheme" not in css


def test_every_page_restores_the_theme_from_one_blocking_script():
    # The same early script restores the theme on the landing, static pages, /try and dashboard.
    pages = [
        *LANDING_PAGES,
        *(ROOT / "landing" / page.name for page in LANDING_PAGES),
        *TRY_PAGES,
    ]
    for page in pages:
        html = read(page)
        assert html.count(THEME_TAG) == 1, page
        assert html.index(THEME_TAG) < first_style(html), page
    dashboard = read(DASHBOARD_SRC)
    assert dashboard.count("<!-- theme.js -->") == 1
    assert dashboard.index("<!-- theme.js -->") < first_style(dashboard)
    built = read(ROOT / "dashboard" / "index.html")
    first_script = re.search(r"<script\b[^>]*>(.*?)</script>", built, re.DOTALL).group(
        1
    )
    assert "sb-theme" in first_script
    script = read(THEME_JS)
    assert len(script.encode("utf-8")) < 600
    assert "sb-theme" in script and "localStorage" in script
    for forbidden in ("fetch(", "XMLHttpRequest", "import", "document.write"):
        assert forbidden not in script, forbidden


def test_the_token_copies_are_identical():
    # A parse, never a byte comparison: whitespace in one copy cannot fail it.
    landing = token_blocks(read(INDEX_CSS), triplets)
    tokens_css = token_blocks(read(LANDING_SRC / "public" / "css" / "tokens.css"), hexes)
    assert tokens_css == landing
    assert token_blocks(read(DASHBOARD_SRC), hexes) == landing


def test_every_page_has_a_theme_toggle():
    # The landing's switch is one component, mounted in both responsive nav layouts.
    toggle = read(COMPONENTS / "ThemeToggle.tsx")
    assert (
        toggle.count('role="switch"') == 1
        and toggle.count('aria-label="Light theme"') == 1
    )
    # The desktop navigation and mobile menu each have their own responsive toggle.
    assert read(COMPONENTS / "Navbar.tsx").count("<ThemeToggle />") == 2
    for page in [
        *STATIC_PAGES,
        LANDING_SRC / "public" / "try" / "index.html",
        DASHBOARD_SRC,
    ]:
        html = read(page)
        assert html.count('role="switch"') == 1, page
        assert html.count('aria-label="Light theme"') == 1, page


def test_unknown_is_never_amber():
    files = [
        LANDING_SRC / "public" / "try" / "index.html",
        DASHBOARD_SRC,
        INDEX_CSS,
        *sorted(COMPONENTS.glob("*.tsx")),
    ]
    for path in files:
        text = read(path).lower()
        for forbidden in ("#f59e0b", "amber", "#fbbf24", "orange"):
            assert forbidden not in text, (path.name, forbidden)


def test_landing_layout_fixes_remain_in_the_source():
    css = read(INDEX_CSS)
    navbar = read(COMPONENTS / "Navbar.tsx")
    section = read(COMPONENTS / "Section.tsx")
    hero = read(COMPONENTS / "HeroRecord.tsx")
    proof = read(COMPONENTS / "Proof.tsx")
    footer = read(COMPONENTS / "Footer.tsx")
    registry = read(COMPONENTS / "Registry.tsx")
    chains = read(COMPONENTS / "Chains.tsx")

    dark_chevron = re.search(r"\.try-select\s*\{([^}]*)\}", css).group(1)
    light_chevron = re.search(
        r':root\[data-theme="light"\] \.try-select\s*\{([^}]*)\}', css
    ).group(1)
    assert "background-image: url(\"data:image/svg+xml" in dark_chevron
    assert "background-repeat: no-repeat" in dark_chevron
    assert "background-position: right 10px center" in dark_chevron
    assert "background-image: url(\"data:image/svg+xml" in light_chevron
    assert "bg-ground/90 backdrop-blur" in navbar and "overflow-hidden bg-ground" in navbar
    assert '"pt-20 pb-12 md:pt-20 md:pb-11"' in section
    assert 'level === "h1" ? "mt-8 md:mt-6" : "mt-10 md:mt-12"' in section
    assert 'className="relative rounded-md border border-hairline bg-ground-alt p-4"' in hero
    assert 'className="relative mx-auto aspect-[365/620] w-full max-w-[365px] overflow-hidden rounded-md bg-ground-alt"' in hero
    assert 'className="hero-loading absolute inset-0 flex items-center justify-center"' in hero
    assert 'className="hero-verdict absolute inset-0 overflow-hidden rounded-md"' in hero
    assert "hero-loading-image" not in css and "hero-loading-backdrop" not in css
    assert "hero-loading-backdrop" not in hero and "mix-blend-mode" not in css
    assert '<dl>\n        <Figure' in proof and "<dt " in proof and "<dd " in proof
    assert "sm:grid-cols-[auto_minmax(0,1fr)]" in proof
    assert 'role="status"' in footer and '{message &&' not in footer
    assert 'border-y border-hairline md:hidden"' in registry
    assert 'className="hidden overflow-x-auto md:block"' in registry
    assert 'className="lg:hidden"' in registry and 'className="hidden lg:block"' in registry
    assert "min-w-[900px]" not in registry
    assert "flex flex-nowrap" in registry and "whitespace-nowrap" in registry
    assert 'aria-labelledby="registry-records-heading"' in registry
    assert 'aria-labelledby="deployed-contracts-heading"' in registry
    assert '<span className="whitespace-nowrap">/launchalerts</span>' in chains


def test_proof_uses_real_figure_terms_and_one_source_link_for_stats():
    proof = read(COMPONENTS / "Proof.tsx")
    metrics = proof[proof.index("function Metrics"):proof.index("function simulationSteps")]
    source_time = read(COMPONENTS / "SourceTime.tsx")

    assert metrics.count("<Figure") == 4
    assert metrics.count("<SourceTime") == 1
    assert "<dt className=" in proof and "<dd className=" in proof
    assert "Launch data unavailable" not in proof
    assert "{launch && (steps ?" in proof
    assert source_time.count('aria-label={`Source fetched at ${time} UTC`}') == 1
    for component in ("Proof.tsx", "Registry.tsx", "Chains.tsx"):
        assert 'import SourceTime from "./SourceTime";' in read(COMPONENTS / component)
