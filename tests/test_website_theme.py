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
    # Expected red on the Opus branch until the Codex branch (static pages, /try, dashboard) is merged.
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
    # A parse, never a byte comparison: whitespace in one copy cannot fail it. The dashboard clause is expected red on
    # the Opus branch until the Codex branch is merged.
    landing = token_blocks(read(INDEX_CSS), triplets)
    tokens_css = token_blocks(read(LANDING_SRC / "public" / "css" / "tokens.css"), hexes)
    assert tokens_css == landing
    assert token_blocks(read(DASHBOARD_SRC), hexes) == landing


def test_every_page_has_a_theme_toggle():
    # The landing's switch is one component, mounted once in the nav. Expected red on the Opus branch for the static
    # pages, /try and the dashboard until the Codex branch is merged.
    toggle = read(COMPONENTS / "ThemeToggle.tsx")
    assert (
        toggle.count('role="switch"') == 1
        and toggle.count('aria-label="Light theme"') == 1
    )
    assert read(COMPONENTS / "Navbar.tsx").count("<ThemeToggle />") == 1
    for page in [
        *STATIC_PAGES,
        LANDING_SRC / "public" / "try" / "index.html",
        DASHBOARD_SRC,
    ]:
        html = read(page)
        assert html.count('role="switch"') == 1, page
        assert html.count('aria-label="Light theme"') == 1, page


def test_unknown_is_never_amber():
    # Expected red on the Opus branch for /try (its --amber) until the Codex branch is merged.
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
