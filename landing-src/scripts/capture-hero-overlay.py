"""Capture the landing page's hero image: the real extension overlay, fed a recorded API reply.

The extension in ../../extension is loaded unpacked into Playwright's bundled Chromium. A test page
with a stub wallet sends the transaction in hero-overlay-request.json; the extension's
POST /api/firewall is answered with hero-overlay-response.json, the verbatim reply of
https://api.shieldbotsecurity.online/api/firewall to that same request on 2026-09-26 at 07:14 UTC.
No other API request is answered, so the capture never reaches the network.

Writes ../public/hero-overlay.webp (desktop) and ../public/hero-overlay-mobile.webp.
Needs Python with playwright (and `playwright install chromium`) and Pillow:
    python landing-src/scripts/capture-hero-overlay.py
"""

import io
import json
import shutil
import tempfile
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

SCRIPTS = Path(__file__).resolve().parent
EXTENSION = SCRIPTS.parent.parent / "extension"
PUBLIC = SCRIPTS.parent / "public"
REQUEST = json.loads((SCRIPTS / "hero-overlay-request.json").read_text(encoding="utf-8"))
RESPONSE = (SCRIPTS / "hero-overlay-response.json").read_text(encoding="utf-8")
PAGE_URL = "https://dapp.example/"
API = "https://api.shieldbotsecurity.online"

# (output file, viewport width, CSS pixels of the dialog to keep from its top; None keeps it all)
SHOTS = [("hero-overlay.webp", 1280, None), ("hero-overlay-mobile.webp", 390, 496)]

PAGE = """<!DOCTYPE html>
<html lang="en"><head><title>Test dApp</title>
<style>body { margin: 0; background: #0a0f1c; color: #e2e8f0; font: 16px system-ui; padding: 40px; }</style>
<script>
  // Stub wallet on the request's chain. It never signs: the capture stops at the overlay.
  window.ethereum = {
    on() {},
    request(args) {
      if (args.method === "eth_chainId") return Promise.resolve("CHAIN_ID");
      return new Promise(() => {});
    },
  };
</script></head>
<body><h1>Test dApp</h1><p>Approve a token for the swap router.</p></body></html>
""".replace("CHAIN_ID", hex(REQUEST["chainId"]))


def find_node(node, class_name):
    """The first node in a pierced DOM.getDocument tree carrying class_name, closed shadow roots included."""
    attributes = node.get("attributes", [])
    classes = dict(zip(attributes[::2], attributes[1::2])).get("class", "").split()
    if class_name in classes:
        return node
    for child in node.get("children", []) + node.get("shadowRoots", []):
        found = find_node(child, class_name)
        if found:
            return found
    return None


def capture(context, width, keep_height):
    seen = {"phishing": 0, "firewall": 0}

    def api(route):
        request = route.request
        if request.url.startswith(f"{API}/api/phishing"):
            seen["phishing"] += 1
            route.abort()
        elif request.url == f"{API}/api/firewall" and request.method == "POST":
            sent = json.loads(request.post_data)
            assert sent == REQUEST, f"the extension sent {sent}, not the recorded request"
            seen["firewall"] += 1
            route.fulfill(status=200, content_type="application/json", body=RESPONSE)
        else:
            route.abort()

    page = context.new_page()
    page.set_viewport_size({"width": width, "height": 1400})
    page.route(
        PAGE_URL, lambda route: route.fulfill(status=200, content_type="text/html", body=PAGE)
    )
    context.route(f"{API}/**", api)
    page.goto(PAGE_URL)
    # The phishing check runs from the extension's service worker on load. Seeing it here proves
    # that worker's requests are routed, so the firewall request below cannot reach the live API.
    for _ in range(50):
        if seen["phishing"]:
            break
        page.wait_for_timeout(100)
    assert seen["phishing"], (
        "the extension's API requests are not routed; refusing to send the transaction"
    )

    transaction = {key: REQUEST[key] for key in ("from", "to", "value", "data")}
    page.evaluate(
        "tx => { window.ethereum.request({method: 'eth_sendTransaction', params: [tx]}); }",
        transaction,
    )
    for _ in range(100):
        if seen["firewall"]:
            break
        page.wait_for_timeout(100)
    assert seen["firewall"] == 1, "the extension did not ask for the firewall verdict"
    page.wait_for_timeout(1500)

    cdp = context.new_cdp_session(page)
    document = cdp.send("DOM.getDocument", {"depth": -1, "pierce": True})["root"]
    modal = find_node(document, "shieldai-modal")
    assert modal, "no overlay dialog on the page"
    html = cdp.send("DOM.getOuterHTML", {"nodeId": modal["nodeId"]})["outerHTML"]
    reply = json.loads(RESPONSE)
    # A reply with full coverage has no coverage reason; the overlay lists its danger signals.
    markers = [*filter(None, reply["coverage_reasons"].values()), *reply.get("danger_signals", [])]
    assert markers, "the recorded reply has no coverage reason or danger signal to look for"
    assert markers[0] in html, "the overlay does not show the recorded response"
    quad = cdp.send("DOM.getBoxModel", {"nodeId": modal["nodeId"]})["model"]["border"]
    x, y, right, bottom = quad[0], quad[1], quad[4], quad[5]
    height = bottom - y if keep_height is None else min(keep_height, bottom - y)
    png = page.screenshot(clip={"x": x, "y": y, "width": right - x, "height": height})
    page.close()
    context.unroute(f"{API}/**", api)
    return png


profile = tempfile.mkdtemp()
try:
    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            profile,
            channel="chromium",
            headless=True,
            device_scale_factor=2,
            args=[f"--disable-extensions-except={EXTENSION}", f"--load-extension={EXTENSION}"],
        )
        for name, width, keep_height in SHOTS:
            image = Image.open(io.BytesIO(capture(context, width, keep_height)))
            image.save(PUBLIC / name, "WEBP", quality=82, method=6)
            print(f"{name}: {image.width}x{image.height}")
        context.close()
finally:
    shutil.rmtree(profile, ignore_errors=True)
