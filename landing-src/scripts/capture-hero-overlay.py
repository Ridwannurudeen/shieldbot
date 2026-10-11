"""Capture the landing page's overlay images: the real extension overlay, fed a recorded API reply.

Branded Chrome 137 and later ignores --load-extension, so the extension is not loaded. Instead the
unmodified extension/content.js runs in a test page at https://dapp.example/ inside real headless
Chrome, with a stubbed `chrome` API (runtime and storage only). The page sends the request the way
the extension's inject.js does (the channel token it hands content.js, an intercept message with a
real HMAC proof), and the stub answers content.js's analysis request with the recorded reply, so the
dialog is the one content.js builds, in its closed shadow root, styled by the real overlay.css.
The request itself is not re-sent: the reply is what POST /api/firewall answered to it (see
hero-overlay-recordings.json). Every request outside dapp.example is aborted.

Each run writes one image to ../public:
    python capture-hero-overlay.py --request hero-overlay-request.json \
        --response hero-overlay-response.json --out hero-overlay.webp
Options: --state loading captures the "Analyzing transaction..." dialog (the reply never arrives);
--width sets the viewport width (default 1280); --keep-height keeps that many CSS pixels of the
dialog from its top; --chain-id overrides the request's chain; --verify only checks that the reply's
evidence_url still answers (evidence is kept 90 days) and exits.
The landing page's images:
    hero-overlay.webp          --request hero-overlay-request.json --response hero-overlay-response.json
    hero-overlay-mobile.webp   the same, --width 390 --keep-height 496
    hero-overlay-loading.webp  the same, --state loading
    hero-overlay-safe.webp     --request hero-overlay-safe-request.json --response hero-overlay-safe-response.json --keep-height 300
    hero-overlay-unknown.webp  --request hero-overlay-unknown-request.json --response hero-overlay-unknown-response.json --keep-height 300
Needs Python with playwright, Google Chrome and Pillow. Not run in CI.
"""

import argparse
import io
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

SCRIPTS = Path(__file__).resolve().parent
EXTENSION = SCRIPTS.parent.parent / "extension"
PUBLIC = SCRIPTS.parent / "public"
ORIGIN = "https://dapp.example"

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Test dApp</title>
<style>body { margin: 0; background: #ffffff; color: #141414; font: 16px system-ui; padding: 40px; }</style>
<script>
let TOKEN = null;
document.addEventListener("shieldai:channel", e => { TOKEN = e.detail; e.preventDefault(); });
const REPLY = REPLY_JSON;
const chromeStub = {
  storage: {
    local: {
      get(defaults, cb) { cb({...defaults, language: "en", policyMode: "BALANCED", sentRecipients: []}); },
      set(value, cb) { if (cb) cb(); },
    },
    onChanged: { addListener() {} },
  },
  runtime: {
    getURL: path => "/ext/" + path,
    sendMessage(message, cb) {
      if (message.type === "SHIELDAI_ANALYZE") {
        window.__analyzed = message;
        // No reply for the loading capture: the dialog stays on "Analyzing transaction...".
        return REPLY === null ? new Promise(() => {}) : Promise.resolve({result: REPLY});
      }
      if (message.type === "SHIELDAI_CHECK_PHISHING") return Promise.resolve({result: {is_phishing: false}});
      if (cb) cb({});
      return Promise.resolve({});
    },
  },
};
async function intercept(tx) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(TOKEN), {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  const proof = Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode("req-1:intercept"))));
  window.postMessage({type: "SHIELDAI_TX_INTERCEPT", requestId: "req-1", method: "eth_sendTransaction", tx, proof}, "*");
}
</script>
<script src="/content-under-test.js"></script>
</head>
<body><h1>Test dApp</h1><p>Approve a token for the swap router.</p></body></html>
"""

CONTENT = (
    "(function (chrome) {\n"
    + (EXTENSION / "content.js").read_text(encoding="utf-8")
    + "\n})(chromeStub);\n"
)


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


def markers(reply):
    """Text the dialog must show for this reply: a coverage reason, else a danger signal, else its action."""
    found = [
        *filter(None, (reply.get("coverage_reasons") or {}).values()),
        *reply.get("danger_signals", []),
    ]
    return found or [reply["decoded_action"]]


def capture(request, reply, width, keep_height):
    def handle(route):
        url = route.request.url
        if url.startswith(f"{ORIGIN}/ext/"):
            path = EXTENSION / url.removeprefix(f"{ORIGIN}/ext/").split("?")[0]
            kind = "text/css" if path.suffix == ".css" else "application/json"
            route.fulfill(status=200, content_type=kind, body=path.read_bytes())
        elif url.startswith(f"{ORIGIN}/content-under-test.js"):
            route.fulfill(status=200, content_type="text/javascript", body=CONTENT)
        elif url.startswith(f"{ORIGIN}/"):
            body = PAGE.replace("REPLY_JSON", json.dumps(reply))
            route.fulfill(status=200, content_type="text/html", body=body)
        else:
            route.abort()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        try:
            page = browser.new_page(
                viewport={"width": width, "height": 1400}, device_scale_factor=2
            )
            page.route("**/*", handle)
            page.goto(f"{ORIGIN}/")
            page.wait_for_function("TOKEN !== null")
            page.evaluate(
                "tx => intercept(tx)",
                {
                    key: request[key]
                    for key in ("from", "to", "value", "data", "chainId")
                },
            )
            page.wait_for_function("window.__analyzed !== undefined")
            page.wait_for_timeout(1500)

            cdp = page.context.new_cdp_session(page)
            document = cdp.send("DOM.getDocument", {"depth": -1, "pierce": True})[
                "root"
            ]
            modal = find_node(document, "shieldai-modal")
            assert modal, "no overlay dialog on the page"
            html = cdp.send("DOM.getOuterHTML", {"nodeId": modal["nodeId"]})[
                "outerHTML"
            ]
            expected = ["shieldai-loading"] if reply is None else markers(reply)[:1]
            assert expected[0] in html, f"the dialog does not show {expected[0]!r}"
            quad = cdp.send("DOM.getBoxModel", {"nodeId": modal["nodeId"]})["model"][
                "border"
            ]
            x, y, right, bottom = quad[0], quad[1], quad[4], quad[5]
            height = bottom - y if keep_height is None else min(keep_height, bottom - y)
            return page.screenshot(
                clip={"x": x, "y": y, "width": right - x, "height": height}
            )
        finally:
            browser.close()


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--request", required=True, help="request fixture in this folder"
    )
    parser.add_argument(
        "--response", required=True, help="recorded reply fixture in this folder"
    )
    parser.add_argument("--out", help="image file name written to ../public")
    parser.add_argument("--state", choices=("loading", "verdict"), default="verdict")
    parser.add_argument("--chain-id", type=int, help="overrides the request's chainId")
    parser.add_argument("--width", type=int, default=1280)
    parser.add_argument("--keep-height", type=int)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="only check that the reply's evidence_url answers",
    )
    args = parser.parse_args()

    request = json.loads((SCRIPTS / args.request).read_text(encoding="utf-8"))
    reply = json.loads((SCRIPTS / args.response).read_text(encoding="utf-8"))
    if args.verify:
        try:
            with urllib.request.urlopen(reply["evidence_url"], timeout=30) as answer:
                print(f"{args.response}: evidence {answer.status}")
        except urllib.error.HTTPError as e:
            sys.exit(
                f"{args.response}: evidence_url answered {e.code}; record the reply again"
            )
        return
    if not args.out:
        parser.error("--out is required unless --verify is given")
    if args.chain_id is not None:
        request["chainId"] = args.chain_id
    png = capture(
        request,
        None if args.state == "loading" else reply,
        args.width,
        args.keep_height,
    )
    image = Image.open(io.BytesIO(png))
    image.save(PUBLIC / args.out, "WEBP", quality=82, method=6)
    print(f"{args.out}: {image.width}x{image.height}")


main()
