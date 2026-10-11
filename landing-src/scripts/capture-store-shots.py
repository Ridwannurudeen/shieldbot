r"""Capture the real 3.2.0 extension pages in one headless branded Chrome run.

This follows F1's method: real pages use worktree extension files with a stubbed
chrome API, including the real content.js, inject.js, and overlay.css. Branded
Chrome ignores --load-extension, so these scripts run as page init scripts.
All external requests are aborted and extension/locale files are served locally.
The single Playwright Chrome browser is closed after all captures.

Run:
  python landing-src/scripts/capture-store-shots.py --design-dir <design-folder>

"""

import argparse
import io
import json
import mimetypes
from pathlib import Path
from urllib.parse import unquote, urlparse

from PIL import Image
from playwright.sync_api import BrowserContext, Page, Route, sync_playwright


ROOT = Path(__file__).resolve().parents[2]
EXT = ROOT / "extension"
DEFAULT_DESIGN = ROOT / "artifacts" / "design"
SIZE = {"width": 1280, "height": 800}
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title></title>
<style>html,body{margin:0;min-height:100%;background:#F7F6F2}</style></head><body></body></html>"""

STUB = r"""
(() => {
  const language = __LANGUAGE__;
  const fixture = __FIXTURE__;
  const history = __HISTORY__;
  const chainId = __CHAIN_ID__;
  const data = {apiUrl:"https://api.shieldbotsecurity.online",enabled:true,policyMode:"BALANCED",
    language,selectedChainId:chainId,healthWallet:"",chatMessages:[],scanHistory:history};
  const listeners = [];
  const storage = {
    get(keys, cb) {
      const out = {};
      if (keys == null) Object.assign(out, data);
      else if (typeof keys === "string") { if (keys in data) out[keys] = data[keys]; }
      else if (Array.isArray(keys)) keys.forEach(k => { if (k in data) out[k] = data[k]; });
      else Object.entries(keys).forEach(([k,v]) => { out[k] = k in data ? data[k] : v; });
      if (cb) queueMicrotask(() => cb(out));
      return Promise.resolve(out);
    },
    set(values, cb) {
      const changes = {};
      Object.entries(values).forEach(([k,v]) => { changes[k] = {oldValue:data[k],newValue:v}; data[k] = v; });
      listeners.forEach(fn => fn(changes,"local"));
      if (cb) queueMicrotask(cb);
      return Promise.resolve();
    },
  };
  const runtime = {
    lastError:null,
    getURL(path) { return "http://localhost/extension/" + String(path).replace(/^\/+/,""); },
    getManifest() { return {version:"3.2.0"}; },
    onMessage:{addListener(){}},
    sendMessage(message, cb) {
      let result = {};
      if (message && message.type === "SHIELDAI_ANALYZE") {
        globalThis.__analysisTx = message.tx;
        globalThis.__analysisResult = fixture;
        result = {result:fixture};
      }
      if (message && message.type === "SHIELDAI_GET_HISTORY") result = {history};
      const promise = Promise.resolve(result);
      if (cb) promise.then(cb);
      return promise;
    },
  };
  Object.defineProperty(globalThis,"chrome",{value:{
    runtime, storage:{local:storage,onChanged:{addListener(fn){listeners.push(fn);}}},
    permissions:{contains(){return Promise.resolve(true);},request(){return Promise.resolve(true);}},
    tabs:{create(){return Promise.resolve({id:1});},query(){return Promise.resolve([]);}},
    windows:{getCurrent(){return Promise.resolve({id:1});}}, sidePanel:{open(){return Promise.resolve();}},
    i18n:{getMessage(k){return k;},getUILanguage(){return language;}},
  }});
  Object.defineProperty(window,"ethereum",{configurable:true,writable:true,value:{
    on(){},request(args){if(args && args.method==="eth_chainId") return Promise.resolve("0x"+chainId.toString(16));return new Promise(()=>{});}
  }});
})();
"""

AUDIT = r"""() => {
 const rgba=s=>{const m=s.match(/rgba?\(([^)]+)\)/);if(!m)return[0,0,0,1];const p=m[1].split(",").map(x=>parseFloat(x.trim()));return[p[0],p[1],p[2],p.length>3?p[3]:1];};
 const over=(f,b)=>{const a=f[3],o=a+b[3]*(1-a);if(!o)return[0,0,0,0];return[(f[0]*a+b[0]*b[3]*(1-a))/o,(f[1]*a+b[1]*b[3]*(1-a))/o,(f[2]*a+b[2]*b[3]*(1-a))/o,o];};
 const c=x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4;};
 const lum=x=>.2126*c(x[0])+.7152*c(x[1])+.0722*c(x[2]);
 const ratio=(a,b)=>(Math.max(lum(a),lum(b))+.05)/(Math.min(lum(a),lum(b))+.05);
 const measure=e=>{
  const s=getComputedStyle(e),chain=[];
  for(let n=e;n;n=n.parentElement||(n.getRootNode&&n.getRootNode().host))chain.push(n);
  let bg=[255,255,255,1];for(const n of chain.slice().reverse()){const x=rgba(getComputedStyle(n).backgroundColor);if(x[3]>0)bg=over(x,bg);}
  let opacity=1;for(const n of chain)opacity*=parseFloat(getComputedStyle(n).opacity||"1");
  const fg=rgba(s.color);fg[3]*=opacity;const shown=over(fg,bg);
  const text=Array.from(e.childNodes).filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent.trim()).filter(Boolean).join(" ");
  const r=e.getBoundingClientRect();
  return{text,color:s.color,background:"rgb("+bg.slice(0,3).map(Math.round).join(", ")+")",
   contrast:Number(ratio(shown,bg).toFixed(2)),fontFamily:s.fontFamily,fontWeight:parseInt(s.fontWeight,10)||400,
   tag:e.tagName.toLowerCase(),rect:{x:Math.round(r.x),y:Math.round(r.y),width:Math.round(r.width),height:Math.round(r.height)}};
 };
 const pairs=[];
 for(const e of document.querySelectorAll("body *")){
  if(!Array.from(e.childNodes).some(n=>n.nodeType===Node.TEXT_NODE&&n.textContent.trim()))continue;
  const s=getComputedStyle(e);if(s.display==="none"||s.visibility==="hidden"||parseFloat(s.opacity)===0||!e.getClientRects().length)continue;
  const p=measure(e);if(p.text)pairs.push(p);
 }
 const d=document.documentElement,b=document.body;
 return{viewport:{width:d.clientWidth,height:d.clientHeight},horizontalOverflow:Math.max(d.scrollWidth,b.scrollWidth)>d.clientWidth,
  scrollWidth:Math.max(d.scrollWidth,b.scrollWidth),visibleText:pairs};
}"""

NODE_AUDIT = r"""function(){
 const rgba=s=>{const m=s.match(/rgba?\(([^)]+)\)/);if(!m)return[0,0,0,1];const p=m[1].split(",").map(x=>parseFloat(x.trim()));return[p[0],p[1],p[2],p.length>3?p[3]:1];};
 const over=(f,b)=>{const a=f[3],o=a+b[3]*(1-a);if(!o)return[0,0,0,0];return[(f[0]*a+b[0]*b[3]*(1-a))/o,(f[1]*a+b[1]*b[3]*(1-a))/o,(f[2]*a+b[2]*b[3]*(1-a))/o,o];};
 const c=x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4;};
 const lum=x=>.2126*c(x[0])+.7152*c(x[1])+.0722*c(x[2]),ratio=(a,b)=>(Math.max(lum(a),lum(b))+.05)/(Math.min(lum(a),lum(b))+.05);
 const s=getComputedStyle(this),chain=[];for(let n=this;n;n=n.parentElement||(n.getRootNode&&n.getRootNode().host))chain.push(n);
 let bg=[255,255,255,1];for(const n of chain.slice().reverse()){const x=rgba(getComputedStyle(n).backgroundColor);if(x[3]>0)bg=over(x,bg);}
 let opacity=1;for(const n of chain)opacity*=parseFloat(getComputedStyle(n).opacity||"1");
 const fg=rgba(s.color);fg[3]*=opacity;const shown=over(fg,bg);
 const text=Array.from(this.childNodes).filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent.trim()).filter(Boolean).join(" ");
 if(!text||!this.getClientRects().length||s.display==="none"||s.visibility==="hidden")return null;
 const r=this.getBoundingClientRect();
 return{text,color:s.color,background:"rgb("+bg.slice(0,3).map(Math.round).join(", ")+")",
  contrast:Number(ratio(shown,bg).toFixed(2)),fontFamily:s.fontFamily,fontWeight:parseInt(s.fontWeight,10)||400,
  tag:this.tagName.toLowerCase(),rect:{x:Math.round(r.x),y:Math.round(r.y),width:Math.round(r.width),height:Math.round(r.height)}};
}"""

def audit_pairs(result: dict) -> dict:
    pairs = result["visibleText"]
    result["minimumContrast"] = min((x["contrast"] for x in pairs), default=None)
    result["contrastFailures"] = [x for x in pairs if x["contrast"] < 4.5]
    result["fontWeightsAbove600"] = [
        x for x in pairs if x["fontWeight"] > 600 and x["tag"] not in
        {"h1", "h2", "h3", "h4", "h5", "h6"}
    ]
    return result


def load_fixtures() -> dict[str, dict]:
    fixture_files = {
        "block": ("hero-overlay-request.json", "hero-overlay-response.json"),
        "unknown": ("hero-overlay-unknown-request.json", "hero-overlay-unknown-response.json"),
    }
    fixtures = {}
    for name, filenames in fixture_files.items():
        pair = {}
        for key, filename in zip(("request", "response"), filenames):
            path = Path(__file__).resolve().parent / filename
            with path.open("r", encoding="utf-8", newline="") as source:
                pair[key] = json.load(source)
        fixtures[name] = pair
    return fixtures


def history_record(request: dict, response: dict) -> dict:
    return {
        **response,
        "to": request["to"],
        "recipient": response["transaction_impact"]["recipient"],
    }


def stub(locale: str, fixture: dict | None = None, history: list[dict] | None = None, chain_id: int = 56) -> str:
    return (
        STUB.replace("__LANGUAGE__", json.dumps(locale))
        .replace("__FIXTURE__", json.dumps(fixture, ensure_ascii=True))
        .replace("__HISTORY__", json.dumps(history or [], ensure_ascii=True))
        .replace("__CHAIN_ID__", str(chain_id))
    )


def route_local(route: Route) -> None:
    url = urlparse(route.request.url)
    if url.netloc == "localhost" and url.path == "/":
        route.fulfill(status=200, content_type="text/html; charset=utf-8", body=PAGE)
    elif url.netloc == "localhost" and url.path.startswith("/extension/"):
        rel = unquote(url.path[len("/extension/"):])
        if not rel or rel.startswith(".env"):
            route.abort()
            return
        path = (EXT / rel).resolve()
        if not path.is_relative_to(EXT.resolve()) or not path.is_file():
            route.fulfill(status=404, content_type="text/plain", body="Not found")
            return
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if mime.startswith("text/") or mime in {"application/javascript", "application/json"}:
            with path.open("r", encoding="utf-8", newline="") as source:
                body = source.read().encode("utf-8")
            if mime in {"text/html", "text/css", "application/javascript"}:
                mime += "; charset=utf-8"
        else:
            body = path.read_bytes()
        route.fulfill(status=200, content_type=mime, body=body)
    else:
        route.abort()


def watch(page: Page) -> list[str]:
    errors: list[str] = []
    page.on("console", lambda msg: errors.append(msg.text)
            if msg.type == "error" and "Failed to load resource: net::ERR_FAILED" not in msg.text else None)
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    return errors


def context_for(browser, locale: str, history: list[dict] | None = None, chain_id: int = 56) -> BrowserContext:
    context = browser.new_context(viewport=SIZE, device_scale_factor=1)
    context.route("**/*", route_local)
    context.add_init_script(stub(locale, history=history, chain_id=chain_id))
    return context


def page_for(context: BrowserContext, path: str, width: int, height: int) -> tuple[Page, list[str]]:
    page = context.new_page()
    page.set_viewport_size({"width": width, "height": height})
    errors = watch(page)
    page.goto("http://localhost/extension/" + path, wait_until="domcontentloaded")
    page.wait_for_timeout(300)
    return page, errors


def closed_shadow_text(page: Page) -> list[dict]:
    cdp = page.context.new_cdp_session(page)
    root = cdp.send("DOM.getDocument", {"depth": -1, "pierce": True})["root"]
    elements: list[dict] = []

    def visit(node: dict, in_shadow: bool = False) -> None:
        children = node.get("children", [])
        if in_shadow and node.get("nodeId") and any(
            child.get("nodeName") == "#text" and child.get("nodeValue", "").strip()
            for child in children
        ):
            elements.append(node)
        for child in children:
            visit(child, in_shadow)
        for shadow in node.get("shadowRoots", []):
            visit(shadow, True)

    visit(root)
    pairs = []
    for node in elements:
        resolved = cdp.send("DOM.resolveNode", {"nodeId": node["nodeId"]})
        object_id = resolved.get("object", {}).get("objectId")
        if object_id:
            value = cdp.send("Runtime.callFunctionOn", {
                "objectId": object_id, "functionDeclaration": NODE_AUDIT, "returnByValue": True,
            }).get("result", {}).get("value")
            if value:
                pairs.append(value)
    cdp.detach()
    return pairs


def render_overlay(browser, name: str, pair: dict, store_dir: Path, render_dir: Path, report: dict) -> None:
    request = pair["request"]
    response = pair["response"]
    context = browser.new_context(viewport=SIZE, device_scale_factor=1)
    context.route("**/*", route_local)
    sources = []
    for filename in ("content.js", "inject.js"):
        with (EXT / filename).open("r", encoding="utf-8", newline="") as source:
            sources.append(source.read())
    context.add_init_script(stub("en", response, chain_id=request["chainId"]) + "\n" + "\n".join(sources))
    page = context.new_page()
    page.set_viewport_size(SIZE)
    errors = watch(page)
    page.goto("http://localhost/", wait_until="domcontentloaded")
    page.evaluate("""() => { window.__overlayShown = false; window.addEventListener("message", event => { if (event.data && event.data.type === "SHIELDAI_TX_SHOWN") window.__overlayShown = true; }); }""")
    tx = {key: request[key] for key in ("from", "to", "value", "data")}
    page.evaluate("""tx => { void window.ethereum.request({method:"eth_sendTransaction",params:[tx]}); }""", tx)
    page.wait_for_function("window.__overlayShown === true && window.__analysisTx && window.__analysisResult", timeout=15_000)
    page.wait_for_timeout(900)
    actual_tx = page.evaluate("() => window.__analysisTx")
    if any(actual_tx.get(key) != value for key, value in tx.items()):
        raise RuntimeError(name + " overlay request did not match its recorded fixture: " + repr(actual_tx))
    if page.evaluate("() => window.__analysisResult") != response:
        raise RuntimeError(name + " overlay did not use its recorded response")
    pairs = closed_shadow_text(page)
    audit = audit_pairs({"visibleText": pairs})
    audit["horizontalOverflow"] = page.evaluate(
        "() => Math.max(document.documentElement.scrollWidth,document.body.scrollWidth)>document.documentElement.clientWidth"
    )
    audit["consoleErrors"] = errors
    all_text = "\n".join(item["text"] for item in pairs)
    markers = list(response.get("coverage_reasons", {}).values()) + response.get("danger_signals", [])
    markers.extend(response["transaction_impact"].values())
    if not any(marker and marker in all_text for marker in markers) or not pairs or errors or audit["contrastFailures"] or audit["horizontalOverflow"]:
        raise RuntimeError(name + " overlay audit failed: " + repr(audit))
    filename = "01-block-overlay.png" if name == "block" else "02-unknown-overlay.png"
    image = page.screenshot()
    for output_dir in (store_dir, render_dir):
        (output_dir / filename).write_bytes(image)
    report["overlays"][name] = audit
    page.close()
    context.close()


def render_surface(browser, report: dict, locale: str, name: str, path: str, size: dict, history: list[dict], chain_id: int, output: Path | None = None) -> None:
    context = context_for(browser, locale, history, chain_id)
    page, errors = page_for(context, path, size["width"], size["height"])
    audit = audit_pairs(page.evaluate(AUDIT))
    audit["consoleErrors"] = errors
    if errors or audit["horizontalOverflow"] or audit["contrastFailures"]:
        raise RuntimeError(locale + " " + name + " audit failed: " + repr(audit))
    report["surfaces"].setdefault(locale, {})[name] = audit
    if output:
        page.screenshot(path=str(output), full_page=False)
    page.close()
    context.close()


def store_canvas(browser, path: str, output: Path, history: list[dict], chain_id: int) -> dict:
    context = context_for(browser, "en", history, chain_id)
    page, errors = page_for(context, path, 1280, 800)
    audit = audit_pairs(page.evaluate(AUDIT))
    audit["consoleErrors"] = errors
    if errors or audit["horizontalOverflow"] or audit["contrastFailures"]:
        raise RuntimeError(path + " store screenshot audit failed: " + repr(audit))
    page.screenshot(path=str(output), full_page=False)
    page.close()
    context.close()
    return audit


def render_welcome_crop(browser, outputs: list[Path]) -> dict:
    context = browser.new_context(viewport={"width": 960, "height": 1000}, device_scale_factor=2)
    context.route("**/*", route_local)
    context.add_init_script(stub("en"))
    page = context.new_page()
    errors = watch(page)
    page.goto("http://localhost/extension/welcome.html", wait_until="domcontentloaded")
    page.wait_for_timeout(100)
    card = page.locator(".card").bounding_box()
    simulate = page.locator(".steps .step").nth(1).bounding_box()
    if not card or not simulate or errors:
        raise RuntimeError("welcome capture could not find its first-step crop boundary: " + repr(errors))
    crop = page.screenshot(clip={
        "x": card["x"], "y": card["y"], "width": card["width"], "height": simulate["y"] - card["y"],
    })
    with Image.open(io.BytesIO(crop)) as source:
        panel = source.convert("RGB")
    max_size = (1280, 752)
    if panel.width > max_size[0] or panel.height > max_size[1]:
        panel.thumbnail(max_size, Image.Resampling.LANCZOS)
    canvas = Image.new("RGB", (1280, 800), (247, 246, 242))
    canvas.paste(panel, ((canvas.width - panel.width) // 2, (canvas.height - panel.height) // 2))
    for output in outputs:
        canvas.save(output, "PNG")
    result = {"dimensions": list(canvas.size), "croppedBeforeStep": "Simulate", "panelDimensions": list(panel.size)}
    page.close()
    context.close()
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--design-dir", type=Path, default=DEFAULT_DESIGN)
    args = parser.parse_args()
    design_dir = args.design_dir.resolve()
    store_dir = design_dir / "store-shots-3.2.0"
    shots_dir = design_dir / "shots-F2" / "fix"
    store_dir.mkdir(parents=True, exist_ok=True)
    shots_dir.mkdir(parents=True, exist_ok=True)
    store_files = ("01-block-overlay.png", "02-unknown-overlay.png", "03-popup-expanded.png", "05-welcome.png")
    stale_store_files = store_files + ("03-popup-compact.png", "04-sidepanel.png")
    render_files = ("01-block-overlay.png", "02-unknown-overlay.png", "popup-history.png", "popup-expanded.png", "welcome-cropped.png", "sidepanel.png", "report.json")
    for filename in stale_store_files:
        stale = store_dir / filename
        if stale.exists():
            stale.unlink()
    for filename in render_files:
        stale = shots_dir / filename
        if stale.exists():
            stale.unlink()
    fixtures = load_fixtures()
    block_history = [history_record(fixtures["block"]["request"], fixtures["block"]["response"])]
    chain_id = fixtures["block"]["request"]["chainId"]
    report = {"chromeChannel":"chrome","headless":True,"browserLaunchCount":1,
              "storeCaptures":[],"actualSizeRenders":{},"surfaces":{},"overlays":{}}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        try:
            for name in ("block", "unknown"):
                render_overlay(browser, name, fixtures[name], store_dir, shots_dir, report)
            for locale in ("en", "zh", "vi"):
                expanded_output = shots_dir / "popup-expanded.png" if locale == "en" else None
                render_surface(browser, report, locale, "popup-expanded", "popup.html?tab=1", SIZE,
                               block_history, chain_id, expanded_output)
                render_surface(browser, report, locale, "welcome", "welcome.html", SIZE, [], chain_id)
            expanded_audit = store_canvas(browser, "popup.html?tab=1", store_dir / "03-popup-expanded.png", block_history, chain_id)
            report["storeCaptures"].append({"file":"03-popup-expanded.png","audit":expanded_audit})
            welcome_outputs = [store_dir / "05-welcome.png", shots_dir / "welcome-cropped.png"]
            report["welcomeCrop"] = render_welcome_crop(browser, welcome_outputs)
        finally:
            browser.close()
    for filename, name in (("01-block-overlay.png", "block"), ("02-unknown-overlay.png", "unknown")):
        report["storeCaptures"].append({"file":filename,"audit":report["overlays"][name]})
    report["storeCaptures"].append({"file":"05-welcome.png","audit":report["surfaces"]["en"]["welcome"]})
    report["storeCaptures"].sort(key=lambda item:item["file"])
    for filename in store_files:
        path = store_dir / filename
        with Image.open(path) as image:
            if image.size != (1280,800):
                raise RuntimeError(path.name + " has wrong dimensions: " + repr(image.size))
    report["actualSizeRenders"] = {
        name:str(shots_dir / filename) for name, filename in (
            ("overlay-block", "01-block-overlay.png"),
            ("overlay-unknown", "02-unknown-overlay.png"),
            ("popup-expanded", "popup-expanded.png"),
            ("welcome-cropped", "welcome-cropped.png"),
        )
    }
    report["storeCapturePaths"] = [str(store_dir / item["file"]) for item in report["storeCaptures"]]
    report["renderPaths"] = list(report["actualSizeRenders"].values())
    report["allContrastPairsMeet4_5"] = all(
        not item["audit"]["contrastFailures"] for item in report["storeCaptures"]
    ) and all(not item["contrastFailures"] for group in report["surfaces"].values() for item in group.values())
    report["noHorizontalOverflow"] = all(
        not item["audit"].get("horizontalOverflow", False) for item in report["storeCaptures"]
    ) and all(not item["horizontalOverflow"] for group in report["surfaces"].values() for item in group.values())
    report["weightsAbove600"] = [
        {"locale":locale,"surface":name,"pairs":audit["fontWeightsAbove600"]}
        for locale,group in report["surfaces"].items() for name,audit in group.items()
        if audit["fontWeightsAbove600"]
    ] + [
        {"surface":"overlay-"+name,"pairs":audit["fontWeightsAbove600"]}
        for name,audit in report["overlays"].items() if audit["fontWeightsAbove600"]
    ]
    report_path = shots_dir / "report.json"
    with report_path.open("w", encoding="utf-8", newline="") as output:
        output.write(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({
        "storeCaptures":report["storeCapturePaths"],"renderPaths":report["renderPaths"],
        "report":str(report_path),"contrastPass":report["allContrastPairsMeet4_5"],
        "horizontalOverflow":not report["noHorizontalOverflow"],"weightsAbove600":report["weightsAbove600"],
    },ensure_ascii=False,indent=2))

if __name__ == "__main__":
    main()
