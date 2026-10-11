r"""Capture the real 3.2.0 extension pages in one headless branded Chrome run.

This follows F1's method: real pages use worktree extension files with a stubbed
chrome API, including the real content.js, inject.js, and overlay.css. Branded
Chrome ignores --load-extension, so these scripts run as page init scripts.
All external requests are aborted and extension/locale files are served locally.
The single Playwright Chrome browser is closed after all captures.

Run:
  C:\Users\gudma\AppData\Local\Programs\Python\Python312\python.exe landing-src/scripts/capture-store-shots.py
"""

import json
import mimetypes
from pathlib import Path
from urllib.parse import unquote, urlparse

from PIL import Image
from playwright.sync_api import BrowserContext, Page, Route, sync_playwright


ROOT = Path(__file__).resolve().parents[2]
EXT = ROOT / "extension"
DESIGN = Path(r"C:\Users\gudma\OneDrive\Desktop\GITHUB-FILES\shieldbot-handoff\briefs\design")
STORE = DESIGN / "store-shots-3.2.0"
SHOTS = DESIGN / "shots-F2"
SIZE = {"width": 1280, "height": 800}
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Swap confirmation</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;padding:40px 64px;color:#f1f2f3;background:#121316;font:14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{display:flex;align-items:center;gap:22px;color:#b8bac1}.brand{color:#fff;font-size:18px;font-weight:600}
main{width:420px;margin:100px auto;padding:24px;border:1px solid #303138;border-radius:12px;background:#1b1c21}
h1{margin:0 0 8px;color:#fff;font-size:22px}p{color:#b8bac1;line-height:1.5}
.token{display:flex;justify-content:space-between;margin:22px 0;padding:16px;border:1px solid #303138;border-radius:8px}
button{width:100%;padding:13px;border:0;border-radius:7px;background:#6d5ce7;color:white;font:600 14px sans-serif}
</style></head><body><header><span class="brand">NORTHSTAR</span><span>Swap</span><span>Explore</span><span>Portfolio</span></header>
<main><h1>Review swap</h1><p>Confirm the details before submitting this transaction.</p>
<div class="token"><span>Pay</span><strong>1.00 ETH</strong></div><div class="token"><span>Receive</span><strong>2,840.00 USDC</strong></div>
<button>Confirm swap</button></main></body></html>"""

FIXTURE = {
    "block": {
        "status": "ok", "partial": False, "classification": "BLOCK_RECOMMENDED",
        "risk_score": 94, "coverage": {"honeypot": 1, "goplus": 1},
        "coverage_reasons": {}, "verdict": "Block Recommended",
        "plain_english": "This approval could give a malicious contract access to your tokens.",
        "transaction_impact": {
            "sending": "0.01 ETH", "granting_access": "Unlimited USDC",
            "recipient": "0x7A250d5630B4cF539739dF2C5dAcb4c659F2488D",
            "post_tx_state": "The contract can move your USDC.",
        },
        "danger_signals": ["Unlimited token approval"], "notes": [],
    },
    "unknown": {
        "status": "unknown", "partial": False, "classification": "UNKNOWN",
        "risk_score": None, "coverage": {"honeypot": 0},
        "coverage_reasons": {"honeypot": "No provider returned a result."},
        "verdict": "Unknown", "plain_english": "The transaction could not be fully checked.",
        "transaction_impact": {
            "sending": "0.01 ETH", "granting_access": "Unknown",
            "recipient": "0x7A250d5630B4cF539739dF2C5dAcb4c659F2488D",
            "post_tx_state": "Unknown",
        },
        "danger_signals": [], "notes": [],
    },
}

STUB = r"""
(() => {
  const language = __LANGUAGE__;
  const fixture = __FIXTURE__;
  const data = {apiUrl:"https://api.shieldbotsecurity.online",enabled:true,policyMode:"BALANCED",
    language,selectedChainId:56,healthWallet:"",chatMessages:[],scanHistory:[]};
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
      if (message && message.type === "SHIELDAI_ANALYZE") result = {result:fixture};
      if (message && message.type === "SHIELDAI_GET_HISTORY") result = {history:[]};
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
    on(){},request(args){if(args && args.method==="eth_chainId") return Promise.resolve("0x1");return new Promise(()=>{});}
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


def stub(locale: str, fixture: dict) -> str:
    return STUB.replace("__LANGUAGE__", json.dumps(locale)).replace(
        "__FIXTURE__", json.dumps(fixture, ensure_ascii=True)
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
            body = path.read_text(encoding="utf-8").encode("utf-8")
            if mime in {"text/html", "text/css", "application/javascript"}:
                mime += "; charset=utf-8"
        else:
            body = path.read_bytes()
        route.fulfill(status=200, content_type=mime, body=body)
    elif url.netloc == "api.shieldbotsecurity.online" and url.path == "/api/health":
        route.fulfill(status=200, content_type="application/json", body='{"status":"ok"}')
    else:
        route.abort()


def watch(page: Page) -> list[str]:
    errors: list[str] = []
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    return errors


def context_for(browser, locale: str, fixture: dict) -> BrowserContext:
    context = browser.new_context(viewport=SIZE, device_scale_factor=1)
    context.route("**/*", route_local)
    context.add_init_script(stub(locale, fixture))
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


def render_overlay(browser, name: str, report: dict) -> None:
    context = browser.new_context(viewport=SIZE, device_scale_factor=1)
    context.route("**/*", route_local)
    context.add_init_script(
        stub("en", FIXTURE[name]) + "\n"
        + (EXT / "content.js").read_text(encoding="utf-8") + "\n"
        + (EXT / "inject.js").read_text(encoding="utf-8")
    )
    page = context.new_page()
    page.set_viewport_size(SIZE)
    errors = watch(page)
    page.goto("http://localhost/", wait_until="domcontentloaded")
    page.evaluate("""() => { window.__overlayShown = false; window.addEventListener("message", event => { if (event.data && event.data.type === "SHIELDAI_TX_SHOWN") window.__overlayShown = true; }); }""")
    page.evaluate("""() => { void window.ethereum.request({method:"eth_sendTransaction",params:[{
      from:"0x1111111111111111111111111111111111111111",
      to:"0x7A250d5630B4cF539739dF2C5dAcb4c659F2488D",
      value:"0x2386f26fc10000",data:"0x",chainId:"0x1"
    }]}); }""")
    page.wait_for_timeout(500)
    page.wait_for_function('window.__overlayShown === true', timeout=15_000)
    page.wait_for_timeout(900)
    pairs = closed_shadow_text(page)
    audit = audit_pairs({"visibleText": pairs})
    audit["horizontalOverflow"] = page.evaluate(
        "() => Math.max(document.documentElement.scrollWidth,document.body.scrollWidth)>document.documentElement.clientWidth"
    )
    audit["consoleErrors"] = errors
    if not pairs or errors or audit["contrastFailures"] or audit["horizontalOverflow"]:
        raise RuntimeError(name + " overlay audit failed: " + repr(audit))
    page.screenshot(path=str(STORE / ("01-block-overlay.png" if name == "block" else "02-unknown-overlay.png")))
    report["overlays"][name] = audit
    page.close()
    context.close()


def render_surface(browser, report: dict, locale: str, name: str, path: str, size: dict, output: Path | None = None) -> None:
    context = context_for(browser, locale, {})
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


def store_canvas(browser, path: str, output: Path, body_width: int | None = None) -> dict:
    context = context_for(browser, "en", {})
    page, errors = page_for(context, path, 1280, 800)
    if body_width:
        page.add_style_tag(content="body{width:"+str(body_width)+"px!important;margin-left:auto!important;margin-right:0!important}")
    audit = audit_pairs(page.evaluate(AUDIT))
    audit["consoleErrors"] = errors
    if errors or audit["horizontalOverflow"] or audit["contrastFailures"]:
        raise RuntimeError(path + " store screenshot audit failed: " + repr(audit))
    page.screenshot(path=str(output), full_page=False)
    page.close()
    context.close()
    return audit


def main() -> None:
    STORE.mkdir(parents=True, exist_ok=True)
    SHOTS.mkdir(parents=True, exist_ok=True)
    report = {"chromeChannel":"chrome","headless":True,"browserLaunchCount":1,
              "storeCaptures":[],"actualSizeRenders":{},"surfaces":{},"overlays":{}}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        try:
            render_overlay(browser, "block", report)
            render_overlay(browser, "unknown", report)
            sizes = {
                "popup-compact": ({"width":360,"height":800}, "popup.html"),
                "popup-expanded": ({"width":1280,"height":800}, "popup.html?tab=1"),
                "sidepanel": ({"width":400,"height":800}, "sidepanel.html"),
                "welcome": ({"width":1280,"height":800}, "welcome.html"),
            }
            for locale in ("en", "zh", "vi"):
                for name, (size, path) in sizes.items():
                    output = SHOTS / (name + ".png") if locale == "en" else None
                    render_surface(browser, report, locale, name, path, size, output)
            for filename, kind, path, width in (
                ("03-popup-compact.png","popup-compact","popup.html",None),
                ("04-sidepanel.png","sidepanel","sidepanel.html",400),
                ("05-welcome.png","welcome","welcome.html",None),
            ):
                report["storeCaptures"].append({
                    "file":filename,"audit":store_canvas(browser,path,STORE/filename,width)
                })
        finally:
            browser.close()
    for name in ("01-block-overlay.png","02-unknown-overlay.png"):
        report["storeCaptures"].append({
            "file":name,"audit":report["overlays"]["block" if name.startswith("01") else "unknown"]
        })
    report["storeCaptures"].sort(key=lambda item:item["file"])
    for path in STORE.glob("*.png"):
        with Image.open(path) as image:
            if image.size != (1280,800):
                raise RuntimeError(path.name + " has wrong dimensions: " + repr(image.size))
    report["actualSizeRenders"] = {
        name:str(SHOTS/(name+".png")) for name in
        ("popup-compact","popup-expanded","sidepanel","welcome")
    }
    report["storeCapturePaths"] = [str(STORE/item["file"]) for item in report["storeCaptures"]]
    report["renderPaths"] = list(report["actualSizeRenders"].values())
    report["allContrastPairsMeet4_5"] = all(
        not item["audit"]["contrastFailures"] for item in report["storeCaptures"]
    ) and all(not item["contrastFailures"] for group in report["surfaces"].values() for item in group.values())
    report["noHorizontalOverflow"] = all(
        not item["audit"]["horizontalOverflow"] for item in report["storeCaptures"]
    ) and all(not item["horizontalOverflow"] for group in report["surfaces"].values() for item in group.values())
    report["weightsAbove600"] = [
        {"locale":locale,"surface":name,"pairs":audit["fontWeightsAbove600"]}
        for locale,group in report["surfaces"].items() for name,audit in group.items()
        if audit["fontWeightsAbove600"]
    ] + [
        {"surface":"overlay-"+name,"pairs":audit["fontWeightsAbove600"]}
        for name,audit in report["overlays"].items() if audit["fontWeightsAbove600"]
    ]
    report_path = SHOTS / "report.json"
    report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="")
    print(json.dumps({
        "storeCaptures":report["storeCapturePaths"],"renderPaths":report["renderPaths"],
        "report":str(report_path),"contrastPass":report["allContrastPairsMeet4_5"],
        "horizontalOverflow":not report["noHorizontalOverflow"],"weightsAbove600":report["weightsAbove600"],
    },ensure_ascii=False,indent=2))


if __name__ == "__main__":
    main()
