/**
 * ShieldAI Background Service Worker
 * Receives intercepted tx data from content script, calls the VPS API,
 * and returns the firewall verdict. Saves scan history.
 */

const DEFAULT_API_URL = "https://api.shieldbotsecurity.online";
const MAX_HISTORY = 50;

// On install and on every extension update, store the default API URL unless
// the user saved their own, so storage never lacks one after an upgrade.
// Fresh installs also open the welcome tab.
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install" || details.reason === "update") {
    chrome.storage.local.get({ apiUrl: "" }, ({ apiUrl }) => {
      if (!apiUrl) chrome.storage.local.set({ apiUrl: DEFAULT_API_URL });
    });
  }
  if (details.reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
  }
});

// Phishing cache: host -> {is_phishing, expiresAt}
// Avoids repeated API calls when navigating across pages on the same site.
// Chrome stops an idle service worker, so the cache is also kept in
// chrome.storage.session, which content scripts cannot read and which lasts
// for the browser session. Only verdicts are kept, under the host alone.
const _phishingCache = new Map();
const PHISHING_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const MAX_PHISHING_CACHE = 500;
let _phishingCacheLoad = null;

function loadPhishingCache() {
  _phishingCacheLoad ||= chrome.storage.session.get({ phishingCache: {} }).then(({ phishingCache }) => {
    for (const [host, entry] of Object.entries(phishingCache)) _phishingCache.set(host, entry);
  });
  return _phishingCacheLoad;
}

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SHIELDAI_ANALYZE") {
    handleAnalyze(message.tx, sender)
      .then((result) => {
        saveToHistory(message.tx, result);
        sendResponse({ result });
      })
      .catch((err) => sendResponse({ error: err.message || "Unknown error" }));
    return true;
  }

  if (message.type === "SHIELDAI_CHECK_PHISHING") {
    checkPhishing(message.url)
      .then((result) => sendResponse({ result }))
      .catch(() => sendResponse({ result: { is_phishing: null } }));
    return true;
  }

  if (message.type === "SHIELDAI_HEALTH") {
    checkHealth()
      .then((status) => sendResponse({ status }))
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }

  if (message.type === "SHIELDAI_GET_HISTORY") {
    chrome.storage.local.get({ scanHistory: [] }, (data) => {
      sendResponse({ history: data.scanHistory });
    });
    return true;
  }

  if (message.type === "SHIELDAI_EXPLAIN") {
    (async () => {
      try {
        const apiUrl = await getApiUrl();
        const response = await fetch(`${apiUrl}/api/agent/explain`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scan_result: message.scanResult }),
          signal: AbortSignal.timeout(30000),
        });
        if (!response.ok) {
          sendResponse({ explanation: "Unable to generate explanation." });
          return;
        }
        const data = await response.json();
        sendResponse({ explanation: data.explanation || "No explanation available." });
      } catch (err) {
        sendResponse({ explanation: "Unable to generate explanation." });
      }
    })();
    return true;
  }

  if (message.type === "SHIELDAI_OPEN_SIDEPANEL") {
    const windowId = sender.tab?.windowId;
    if (!windowId) {
      sendResponse({ error: "No window context available" });
      return true;
    }
    chrome.sidePanel.open({ windowId })
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }

  if (message.type === "SHIELDAI_GET_GUARDIAN_ALERTS") {
    (async () => {
      try {
        const apiUrl = await getApiUrl();
        const response = await fetch(`${apiUrl}/api/guardian/alerts`, {
          method: "GET",
          signal: AbortSignal.timeout(15000),
        });
        if (!response.ok) {
          sendResponse({ error: `HTTP ${response.status}` });
          return;
        }
        const data = await response.json();
        sendResponse({ alerts: data });
      } catch (err) {
        sendResponse({ error: err.message || "Failed to fetch alerts" });
      }
    })();
    return true;
  }

  if (message.type === "SHIELDAI_SCAN_INJECTION") {
    (async () => {
      try {
        const apiUrl = await getApiUrl();
        const response = await fetch(`${apiUrl}/api/scan/injection`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(message.payload || {}),
          signal: AbortSignal.timeout(30000),
        });
        if (!response.ok) {
          sendResponse({ error: `HTTP ${response.status}` });
          return;
        }
        const data = await response.json();
        sendResponse({ result: data });
      } catch (err) {
        sendResponse({ error: err.message || "Injection scan failed" });
      }
    })();
    return true;
  }

  if (message.type === "SHIELDAI_GET_ACTIVE_TAB") {
    // Only allow extension pages (sidepanel/popup), not content scripts
    if (sender.tab) {
      sendResponse({ url: null });
      return true;
    }
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        sendResponse({ url: tabs[0].url, title: tabs[0].title });
      } else {
        sendResponse({ url: null });
      }
    });
    return true;
  }

});


async function checkPhishing(url) {
  try {
    const parsedUrl = new URL(url);
    const { hostname } = parsedUrl;
    const cacheKey = hostname.toLowerCase();
    const lookupUrl = `${parsedUrl.protocol}//${parsedUrl.host}/`;

    // Check extension-side cache
    await loadPhishingCache();
    const cached = _phishingCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return { is_phishing: cached.is_phishing };
    }

    // Get configured API URL — if not set, skip silently
    let apiUrl;
    try {
      apiUrl = await getApiUrl();
    } catch {
      console.warn("Phishing check skipped: no API URL configured");
      return { is_phishing: null, check_failed: true };
    }

    const response = await fetch(
      `${apiUrl}/api/phishing?url=${encodeURIComponent(lookupUrl)}`,
      {
        method: "GET",
        signal: AbortSignal.timeout(5000),
      }
    );

    if (!response.ok) {
      console.warn("Phishing check failed: HTTP", response.status);
      return { is_phishing: null, check_failed: true };
    }

    const result = await response.json();
    // is_phishing null is no verdict: show nothing and ask again next time
    if (typeof result.is_phishing !== "boolean") return result;
    // Evict oldest entry if cache is full
    if (_phishingCache.size >= MAX_PHISHING_CACHE) {
      const firstKey = _phishingCache.keys().next().value;
      _phishingCache.delete(firstKey);
    }
    _phishingCache.set(cacheKey, { is_phishing: result.is_phishing, expiresAt: Date.now() + PHISHING_CACHE_TTL_MS });
    chrome.storage.session.set({ phishingCache: Object.fromEntries(_phishingCache) });
    return result;
  } catch (err) {
    console.warn("Phishing check failed:", err.message || err);
    return { is_phishing: null, check_failed: true };
  }
}

function isAllowedUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol === "https:") return true;
    // Allow HTTP only for localhost (development mode)
    if (u.protocol === "http:") {
      const allowed = ["localhost", "127.0.0.1"];
      return allowed.includes(u.hostname);
    }
    return false;
  } catch {
    return false;
  }
}

async function getApiUrl() {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get({ apiUrl: DEFAULT_API_URL }, (data) => {
      const url = data.apiUrl || DEFAULT_API_URL;
      // Block disallowed URLs
      if (!url || !isAllowedUrl(url)) {
        reject(new Error("Invalid or missing API URL. Please configure a valid HTTPS endpoint in extension settings."));
        return;
      }
      resolve(url);
    });
  });
}

// The answer for a request whose wallet chain could not be read, does not
// match the request, or is not one the API supports: nothing was analysed,
// and the overlay offers only Block.
function unknownChain(reason) {
  return {
    status: "unknown",
    partial: true,
    classification: "UNKNOWN",
    risk_level: "UNKNOWN",
    risk_score: null,
    coverage: { chain: false },
    coverage_reasons: { chain: reason },
    verdict: "Unknown wallet chain. Reconnect the wallet and retry; the request is blocked.",
  };
}

// Sign-In with Ethereum (EIP-4361). A personal_sign message that says it is
// one is parsed strictly, as the reference parser reads it: every field in its
// order and form, and nothing else. Its domain and its URI's host must be the
// host of the frame that asked, which the browser gives this worker as the
// message's sender; the page has no say in it. The address's EIP-55 checksum
// is not required: the standard says SHOULD.
const SIWE_HEADER = " wants you to sign in with your Ethereum account:";
const SIWE_FIRST_LINE = /^(?:[a-z][a-z0-9+.-]*:\/\/)?([^\s/?#]+) wants you to sign in with your Ethereum account:$/i;
const SIWE_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i;
const SIWE_UNREADABLE = "The message looks like Sign-In with Ethereum but does not follow EIP-4361, " +
  "so the site it is for cannot be checked.";

// A URL, or null for a string that is not one.
function parseUrl(value) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

// The text a personal_sign message signs: hex is decoded as UTF-8, as wallets
// do, and anything else is signed as written. null when the bytes are not text.
function signedText(data) {
  if (typeof data !== "string") return null;
  if (!/^0x([0-9a-f]{2})*$/i.test(data)) return data;
  const bytes = new Uint8Array((data.length - 2) / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(data.slice(2 + i * 2, 4 + i * 2), 16);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

// The domain and URI of a message laid out as EIP-4361 says, or null.
function parseSiwe(text) {
  const lines = text.split("\n");
  const first = SIWE_FIRST_LINE.exec(lines[0]);
  if (!first || !/^0x[0-9a-f]{40}$/i.test(lines[1] || "") || lines[2] !== "") return null;
  // An optional statement of one line, between blank lines.
  let at = lines[3] === "" ? 4 : lines[4] === "" ? 5 : -1;
  if (at < 0) return null;
  const take = (prefix, valid) => {
    const line = lines[at] || "";
    if (!line.startsWith(prefix) || !valid(line.slice(prefix.length))) return null;
    at++;
    return line.slice(prefix.length);
  };
  const isUri = (value) => /^[a-z][a-z0-9+.-]*:\S+$/i.test(value) && parseUrl(value) !== null;
  const isDate = (value) => SIWE_DATE.test(value);
  const uri = take("URI: ", isUri);
  if (uri === null ||
      take("Version: ", (value) => value === "1") === null ||
      take("Chain ID: ", (value) => /^[0-9]+$/.test(value)) === null ||
      take("Nonce: ", (value) => /^[a-z0-9]{8,}$/i.test(value)) === null ||
      take("Issued At: ", isDate) === null) {
    return null;
  }
  for (const [prefix, valid] of [
    ["Expiration Time: ", isDate],
    ["Not Before: ", isDate],
    ["Request ID: ", (value) => /^[a-z0-9\-._~%!$&'()*+,;=:@]*$/i.test(value)],
  ]) {
    if ((lines[at] || "").startsWith(prefix) && take(prefix, valid) === null) return null;
  }
  if (lines[at] === "Resources:") {
    at++;
    while ((lines[at] || "").startsWith("- ") && isUri(lines[at].slice(2))) at++;
  }
  return at === lines.length ? { domain: first[1], uri } : null;
}

// What a personal_sign message says about the site it signs in to: null when
// it is not a sign-in message, state "unreadable" when it says it is one but
// is not laid out as EIP-4361, and otherwise whether its domain and its URI's
// host are the host of origin, the frame that asked.
function judgeSignIn(data, origin) {
  const text = signedText(data);
  if (text === null || !text.includes(SIWE_HEADER)) return null;
  const message = parseSiwe(text);
  const domain = message && parseUrl(`https://${message.domain}`);
  if (!domain) return { state: "unreadable" };
  const uri = parseUrl(message.uri);
  const page = parseUrl(origin);
  const host = page ? page.host : "";
  const claimed = domain.username || domain.password || domain.host !== host ? message.domain
    : uri.host && uri.host !== host ? uri.host : null;
  return claimed === null
    ? { state: "match", domain: message.domain }
    : { state: "mismatch", domain: claimed, origin: host || String(origin) };
}

async function handleAnalyze(tx, sender) {
  const validChainId = typeof tx.chainId === "number" ||
    (typeof tx.chainId === "string" && /^(0x[0-9a-f]+|[0-9]+)$/i.test(tx.chainId));
  const chainId = validChainId ? Number(tx.chainId) : null;
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    return unknownChain("Wallet chain unavailable, invalid, or mismatched; the request was not analyzed.");
  }

  // A sign-in message for another site than the one asking is Block
  // Recommended whatever the API would say, so the API is not asked.
  const signMethod = tx._signMethod || tx.signMethod;
  const signIn = signMethod === "personal_sign" ? judgeSignIn(tx.data, sender.origin) : null;
  if (signIn && signIn.state === "mismatch") {
    return {
      status: "ok",
      partial: false,
      classification: "BLOCK_RECOMMENDED",
      risk_level: "HIGH",
      risk_score: 100,
      coverage: { siwe: 1 },
      coverage_reasons: {},
      siwe: signIn,
      verdict: `Sign-in message for ${signIn.domain}, asked for by ${signIn.origin}`,
    };
  }

  const apiUrl = await getApiUrl();

  // Ensure we have permission for this origin
  const hasPermission = await ensureHostPermission(apiUrl);
  if (!hasPermission) {
    throw new Error("Permission required: Open extension popup and reconnect to grant access to your API server.");
  }

  const endpoint = `${apiUrl}/api/firewall`;

  const body = {
    to: tx.to || "",
    from: tx.from || "",
    value: tx.value || "0x0",
    // A message or hash to sign stays in the browser: the API judges
    // personal_sign and eth_sign by their method and does not read them.
    data: signMethod === "personal_sign" || signMethod === "eth_sign" ? "0x" : tx.data || "0x",
    chainId,
  };

  // Include typed data for signature analysis (EIP-712, Permit2, etc.).
  // MetaMask's legacy form, a list of fields, is not an EIP-712 object and is
  // left out; the API reads a signature without typed data as unknown.
  const typedData = tx._typedData || tx.typedData;
  if (typeof typedData === "object" && typedData !== null && !Array.isArray(typedData)) {
    body.typedData = typedData;
  }
  if (signMethod) {
    body.signMethod = signMethod;
  }

  // Get policy mode setting
  const settings = await new Promise((resolve) => {
    chrome.storage.local.get({ policyMode: "BALANCED" }, resolve);
  });

  // The only wait on the analysis path that can be long. It must stay below
  // content.js's DECISION_WINDOW_MS (50 s), after which a result is shown as
  // timed out, and inject.js's 60-second fail-closed limit.
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Policy-Mode": settings.policyMode,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30000),
  });

  if (!response.ok) {
    const text = await response.text();
    // The API refuses a chain it does not support with a 400 that says so.
    const unsupported = response.status === 400 && /"detail":\s*"(Unsupported chain ID[^"]*)"/.exec(text);
    if (unsupported) return unknownChain(unsupported[1]);
    throw new Error(`API error ${response.status}: ${text}`);
  }

  const result = await response.json();
  // The API cannot tell which site a sign-in message is for; a message that
  // says it is one but cannot be read leaves the verdict Unknown, never Safe
  // (the API's own rule for an incomplete signature).
  if (signIn && signIn.state === "unreadable") {
    return {
      ...result,
      classification: result.classification === "SAFE" ? "CAUTION" : result.classification,
      status: "unknown",
      partial: true,
      coverage: { ...result.coverage, siwe: 0 },
      coverage_reasons: { ...result.coverage_reasons, siwe: SIWE_UNREADABLE },
      siwe: signIn,
    };
  }
  return result;
}

async function checkHealth() {
  const apiUrl = await getApiUrl();

  // Ensure we have permission for this origin
  const hasPermission = await ensureHostPermission(apiUrl);
  if (!hasPermission) {
    throw new Error("Permission required: Reconnect via extension popup to grant access.");
  }

  const response = await fetch(`${apiUrl}/api/health`, {
    method: "GET",
    signal: AbortSignal.timeout(5000),
  });

  if (!response.ok) {
    throw new Error(`Health check failed: ${response.status}`);
  }

  return response.json();
}

async function ensureHostPermission(url) {
  try {
    const u = new URL(url);
    const origin = `${u.protocol}//${u.hostname}${u.port ? ':' + u.port : ''}/*`;

    // Check if we already have permission
    const hasPermission = await chrome.permissions.contains({
      origins: [origin]
    });

    if (hasPermission) {
      return true;
    }

    // Permission not granted - fail with clear instructions
    // User must grant permission via extension popup or chrome://extensions
    return false;
  } catch (err) {
    console.error("Permission check error:", err);
    return false;
  }
}

function saveToHistory(tx, result) {
  const incomplete = result.status !== "ok" || result.partial === true ||
    result.risk_level === "UNKNOWN" || result.classification === "UNKNOWN" ||
    !Number.isFinite(result.risk_score) ||
    Object.values(result.coverage || {}).some(value => Number(value) < 1);
  chrome.storage.local.get({ scanHistory: [] }, (data) => {
    const history = data.scanHistory;
    history.unshift({
      timestamp: Date.now(),
      to: tx.to || "",
      classification: incomplete && !["HIGH_RISK", "BLOCK_RECOMMENDED"].includes(result.classification)
        ? "UNKNOWN" : result.classification || "UNKNOWN",
      risk_score: result.risk_score ?? null,
      status: incomplete ? "unknown" : "ok",
      coverage: result.coverage || {},
      coverage_reasons: result.coverage_reasons || {},
      risk_display: incomplete ? "Unknown (incomplete provider coverage)" : result.risk_display,
      partial: incomplete,
      verdict: incomplete ? "Unknown (incomplete provider coverage)" : result.verdict || "",
      recipient: result.transaction_impact?.recipient || tx.to || "",
    });

    // Keep only the last N entries
    if (history.length > MAX_HISTORY) {
      history.length = MAX_HISTORY;
    }

    chrome.storage.local.set({ scanHistory: history });
  });
}

