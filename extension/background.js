/**
 * ShieldAI Background Service Worker
 * Receives intercepted tx data from content script, calls the VPS API,
 * and returns the firewall verdict. Saves scan history.
 */

const DEFAULT_API_URL = "https://api.shieldbotsecurity.online";
const MAX_HISTORY = 50;

// On fresh install: pre-fill API URL and open welcome tab
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    chrome.storage.local.set({ apiUrl: "https://api.shieldbotsecurity.online" });
    chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
  }
});

// In-memory phishing cache: domain -> {result, expiresAt}
// Avoids repeated API calls when navigating across pages on the same site.
const _phishingCache = new Map();
const PHISHING_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SHIELDAI_ANALYZE") {
    handleAnalyze(message.tx)
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
      .catch(() => sendResponse({ result: { is_phishing: false } }));
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

});


async function checkPhishing(url) {
  try {
    const { hostname } = new URL(url);
    const cacheKey = hostname.toLowerCase();

    // Check extension-side cache
    const cached = _phishingCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.result;
    }

    // Get configured API URL — if not set, skip silently
    let apiUrl;
    try {
      apiUrl = await getApiUrl();
    } catch {
      return { is_phishing: false };
    }

    const response = await fetch(
      `${apiUrl}/api/phishing?url=${encodeURIComponent(url)}`,
      {
        method: "GET",
        signal: AbortSignal.timeout(5000),
      }
    );

    if (!response.ok) {
      return { is_phishing: false };
    }

    const result = await response.json();
    _phishingCache.set(cacheKey, { result, expiresAt: Date.now() + PHISHING_CACHE_TTL_MS });
    return result;
  } catch {
    return { is_phishing: false };
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

async function handleAnalyze(tx) {
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
    data: tx.data || "0x",
    chainId: typeof tx.chainId === "string" ? parseInt(tx.chainId, 16) || 56 : (tx.chainId || 56),
  };

  // Include typed data for signature analysis (EIP-712, Permit2, etc.)
  if (tx._typedData || tx.typedData) {
    body.typedData = tx._typedData || tx.typedData;
  }
  if (tx._signMethod || tx.signMethod) {
    body.signMethod = tx._signMethod || tx.signMethod;
  }

  // Get policy mode setting
  const settings = await new Promise((resolve) => {
    chrome.storage.local.get({ policyMode: "BALANCED" }, resolve);
  });

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
    throw new Error(`API error ${response.status}: ${text}`);
  }

  return response.json();
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
  chrome.storage.local.get({ scanHistory: [] }, (data) => {
    const history = data.scanHistory;
    history.unshift({
      timestamp: Date.now(),
      to: tx.to || "",
      classification: result.classification || "UNKNOWN",
      risk_score: result.risk_score || 0,
      verdict: result.verdict || "",
      recipient: result.transaction_impact?.recipient || tx.to || "",
    });

    // Keep only the last N entries
    if (history.length > MAX_HISTORY) {
      history.length = MAX_HISTORY;
    }

    chrome.storage.local.set({ scanHistory: history });
  });
}

