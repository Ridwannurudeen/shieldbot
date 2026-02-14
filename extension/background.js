/**
 * ShieldAI Background Service Worker
 * Receives intercepted tx data from content script, calls the VPS API,
 * and returns the firewall verdict. Saves scan history.
 */

const DEFAULT_API_URL = "https://38.49.212.108:8000";
const MAX_HISTORY = 50;

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

function isSecureUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) return true;
    return false;
  } catch {
    return false;
  }
}

async function getApiUrl() {
  return new Promise((resolve) => {
    chrome.storage.local.get({ apiUrl: DEFAULT_API_URL }, (data) => {
      const url = data.apiUrl || DEFAULT_API_URL;
      // Block insecure non-local URLs
      resolve(isSecureUrl(url) ? url : DEFAULT_API_URL);
    });
  });
}

async function handleAnalyze(tx) {
  const apiUrl = await getApiUrl();
  const endpoint = `${apiUrl}/api/firewall`;

  const body = {
    to: tx.to || "",
    from: tx.from || "",
    value: tx.value || "0x0",
    data: tx.data || "0x",
    chainId: tx.chainId || 56,
  };

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`API error ${response.status}: ${text}`);
  }

  return response.json();
}

async function checkHealth() {
  const apiUrl = await getApiUrl();
  const response = await fetch(`${apiUrl}/api/health`, {
    method: "GET",
    signal: AbortSignal.timeout(5000),
  });

  if (!response.ok) {
    throw new Error(`Health check failed: ${response.status}`);
  }

  return response.json();
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
