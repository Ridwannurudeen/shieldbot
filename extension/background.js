/**
 * ShieldAI Background Service Worker
 * Receives intercepted tx data from content script, calls the VPS API,
 * and returns the firewall verdict.
 */

const DEFAULT_API_URL = "http://38.49.212.108:8000";

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SHIELDAI_ANALYZE") {
    handleAnalyze(message.tx)
      .then((result) => sendResponse({ result }))
      .catch((err) => sendResponse({ error: err.message || "Unknown error" }));
    return true; // Keep the message channel open for async response
  }

  if (message.type === "SHIELDAI_HEALTH") {
    checkHealth()
      .then((status) => sendResponse({ status }))
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }
});

async function getApiUrl() {
  return new Promise((resolve) => {
    chrome.storage.local.get({ apiUrl: DEFAULT_API_URL }, (data) => {
      resolve(data.apiUrl || DEFAULT_API_URL);
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
