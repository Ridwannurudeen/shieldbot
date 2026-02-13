/**
 * ShieldAI Popup Script
 * Manages settings and displays connection status.
 */

const DEFAULT_API_URL = "http://38.49.212.108:8000";

document.addEventListener("DOMContentLoaded", () => {
  const apiUrlInput = document.getElementById("apiUrl");
  const enabledToggle = document.getElementById("enabled");
  const saveBtn = document.getElementById("saveBtn");
  const savedMsg = document.getElementById("savedMsg");
  const statusDot = document.getElementById("statusDot");
  const statusText = document.getElementById("statusText");

  // Load saved settings
  chrome.storage.local.get(
    { apiUrl: DEFAULT_API_URL, enabled: true },
    (data) => {
      apiUrlInput.value = data.apiUrl;
      enabledToggle.checked = data.enabled;
      checkConnection(data.apiUrl);
    }
  );

  // Save settings
  saveBtn.addEventListener("click", () => {
    const apiUrl = apiUrlInput.value.trim().replace(/\/+$/, "");
    const enabled = enabledToggle.checked;

    chrome.storage.local.set({ apiUrl, enabled }, () => {
      savedMsg.classList.add("show");
      setTimeout(() => savedMsg.classList.remove("show"), 2000);
      checkConnection(apiUrl);
    });
  });

  // Check API connection — call API directly from popup (no background worker needed)
  async function checkConnection(apiUrl) {
    statusDot.className = "status-dot yellow";
    statusText.textContent = "Checking connection...";

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(`${apiUrl}/api/health`, {
        method: "GET",
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!response.ok) {
        statusDot.className = "status-dot red";
        statusText.textContent = "Disconnected (HTTP " + response.status + ")";
        return;
      }

      const data = await response.json();
      statusDot.className = "status-dot green";
      const aiStatus = data.ai_available ? " (AI active)" : " (AI offline)";
      statusText.textContent = "Connected" + aiStatus;
    } catch (err) {
      statusDot.className = "status-dot red";
      statusText.textContent = "Disconnected";
    }
  }
});
