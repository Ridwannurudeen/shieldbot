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

  // Check API connection
  async function checkConnection(apiUrl) {
    statusDot.className = "status-dot yellow";
    statusText.textContent = "Checking connection...";

    try {
      const response = await chrome.runtime.sendMessage({
        type: "SHIELDAI_HEALTH",
      });

      if (response.error) {
        statusDot.className = "status-dot red";
        statusText.textContent = "Disconnected";
      } else {
        statusDot.className = "status-dot green";
        const aiStatus = response.status?.ai_available ? " (AI active)" : " (AI offline)";
        statusText.textContent = "Connected" + aiStatus;
      }
    } catch (err) {
      statusDot.className = "status-dot red";
      statusText.textContent = "Disconnected";
    }
  }
});
