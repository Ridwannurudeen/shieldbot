/**
 * ShieldAI Popup Script
 * Manages settings, displays connection status, and shows scan history.
 */

const DEFAULT_API_URL = "http://38.49.212.108:8000";

document.addEventListener("DOMContentLoaded", () => {
  const apiUrlInput = document.getElementById("apiUrl");
  const enabledToggle = document.getElementById("enabled");
  const saveBtn = document.getElementById("saveBtn");
  const savedMsg = document.getElementById("savedMsg");
  const statusDot = document.getElementById("statusDot");
  const statusText = document.getElementById("statusText");
  const historyList = document.getElementById("historyList");

  // --- Tabs ---
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById("tab-" + tab.dataset.tab).classList.add("active");

      if (tab.dataset.tab === "history") {
        loadHistory();
      }
    });
  });

  // --- Settings ---
  chrome.storage.local.get(
    { apiUrl: DEFAULT_API_URL, enabled: true },
    (data) => {
      apiUrlInput.value = data.apiUrl;
      enabledToggle.checked = data.enabled;
      checkConnection(data.apiUrl);
    }
  );

  saveBtn.addEventListener("click", () => {
    const apiUrl = apiUrlInput.value.trim().replace(/\/+$/, "");
    const enabled = enabledToggle.checked;

    chrome.storage.local.set({ apiUrl, enabled }, () => {
      savedMsg.classList.add("show");
      setTimeout(() => savedMsg.classList.remove("show"), 2000);
      checkConnection(apiUrl);
    });
  });

  // --- Connection Check ---
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

  // --- History ---
  function loadHistory() {
    chrome.runtime.sendMessage({ type: "SHIELDAI_GET_HISTORY" }, (response) => {
      if (chrome.runtime.lastError || !response) {
        // Fallback: read directly from storage
        chrome.storage.local.get({ scanHistory: [] }, (data) => {
          renderHistory(data.scanHistory);
        });
        return;
      }
      renderHistory(response.history || []);
    });
  }

  function renderHistory(history) {
    if (!history || history.length === 0) {
      historyList.innerHTML = '<div class="history-empty">No scans yet. Transactions will appear here after analysis.</div>';
      return;
    }

    const badgeMap = {
      SAFE: { cls: "badge-safe", label: "SAFE" },
      CAUTION: { cls: "badge-caution", label: "CAUTION" },
      HIGH_RISK: { cls: "badge-high", label: "HIGH" },
      BLOCK_RECOMMENDED: { cls: "badge-block", label: "BLOCK" },
    };

    historyList.innerHTML = history
      .map((item) => {
        const badge = badgeMap[item.classification] || { cls: "badge-caution", label: item.classification };
        const safety = 100 - (item.risk_score || 0);
        const time = formatTime(item.timestamp);
        const recipient = escapeHtml(item.recipient || item.to || "Unknown");

        return `
          <div class="history-item">
            <span class="history-badge ${badge.cls}">${badge.label}</span>
            <div class="history-info">
              <div class="history-recipient">${recipient}</div>
              <div class="history-time">${time}</div>
            </div>
            <div class="history-score">${safety}/100</div>
          </div>
        `;
      })
      .join("");
  }

  function formatTime(ts) {
    if (!ts) return "";
    const d = new Date(ts);
    const now = new Date();
    const diffMs = now - d;
    const diffMin = Math.floor(diffMs / 60000);

    if (diffMin < 1) return "Just now";
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    return d.toLocaleDateString();
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
});
