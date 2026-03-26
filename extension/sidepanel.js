const DEFAULT_API_URL = "https://api.shieldbotsecurity.online";

const SUGGESTED_PROMPTS = [
  "Recent threats",
  "Scan this page",
  "How does ShieldBot work?",
  "Check 0x...",
];

document.addEventListener("DOMContentLoaded", async () => {
  const messagesEl = document.getElementById("messages");
  const inputEl = document.getElementById("chatInput");
  const sendBtn = document.getElementById("sendBtn");
  const chainSelect = document.getElementById("chainSelect");
  let sending = false;

  // Get or create a persistent user ID
  let { chatUserId } = await chrome.storage.local.get("chatUserId");
  if (!chatUserId) {
    chatUserId = crypto.randomUUID();
    await chrome.storage.local.set({ chatUserId });
  }

  // Restore persisted chain selection
  const { selectedChainId } = await chrome.storage.local.get("selectedChainId");
  if (selectedChainId) chainSelect.value = String(selectedChainId);
  chainSelect.addEventListener("change", () => {
    chrome.storage.local.set({ selectedChainId: parseInt(chainSelect.value) || 56 });
  });

  // Load cached messages on open with validation
  const { chatMessages = [] } = await chrome.storage.local.get("chatMessages");
  chatMessages.forEach(m => {
    if (!m || typeof m.text !== "string" || (m.role !== "user" && m.role !== "assistant")) return;
    if (m.scanData && typeof m.scanData === "object") renderRiskCard(m.scanData);
    appendMessage(m.role, m.text, { save: false });
  });

  // Show suggested prompts if chat is empty
  if (chatMessages.length === 0) showSuggestedPrompts();

  // -------------------------------------------------------------------
  // HTML escaping (includes quotes to prevent attribute injection)
  // -------------------------------------------------------------------
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // -------------------------------------------------------------------
  // Markdown renderer
  // -------------------------------------------------------------------
  function renderMarkdown(text) {
    // Escape ALL HTML including quotes
    let html = escapeHtml(text);

    // Code blocks: ```...```
    html = html.replace(/```(?:\w*)\n?([\s\S]*?)```/g, (_, code) =>
      `<code class="md-codeblock">${code.trim()}</code>`
    );
    // Inline code: `...`
    html = html.replace(/`([^`]+)`/g, '<code class="md-code">$1</code>');
    // Bold: **...**
    html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    // Italic: *...*
    html = html.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, "<em>$1</em>");
    // Links: [text](https://...) — exclude quotes/spaces from URL capture
    html = html.replace(/\[([^\]]+)\]\((https:\/\/[^)"'\s]+)\)/g,
      '<a class="md-link" href="$2" target="_blank" rel="noopener">$1</a>'
    );

    // Bullet lists
    html = html.replace(/((?:^|\n)[•\-\*] .+(?:\n[•\-\*] .+)*)/g, (block) => {
      const items = block.trim().split("\n").map(l =>
        `<li>${l.replace(/^[•\-\*]\s*/, "")}</li>`
      ).join("");
      return `<ul class="md-list">${items}</ul>`;
    });
    // Numbered lists
    html = html.replace(/((?:^|\n)\d+[\.\)] .+(?:\n\d+[\.\)] .+)*)/g, (block) => {
      const items = block.trim().split("\n").map(l =>
        `<li>${l.replace(/^\d+[\.\)]\s*/, "")}</li>`
      ).join("");
      return `<ol class="md-list">${items}</ol>`;
    });

    // Paragraphs: double newlines
    html = html.replace(/\n{2,}/g, "</p><p>");
    html = `<p>${html}</p>`;
    // Single newlines inside paragraphs
    html = html.replace(/(?<!<\/li>|<\/ul>|<\/ol>|<\/code>)\n(?!<)/g, "<br>");

    return html;
  }

  // -------------------------------------------------------------------
  // Typing bubble
  // -------------------------------------------------------------------
  function showTypingBubble() {
    const bubble = document.createElement("div");
    bubble.className = "chat-bubble typing";
    bubble.id = "typingBubble";
    bubble.innerHTML = `
      <div class="typing-dots">
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
      </div>
      <span class="typing-label">ShieldBot is thinking...</span>
    `;
    messagesEl.appendChild(bubble);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function removeTypingBubble() {
    const b = document.getElementById("typingBubble");
    if (b) b.remove();
  }

  // -------------------------------------------------------------------
  // Risk card (all values coerced/escaped before innerHTML)
  // -------------------------------------------------------------------
  function renderRiskCard(scanData) {
    if (!scanData || typeof scanData !== "object") return;
    const score = Number(scanData.risk_score) || 0;
    let level = "low";
    if (score >= 70) level = "high";
    else if (score >= 40) level = "medium";

    const card = document.createElement("div");
    card.className = "risk-card";

    const flags = (Array.isArray(scanData.flags) ? scanData.flags : []).map(f =>
      `<span class="risk-flag">${escapeHtml(f)}</span>`
    ).join("");

    const archetype = scanData.archetype
      ? `<div class="risk-card-subtitle">${escapeHtml(scanData.archetype)}</div>` : "";

    let metaParts = [];
    const hp = (typeof scanData.honeypot === "object" && scanData.honeypot) || {};
    if (hp.is_honeypot !== undefined) {
      metaParts.push(`Honeypot: <span>${hp.is_honeypot ? "Yes" : "No"}</span>`);
    }
    if (hp.sell_tax !== undefined) {
      metaParts.push(`Sell tax: <span>${Number(hp.sell_tax)}%</span>`);
    }
    const mkt = (typeof scanData.market === "object" && scanData.market) || {};
    if (mkt.liquidity_usd !== undefined) {
      metaParts.push(`Liq: <span>$${Number(mkt.liquidity_usd).toLocaleString()}</span>`);
    }
    if (mkt.volume_24h !== undefined) {
      metaParts.push(`Vol 24h: <span>$${Number(mkt.volume_24h).toLocaleString()}</span>`);
    }

    // Validate address format before rendering
    const addr = /^0x[a-fA-F0-9]{40}$/.test(scanData.address || "") ? scanData.address : "";
    const shortAddr = addr ? `${addr.slice(0, 6)}...${addr.slice(-4)}` : "";

    card.innerHTML = `
      <div class="risk-card-header">
        <div class="risk-score-badge ${level}">${score}</div>
        <div>
          <div class="risk-card-title">${escapeHtml(scanData.risk_level || level.toUpperCase())} Risk ${shortAddr ? `— ${shortAddr}` : ""}</div>
          ${archetype}
        </div>
      </div>
      ${flags ? `<div style="margin-bottom:4px">${flags}</div>` : ""}
      ${metaParts.length ? `<div class="risk-card-meta">${metaParts.join(" | ")}</div>` : ""}
    `;
    messagesEl.appendChild(card);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  // -------------------------------------------------------------------
  // Suggested prompts
  // -------------------------------------------------------------------
  function showSuggestedPrompts() {
    const container = document.createElement("div");
    container.className = "suggested-prompts";
    container.id = "suggestedPrompts";
    SUGGESTED_PROMPTS.forEach(text => {
      const chip = document.createElement("button");
      chip.className = "prompt-chip";
      chip.textContent = text;
      chip.addEventListener("click", () => {
        if (text === "Scan this page") {
          scanCurrentPage();
        } else if (text === "Check 0x...") {
          inputEl.value = "Check ";
          inputEl.focus();
        } else {
          inputEl.value = text;
          sendMessage();
        }
      });
      container.appendChild(chip);
    });
    messagesEl.appendChild(container);
  }

  function removeSuggestedPrompts() {
    const el = document.getElementById("suggestedPrompts");
    if (el) el.remove();
  }

  // -------------------------------------------------------------------
  // Scan current page
  // -------------------------------------------------------------------
  function extractAddressFromUrl(url) {
    if (!url) return null;
    // BscScan / Etherscan: /address/0x... or /token/0x...
    const scanMatch = url.match(/(?:\/address\/|\/token\/)(0x[a-fA-F0-9]{40})/);
    if (scanMatch) return scanMatch[1];
    // DexScreener: /.../{chain}/0x...
    const dexMatch = url.match(/dexscreener\.com\/[^/]+\/(0x[a-fA-F0-9]{40})/);
    if (dexMatch) return dexMatch[1];
    return null;
  }

  async function scanCurrentPage() {
    try {
      const resp = await chrome.runtime.sendMessage({ type: "SHIELDAI_GET_ACTIVE_TAB" });
      if (resp && resp.url) {
        const addr = extractAddressFromUrl(resp.url);
        if (addr) {
          inputEl.value = `Scan ${addr}`;
          sendMessage();
        } else {
          appendMessage("assistant", "No token or contract address found on the current page.");
          saveMessages();
        }
      } else {
        appendMessage("assistant", "Could not read the current tab URL.");
        saveMessages();
      }
    } catch {
      appendMessage("assistant", "Could not access the current tab.");
      saveMessages();
    }
  }

  // -------------------------------------------------------------------
  // Send message (with lock to prevent double-send)
  // -------------------------------------------------------------------
  async function sendMessage() {
    if (sending) return;
    const text = inputEl.value.trim();
    if (!text) return;
    sending = true;
    inputEl.value = "";
    removeSuggestedPrompts();
    appendMessage("user", text);
    saveMessages();

    showTypingBubble();
    sendBtn.disabled = true;

    try {
      const stored = await chrome.storage.local.get({ apiUrl: DEFAULT_API_URL });
      const apiUrl = stored.apiUrl || DEFAULT_API_URL;
      try { const u = new URL(apiUrl); if (u.protocol !== "https:" && !["localhost","127.0.0.1"].includes(u.hostname)) throw 0; } catch { throw new Error("Invalid API URL. Check extension settings."); }
      const chainId = parseInt(chainSelect.value) || 56;
      const resp = await fetch(`${apiUrl}/api/agent/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text, user_id: chatUserId, chain_id: chainId }),
        signal: AbortSignal.timeout(30000),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${resp.status}`);
      }

      const data = await resp.json();

      // Render risk card if scan_data is present
      if (data.scan_data) {
        renderRiskCard(data.scan_data);
      }

      appendMessage("assistant", data.response, { scanData: data.scan_data });
    } catch (err) {
      appendMessage("assistant", `Error: ${err.message}`, { isError: true, originalMessage: text });
    } finally {
      removeTypingBubble();
      sendBtn.disabled = false;
      sending = false;
    }
    saveMessages();
  }

  // -------------------------------------------------------------------
  // Append message bubble
  // -------------------------------------------------------------------
  function appendMessage(role, text, opts = {}) {
    const { isError = false, originalMessage = null, scanData = null } = opts;

    if (role === "assistant") {
      const wrapper = document.createElement("div");
      wrapper.className = "bubble-wrapper";
      if (scanData) wrapper.dataset.scanData = JSON.stringify(scanData);

      const bubble = document.createElement("div");
      bubble.className = `chat-bubble assistant${isError ? " error" : ""}`;
      bubble.dataset.raw = text;
      bubble.innerHTML = renderMarkdown(text);
      wrapper.appendChild(bubble);

      // Copy button with error handling
      const copyBtn = document.createElement("button");
      copyBtn.className = "copy-btn";
      copyBtn.textContent = "Copy";
      copyBtn.addEventListener("click", () => {
        navigator.clipboard.writeText(text).then(() => {
          copyBtn.textContent = "Copied";
          setTimeout(() => { copyBtn.textContent = "Copy"; }, 1500);
        }).catch(() => {
          copyBtn.textContent = "Failed";
          setTimeout(() => { copyBtn.textContent = "Copy"; }, 1500);
        });
      });
      wrapper.appendChild(copyBtn);

      // Retry button on errors
      if (isError && originalMessage) {
        const retryBtn = document.createElement("button");
        retryBtn.className = "retry-btn";
        retryBtn.textContent = "Retry";
        retryBtn.addEventListener("click", () => {
          wrapper.remove();
          inputEl.value = originalMessage;
          sendMessage();
        });
        bubble.appendChild(retryBtn);
      }

      messagesEl.appendChild(wrapper);
    } else {
      const bubble = document.createElement("div");
      bubble.className = "chat-bubble user";
      bubble.textContent = text;
      messagesEl.appendChild(bubble);
    }

    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  // -------------------------------------------------------------------
  // Save / export
  // -------------------------------------------------------------------
  function saveMessages() {
    const items = messagesEl.querySelectorAll(".chat-bubble.user, .bubble-wrapper");
    const msgs = Array.from(items).slice(-20).map(el => {
      if (el.classList.contains("bubble-wrapper")) {
        const bubble = el.querySelector(".chat-bubble");
        let scanData;
        if (el.dataset.scanData) {
          try { scanData = JSON.parse(el.dataset.scanData); } catch { /* ignore corrupt */ }
        }
        return {
          role: "assistant",
          text: bubble ? bubble.dataset.raw || bubble.textContent : "",
          scanData,
        };
      }
      return { role: "user", text: el.textContent };
    });
    chrome.storage.local.set({ chatMessages: msgs });
  }

  function exportChat() {
    const items = messagesEl.querySelectorAll(".chat-bubble.user, .bubble-wrapper");
    let lines = ["ShieldBot Chat Export", `Date: ${new Date().toISOString()}`, "---", ""];
    items.forEach(el => {
      if (el.classList.contains("bubble-wrapper")) {
        const bubble = el.querySelector(".chat-bubble");
        const raw = bubble ? (bubble.dataset.raw || bubble.textContent) : "";
        lines.push(`[ShieldBot]: ${raw}`, "");
      } else {
        lines.push(`[You]: ${el.textContent}`, "");
      }
    });
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `shieldbot-chat-${Date.now()}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // -------------------------------------------------------------------
  // Tab switching
  // -------------------------------------------------------------------
  const tabBtns = document.querySelectorAll(".tab-btn");
  const panels = document.querySelectorAll(".panel");

  function switchTab(tabName) {
    tabBtns.forEach(b => b.classList.toggle("active", b.dataset.tab === tabName));
    panels.forEach(p => p.classList.toggle("active", p.id === tabName + "Panel"));
    localStorage.setItem("shieldbot_active_tab", tabName);
    if (tabName === "guardian") loadGuardianAlerts();
  }

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // Restore last active tab
  const savedTab = localStorage.getItem("shieldbot_active_tab");
  if (savedTab && ["chat", "guardian", "scanner"].includes(savedTab)) {
    switchTab(savedTab);
  }

  // -------------------------------------------------------------------
  // Guardian: load alerts
  // -------------------------------------------------------------------
  const guardianAlertsEl = document.getElementById("guardianAlerts");

  async function loadGuardianAlerts() {
    guardianAlertsEl.innerHTML = '<div class="placeholder-msg">Loading alerts...</div>';
    try {
      const stored = await chrome.storage.local.get({ apiUrl: DEFAULT_API_URL, healthWallet: "" });
      const apiUrl = stored.apiUrl || DEFAULT_API_URL;
      const wallet = stored.healthWallet;
      if (!apiUrl) {
        guardianAlertsEl.innerHTML = '<div class="placeholder-msg">Set your API URL in extension settings to see alerts.</div>';
        return;
      }
      if (!wallet) {
        guardianAlertsEl.innerHTML = '<div class="placeholder-msg">Enter your wallet address in the popup Health tab first, then come back here.</div>';
        return;
      }
      const resp = await fetch(`${apiUrl}/api/guardian/alerts?wallet_address=${encodeURIComponent(wallet)}`, {
        method: "GET",
        signal: AbortSignal.timeout(15000),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const alerts = await resp.json();
      renderGuardianAlerts(Array.isArray(alerts) ? alerts : []);
    } catch (err) {
      guardianAlertsEl.innerHTML = `<div class="placeholder-msg">Could not load alerts: ${escapeHtml(err.message)}</div>`;
    }
  }

  function renderGuardianAlerts(alerts) {
    guardianAlertsEl.innerHTML = "";
    if (alerts.length === 0) {
      guardianAlertsEl.innerHTML = '<div class="placeholder-msg">No alerts. Your wallets are looking good.</div>';
      return;
    }
    alerts.forEach(alert => {
      const severity = String(alert.severity || "info").toLowerCase();
      const wallet = alert.wallet_address || "";
      const shortWallet = wallet.length >= 10 ? `${wallet.slice(0, 6)}...${wallet.slice(-4)}` : wallet;
      const card = document.createElement("div");
      card.className = "alert-card";
      card.innerHTML = `
        <div class="alert-card-header">
          <span class="severity-badge ${escapeHtml(severity)}">${escapeHtml(severity)}</span>
          <span class="alert-card-title">${escapeHtml(alert.title || "Alert")}</span>
        </div>
        ${shortWallet ? `<div class="alert-card-wallet">${escapeHtml(shortWallet)}</div>` : ""}
        <button class="ack-btn" data-alert-id="${Number(alert.id) || 0}">Acknowledge</button>
      `;
      card.querySelector(".ack-btn").addEventListener("click", async (e) => {
        const alertId = e.target.dataset.alertId;
        try {
          const stored = await chrome.storage.local.get({ apiUrl: DEFAULT_API_URL });
          const apiUrl = stored.apiUrl || DEFAULT_API_URL;
          await fetch(`${apiUrl}/api/guardian/alerts/${alertId}/acknowledge`, {
            method: "POST",
            signal: AbortSignal.timeout(10000),
          });
          card.remove();
          if (!guardianAlertsEl.querySelector(".alert-card")) {
            guardianAlertsEl.innerHTML = '<div class="placeholder-msg">No alerts. Your wallets are looking good.</div>';
          }
        } catch { /* silent fail */ }
      });
      guardianAlertsEl.appendChild(card);
    });
  }

  document.getElementById("refreshAlertsBtn").addEventListener("click", loadGuardianAlerts);

  // -------------------------------------------------------------------
  // Scanner: injection detection
  // -------------------------------------------------------------------
  const injectionInput = document.getElementById("injectionInput");
  const scanInjectionBtn = document.getElementById("scanInjectionBtn");
  const scannerResults = document.getElementById("scannerResults");

  scanInjectionBtn.addEventListener("click", scanInjection);
  injectionInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.ctrlKey) {
      e.preventDefault();
      scanInjection();
    }
  });

  async function scanInjection() {
    const text = injectionInput.value.trim();
    if (!text) return;
    scanInjectionBtn.disabled = true;
    scanInjectionBtn.textContent = "Scanning...";
    try {
      const stored = await chrome.storage.local.get({ apiUrl: DEFAULT_API_URL });
      const apiUrl = stored.apiUrl || DEFAULT_API_URL;
      const resp = await fetch(`${apiUrl}/api/scan/injection`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, depth: "thorough" }),
        signal: AbortSignal.timeout(30000),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      renderInjectionResult(data);
    } catch (err) {
      scannerResults.innerHTML = `<div class="placeholder-msg">Scan failed: ${escapeHtml(err.message)}</div>`;
    } finally {
      scanInjectionBtn.disabled = false;
      scanInjectionBtn.textContent = "Scan for Injection";
    }
  }

  function renderInjectionResult(data) {
    const score = Number(data.risk_score) || 0;
    let level = "safe";
    let label = "Safe";
    if (score >= 70) { level = "danger"; label = "Injection Detected"; }
    else if (score >= 30) { level = "warning"; label = "Suspicious"; }

    const patterns = Array.isArray(data.matched_patterns) ? data.matched_patterns : [];
    const patternTags = patterns.map(p =>
      `<li class="pattern-tag">${escapeHtml(p)}</li>`
    ).join("");

    const card = document.createElement("div");
    card.className = "scan-result-card";
    card.innerHTML = `
      <div class="scan-result-header">
        <div class="scan-score-badge ${level}">${score}</div>
        <div>
          <div class="scan-result-label">${escapeHtml(label)}</div>
          <div class="scan-result-sublabel">Confidence: ${Number(data.confidence || 0).toFixed(1)}%</div>
        </div>
      </div>
      ${patternTags ? `<ul class="pattern-list">${patternTags}</ul>` : '<ul class="pattern-list"><li class="pattern-tag safe">No patterns matched</li></ul>'}
    `;
    scannerResults.prepend(card);
  }

  // -------------------------------------------------------------------
  // Event listeners
  // -------------------------------------------------------------------
  document.getElementById("clearBtn").addEventListener("click", () => {
    messagesEl.innerHTML = "";
    chrome.storage.local.remove("chatMessages");
    showSuggestedPrompts();
  });

  document.getElementById("exportBtn").addEventListener("click", exportChat);

  sendBtn.addEventListener("click", sendMessage);
  inputEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      sendMessage();
    }
  });
});
