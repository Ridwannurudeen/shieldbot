/**
 * ShieldAI Popup Script
 * Manages settings, connection status, scan history, and wallet health.
 */

const DEFAULT_API_URL = "https://api.shieldbotsecurity.online";

const _urlParams = new URLSearchParams(location.search);
const _isFullPage = _urlParams.get("tab") === "1";

// ============================================================
// SHARED HELPERS
// ============================================================

function isAllowedUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:") return ["localhost", "127.0.0.1"].includes(u.hostname);
    return false;
  } catch { return false; }
}

function formatTime(ts) {
  if (!ts) return "";
  const diffMin = Math.floor((Date.now() - ts) / 60000);
  if (diffMin < 1)  return "Just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24)  return `${diffHr}h ago`;
  return new Date(ts).toLocaleDateString();
}

function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str;
  return d.innerHTML;
}

function shortAddr(addr) {
  if (!addr || addr.length < 10) return addr || "";
  return addr.slice(0, 6) + "…" + addr.slice(-4);
}

function fmtUsd(val) {
  if (!val && val !== 0) return null;
  if (val >= 1e6) return "$" + (val / 1e6).toFixed(1) + "M";
  if (val >= 1e3) return "$" + (val / 1e3).toFixed(1) + "k";
  return "$" + val.toFixed(2);
}

function showMsg(el, text, isError) {
  el.textContent = text;
  el.style.color = isError ? "#ef4444" : "";
  el.classList.add("show");
  setTimeout(() => { el.classList.remove("show"); el.textContent = isError ? "" : t("msgSaved"); el.style.color = ""; }, isError ? 3000 : 2000);
}

// ============================================================
// ENTRY POINT
// ============================================================

document.addEventListener("DOMContentLoaded", async () => {
  if (typeof initI18n === "function") {
    await initI18n();
    applyTranslations();
  }
  if (_isFullPage) {
    document.body.classList.add("expanded");
    const btn = document.getElementById("expandBtn");
    if (btn) btn.style.display = "none";
    initDashboard();
  } else {
    initCompact();
  }
});

// ============================================================
// COMPACT POPUP
// ============================================================

function initCompact() {
  const apiUrlInput   = document.getElementById("apiUrl");
  const enabledToggle = document.getElementById("enabled");
  const saveBtn       = document.getElementById("saveBtn");
  const savedMsg      = document.getElementById("savedMsg");
  const statusDot     = document.getElementById("statusDot");
  const statusText    = document.getElementById("statusText");
  const historyList   = document.getElementById("historyList");

  document.getElementById("expandBtn")?.addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("popup.html") + "?tab=1" });
    window.close();
  });

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
      if (tab.dataset.tab === "history") loadAndRenderHistory(historyList);
      if (tab.dataset.tab === "feed") initFeedTab();
    });
  });

  chrome.storage.local.get({ apiUrl: DEFAULT_API_URL, enabled: true, policyMode: "BALANCED" }, (data) => {
    apiUrlInput.value = data.apiUrl;
    enabledToggle.checked = data.enabled;
    const radio = document.querySelector(`input[name="policyMode"][value="${data.policyMode}"]`);
    if (radio) radio.checked = true;
    checkConnection(data.apiUrl, statusDot, statusText);
  });

  saveBtn.addEventListener("click", () => {
    const apiUrl = apiUrlInput.value.trim().replace(/\/+$/, "");
    const enabled = enabledToggle.checked;
    if (!apiUrl)             { showMsg(savedMsg, t("msgErrEmptyUrl"), true); return; }
    if (!isAllowedUrl(apiUrl)) { showMsg(savedMsg, t("msgErrHttps"), true); return; }
    try { new URL(apiUrl); } catch { showMsg(savedMsg, t("msgErrInvalidUrl"), true); return; }
    const policyMode = document.querySelector('input[name="policyMode"]:checked')?.value || "BALANCED";
    chrome.storage.local.set({ apiUrl, enabled, policyMode }, () => {
      showMsg(savedMsg, t("msgSaved"), false);
      checkConnection(apiUrl, statusDot, statusText);
    });
  });

  // Language selector
  const langSel = document.getElementById("langSelect");
  if (langSel) {
    langSel.value = getCurrentLang ? getCurrentLang() : "en";
    langSel.addEventListener("change", async () => {
      if (typeof setLanguage === "function") {
        await setLanguage(langSel.value);
        applyTranslations();
      }
    });
  }

  // Health tab
  const healthScanBtn = document.getElementById("healthScanBtn");
  const healthAddress = document.getElementById("healthAddress");

  chrome.storage.local.get({ healthWallet: "" }, (d) => {
    if (d.healthWallet) healthAddress.value = d.healthWallet;
  });

  healthScanBtn.addEventListener("click", () => {
    const addr = healthAddress.value.trim();
    const errEl = document.getElementById("healthError");
    if (!addr || !addr.startsWith("0x") || addr.length < 40) {
      errEl.style.display = "block";
      errEl.textContent = t("msgErrInvalidWallet");
      return;
    }
    errEl.style.display = "none";
    chrome.storage.local.set({ healthWallet: addr });
    runHealthScan(addr, {
      resultEl:    document.getElementById("healthResult"),
      loadingEl:   document.getElementById("healthLoading"),
      errorEl:     errEl,
      scoreNumEl:  document.getElementById("healthScoreNum"),
      statsEl:     document.getElementById("healthStats"),
      approvalsEl: document.getElementById("healthApprovals"),
      maxApprovals: 12,
      compact: true,
    });
  });

  // Ask ShieldBot AI — open side panel
  document.getElementById("askBtn")?.addEventListener("click", async () => {
    await chrome.sidePanel.open({ windowId: (await chrome.windows.getCurrent()).id });
    window.close();
  });
}

// ============================================================
// SHARED: connection check
// ============================================================

async function checkConnection(apiUrl, dotEl, textEl) {
  if (!apiUrl) { dotEl.className = "status-dot red"; textEl.textContent = t("statusNoApi"); return; }
  dotEl.className = "status-dot yellow";
  textEl.textContent = t("statusChecking");
  try {
    const u = new URL(apiUrl);
    const origin = `${u.protocol}//${u.hostname}${u.port ? ":" + u.port : ""}/*`;
    const hasPerm = await chrome.permissions.contains({ origins: [origin] });
    if (!hasPerm) {
      const granted = await chrome.permissions.request({ origins: [origin] });
      if (!granted) { dotEl.className = "status-dot red"; textEl.textContent = t("statusPermDenied"); return; }
    }
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 5000);
    const resp = await fetch(`${apiUrl}/api/health`, { signal: ctrl.signal });
    clearTimeout(to);
    if (!resp.ok) { dotEl.className = "status-dot red"; textEl.textContent = t("statusConnFailed", { status: resp.status }); return; }
    await resp.json();
    dotEl.className = "status-dot green";
    textEl.textContent = t("statusConnected");
  } catch (err) {
    dotEl.className = "status-dot red";
    textEl.textContent = err.name === "AbortError" ? t("statusTimeout") : t("statusCannotReach");
  }
}

// ============================================================
// SHARED: history
// ============================================================

function loadAndRenderHistory(listEl) {
  chrome.runtime.sendMessage({ type: "SHIELDAI_GET_HISTORY" }, (response) => {
    if (chrome.runtime.lastError || !response) {
      chrome.storage.local.get({ scanHistory: [] }, (d) => renderCompactHistory(d.scanHistory, listEl));
      return;
    }
    renderCompactHistory(response.history || [], listEl);
  });
}

function renderCompactHistory(history, listEl) {
  if (!history || !history.length) {
    listEl.innerHTML = `<div class="history-empty">${t("historyEmpty")}</div>`;
    return;
  }
  const MAP = {
    SAFE:              { cls: "badge-safe",    label: t("classSafe") },
    CAUTION:           { cls: "badge-caution", label: t("classCaution") },
    HIGH_RISK:         { cls: "badge-high",    label: t("classHighRisk") },
    BLOCK_RECOMMENDED: { cls: "badge-block",   label: t("classBlock") },
  };
  listEl.innerHTML = history.map((item) => {
    const b = MAP[item.classification] || { cls: "badge-caution", label: item.classification };
    const safety = 100 - (item.risk_score || 0);
    return `<div class="history-item">
      <span class="history-badge ${b.cls}">${b.label}</span>
      <div class="history-info">
        <div class="history-recipient">${escapeHtml(item.recipient || item.to || "Unknown")}</div>
        <div class="history-time">${formatTime(item.timestamp)}</div>
      </div>
      <div class="history-score">${safety}/100</div>
    </div>`;
  }).join("");
}

// ============================================================
// SHARED: health scan
// ============================================================

async function runHealthScan(addr, ctx) {
  const { apiUrl } = await new Promise((r) => chrome.storage.local.get({ apiUrl: DEFAULT_API_URL }, r));
  ctx.resultEl.style.display  = "none";
  ctx.loadingEl.style.display = "block";
  ctx.errorEl.style.display   = "none";
  try {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 60000);
    const resp = await fetch(`${apiUrl}/api/rescue/${addr}?chain_id=56`, { signal: ctrl.signal });
    clearTimeout(to);
    ctx.loadingEl.style.display = "none";
    if (!resp.ok) throw new Error(`API error ${resp.status}`);
    renderHealthData(await resp.json(), ctx);
  } catch (err) {
    ctx.loadingEl.style.display = "none";
    ctx.errorEl.style.display   = "block";
    ctx.errorEl.textContent = err.name === "AbortError" ? t("healthScanTimeout") : (err.message || t("healthScanFailed"));
  }
}

function renderHealthData(data, ctx) {
  const highRisk   = data.high_risk || 0;
  const mediumRisk = data.medium_risk || 0;
  const totalUsd   = data.total_value_at_risk_usd || 0;
  const score      = Math.max(0, 100 - highRisk * 20 - mediumRisk * 5);
  const scoreColor = score < 50 ? "#ef4444" : score < 80 ? "#f97316" : "#22c55e";

  ctx.scoreNumEl.textContent = score;
  ctx.scoreNumEl.style.color = scoreColor;

  const usdColor = totalUsd > 0 ? "#ef4444" : "#94a3b8";

  if (ctx.compact) {
    ctx.statsEl.innerHTML = `
      <div class="health-stat"><div class="health-stat-num" style="color:#ef4444">${highRisk}</div><div class="health-stat-label">${t("healthHighRisk")}</div></div>
      <div class="health-stat"><div class="health-stat-num" style="color:#f97316">${mediumRisk}</div><div class="health-stat-label">${t("healthMedium")}</div></div>
      <div class="health-stat"><div class="health-stat-num" style="color:${usdColor};font-size:14px">${fmtUsd(totalUsd) || "$0"}</div><div class="health-stat-label">${t("healthAtRisk")}</div></div>`;
  } else {
    ctx.statsEl.innerHTML = `
      <div class="wh-stat"><div class="wh-statnum" style="color:#ef4444">${highRisk}</div><div class="wh-statlbl">${t("healthHighRisk")}</div></div>
      <div class="wh-stat"><div class="wh-statnum" style="color:#f97316">${mediumRisk}</div><div class="wh-statlbl">${t("healthMedium")}</div></div>
      <div class="wh-stat"><div class="wh-statnum" style="color:${usdColor};font-size:11px">${fmtUsd(totalUsd) || "$0"}</div><div class="wh-statlbl">${t("healthAtRisk")}</div></div>`;
  }

  const approvals  = data.approvals || [];
  const riskClass  = { HIGH: "risk-high", MEDIUM: "risk-medium", LOW: "risk-low" };

  if (!approvals.length) {
    ctx.approvalsEl.innerHTML = ctx.compact
      ? `<div class="health-empty">${t("healthNoApprovals")}</div>`
      : `<div class="wh-empty">${t("healthNoApprovalsDash")}</div>`;
  } else if (ctx.compact) {
    ctx.approvalsEl.innerHTML = approvals.slice(0, 12).map((a) => {
      const spd = a.spender_label && a.spender_label !== "Unknown Contract" ? escapeHtml(a.spender_label) : escapeHtml(shortAddr(a.spender || ""));
      const right = a.value_at_risk_usd
        ? `<div class="health-usd-risk">${escapeHtml(fmtUsd(a.value_at_risk_usd))}</div>`
        : `<div class="health-allowance">${escapeHtml(a.allowance || "")}</div>`;
      return `<div class="health-approval-item">
        <span class="health-risk-badge ${riskClass[a.risk_level] || "risk-low"}">${escapeHtml(a.risk_level)}</span>
        <div class="health-token">
          <div class="health-token-name">${escapeHtml(a.token_symbol || shortAddr(a.token_address))}</div>
          <div class="health-token-reason">${spd}</div>
        </div>${right}</div>`;
    }).join("");
  } else {
    ctx.approvalsEl.innerHTML = approvals.slice(0, 20).map((a) => {
      const spd = a.spender_label && a.spender_label !== "Unknown Contract" ? escapeHtml(a.spender_label) : escapeHtml(shortAddr(a.spender || ""));
      const usdEl = a.value_at_risk_usd ? `<div class="wh-appr-usd">${escapeHtml(fmtUsd(a.value_at_risk_usd))}</div>` : "";
      return `<div class="wh-appr">
        <span class="wh-appr-badge ${riskClass[a.risk_level] || "risk-low"}">${escapeHtml(a.risk_level)}</span>
        <div class="wh-appr-tok">
          <div class="wh-appr-name">${escapeHtml(a.token_symbol || shortAddr(a.token_address))}</div>
          <div class="wh-appr-spender">${spd}</div>
        </div>${usdEl}</div>`;
    }).join("");
  }

  ctx.resultEl.style.display = "block";
}

// ============================================================
// DASHBOARD
// ============================================================

function initDashboard() {
  const dashDot    = document.getElementById("dash-statusDot");
  const dashText   = document.getElementById("dash-statusText");
  const dashApiUrl = document.getElementById("dash-apiUrl");
  const dashEnabled = document.getElementById("dash-enabled");
  const dashSaveBtn = document.getElementById("dash-saveBtn");
  const dashSavedMsg = document.getElementById("dash-savedMsg");

  // Load settings
  chrome.storage.local.get({ apiUrl: DEFAULT_API_URL, enabled: true, policyMode: "BALANCED" }, (data) => {
    dashApiUrl.value = data.apiUrl;
    dashEnabled.checked = data.enabled;
    const radio = document.querySelector(`input[name="dashPolicy"][value="${data.policyMode}"]`);
    if (radio) radio.checked = true;
    checkConnection(data.apiUrl, dashDot, dashText);
  });

  // Save
  dashSaveBtn.addEventListener("click", () => {
    const apiUrl = dashApiUrl.value.trim().replace(/\/+$/, "");
    const enabled = dashEnabled.checked;
    if (!apiUrl)               { showDashMsg(dashSavedMsg, t("msgErrEmptyUrl"), true); return; }
    if (!isAllowedUrl(apiUrl)) { showDashMsg(dashSavedMsg, t("msgErrHttps"), true); return; }
    try { new URL(apiUrl); } catch { showDashMsg(dashSavedMsg, t("msgErrInvalidUrl"), true); return; }
    const policyMode = document.querySelector('input[name="dashPolicy"]:checked')?.value || "BALANCED";
    chrome.storage.local.set({ apiUrl, enabled, policyMode }, () => {
      showDashMsg(dashSavedMsg, t("msgSavedDash"), false);
      checkConnection(apiUrl, dashDot, dashText);
    });
  });

  // Language selector
  const dashLangSel = document.getElementById("dash-langSelect");
  if (dashLangSel) {
    dashLangSel.value = getCurrentLang ? getCurrentLang() : "en";
    dashLangSel.addEventListener("change", async () => {
      if (typeof setLanguage === "function") {
        await setLanguage(dashLangSel.value);
        applyTranslations();
      }
    });
  }

  // Load history → feed + center + stats
  chrome.runtime.sendMessage({ type: "SHIELDAI_GET_HISTORY" }, (response) => {
    if (chrome.runtime.lastError || !response) {
      chrome.storage.local.get({ scanHistory: [] }, (d) => applyHistory(d.scanHistory || []));
      return;
    }
    applyHistory(response.history || []);
  });

  // Wallet health
  const whAddr    = document.getElementById("dash-healthAddr");
  const whScanBtn = document.getElementById("dash-healthScanBtn");
  const whResult  = document.getElementById("dash-healthResult");
  const whLoading = document.getElementById("dash-healthLoading");
  const whError   = document.getElementById("dash-healthError");

  chrome.storage.local.get({ healthWallet: "" }, (d) => { if (d.healthWallet) whAddr.value = d.healthWallet; });

  whScanBtn.addEventListener("click", () => {
    const addr = whAddr.value.trim();
    if (!addr || !addr.startsWith("0x") || addr.length < 40) {
      whError.style.display = "block";
      whError.textContent = t("msgErrInvalidWallet");
      return;
    }
    whError.style.display = "none";
    chrome.storage.local.set({ healthWallet: addr });
    runHealthScan(addr, {
      resultEl:    whResult,
      loadingEl:   whLoading,
      errorEl:     whError,
      scoreNumEl:  document.getElementById("dash-healthScoreNum"),
      statsEl:     document.getElementById("dash-healthStats"),
      approvalsEl: document.getElementById("dash-healthApprovals"),
      maxApprovals: 20,
      compact: false,
    });
  });
}

function showDashMsg(el, text, isError) {
  el.textContent = text;
  el.style.color = isError ? "#ef4444" : "#22C55E";
  el.classList.add("show");
  setTimeout(() => { el.classList.remove("show"); el.textContent = t("msgSavedDash"); el.style.color = "#22C55E"; }, isError ? 3000 : 2000);
}

function applyHistory(history) {
  renderDashFeed(history);
  renderDashStats(history);
  renderDashCenter(history[0] || null);
}

// ---- Feed ----
const FEED_MAP = {
  SAFE:              { cls: "badge-safe",    label: "SAFE",    color: "#22C55E", border: "#22C55E" },
  CAUTION:           { cls: "badge-caution", label: "CAUTION", color: "#EAB308", border: "#EAB308" },
  HIGH_RISK:         { cls: "badge-high",    label: "HIGH",    color: "#F97316", border: "#F97316" },
  BLOCK_RECOMMENDED: { cls: "badge-block",   label: "BLOCK",   color: "#EF4444", border: "#EF4444" },
};

function renderDashFeed(history) {
  const feedEl = document.getElementById("dash-feed");
  if (!history || !history.length) {
    feedEl.innerHTML = `<div class="feed-empty">
      <div class="feed-scanning"><div class="scan-dot"></div><div class="scan-dot"></div><div class="scan-dot"></div></div>
      <div class="feed-empty-lbl">${t("dashMonitoring")}</div>
    </div>`;
    return;
  }
  const FEED_LABELS = {
    SAFE:              t("classSafe"),
    CAUTION:           t("classCaution"),
    HIGH_RISK:         t("classHighRisk"),
    BLOCK_RECOMMENDED: t("classBlock"),
  };
  feedEl.innerHTML = history.slice(0, 8).map((item) => {
    const b = FEED_MAP[item.classification] || { cls: "badge-caution", color: "#EAB308", border: "#EAB308" };
    const lbl = FEED_LABELS[item.classification] || item.classification;
    const safety = 100 - (item.risk_score || 0);
    const addr = escapeHtml(shortAddr(item.recipient || item.to || "Unknown"));
    return `<div class="feed-item" style="--fc:${b.border}">
      <span class="feed-badge ${b.cls}">${lbl}</span>
      <div class="feed-info">
        <div class="feed-addr">${addr}</div>
        <div class="feed-time">${formatTime(item.timestamp)}</div>
      </div>
      <div class="feed-score" style="color:${b.color}">${safety}</div>
    </div>`;
  }).join("");
}

// ---- Stats ----
function renderDashStats(history) {
  const total   = history.length;
  const blocked = history.filter((h) => h.classification === "BLOCK_RECOMMENDED").length;
  const safe    = history.filter((h) => h.classification === "SAFE").length;
  const safeRate = total > 0 ? Math.round((safe / total) * 100) : 100;

  document.getElementById("dash-stat-total").textContent   = total;
  document.getElementById("dash-stat-blocked").textContent = blocked;
  document.getElementById("dash-stat-safe").textContent    = safeRate + "%";
}

// ---- Center ----
function renderDashCenter(lastScan) {
  const gaugeArc      = document.getElementById("dash-gauge-arc");
  const gaugeNum      = document.getElementById("dash-gauge-num");
  const clsBadge      = document.getElementById("dash-cls-badge");
  const metaEl        = document.getElementById("dash-ctr-meta");
  const protectedList = document.getElementById("dash-protected-list");
  const verdictWrap   = document.getElementById("dash-verdict-wrap");
  const verdictEl     = document.getElementById("dash-verdict");

  if (!lastScan) {
    // Default: PROTECTED / 100
    setGauge(gaugeArc, gaugeNum, 100, true);
    clsBadge.textContent = "PROTECTED";
    clsBadge.className   = "cls-badge cls-protected";
    metaEl.textContent   = t("dashFirewallActive");
    protectedList.style.display = "block";
    verdictWrap.style.display   = "none";
    return;
  }

  const safety = 100 - (lastScan.risk_score || 0);
  setGauge(gaugeArc, gaugeNum, safety, false);

  const CLS = {
    SAFE:              { cls: "cls-safe",    label: t("classSafe") },
    CAUTION:           { cls: "cls-caution", label: t("classCaution") },
    HIGH_RISK:         { cls: "cls-high",    label: t("classHighRisk") },
    BLOCK_RECOMMENDED: { cls: "cls-block",   label: t("classBlock") },
  };
  const b = CLS[lastScan.classification] || { cls: "cls-caution", label: lastScan.classification };
  clsBadge.textContent = b.label;
  clsBadge.className   = `cls-badge ${b.cls}`;

  const addr = shortAddr(lastScan.recipient || lastScan.to || "");
  metaEl.textContent = [addr ? `→ ${addr}` : "", formatTime(lastScan.timestamp)].filter(Boolean).join(" \u00b7 ");

  protectedList.style.display = "none";
  verdictWrap.style.display   = "block";
  verdictEl.textContent = lastScan.verdict || t("overlayNoAnalysis");
}

function setGauge(arcEl, numEl, score, glow) {
  const circumference = 439.82;
  const totalArc      = 293.2;
  const clamped = Math.max(0, Math.min(100, score));
  const filled  = totalArc * (clamped / 100);

  arcEl.style.strokeDasharray = `${filled} ${circumference - filled}`;

  const color = clamped >= 80 ? "#22C55E" : clamped >= 50 ? "#F97316" : "#EF4444";
  arcEl.style.stroke = color;

  numEl.textContent  = clamped;
  numEl.style.fill   = clamped >= 80 ? "#f8fafc" : color;

  if (glow) {
    arcEl.classList.add("glow");
  } else {
    arcEl.classList.remove("glow");
  }
}

// ============================================================
// FEED TAB — $SHIELDBOT holder deployer alerts
// ============================================================

let _feedBtnInit = false;

function initFeedTab() {
  const feedAddr   = document.getElementById("feedAddress");
  const feedBtn    = document.getElementById("feedLoadBtn");
  const feedErr    = document.getElementById("feedError");
  const feedLoad   = document.getElementById("feedLoading");
  const feedLocked = document.getElementById("feedLocked");
  const feedList   = document.getElementById("feedList");

  if (!feedAddr || !feedBtn) return;

  // Add button listener only once — prevents stacking on repeated tab clicks
  if (!_feedBtnInit) {
    _feedBtnInit = true;
    feedBtn.addEventListener("click", () => {
      const addr = feedAddr.value.trim();
      feedErr.style.display = "none";
      if (!addr || !/^0x[a-fA-F0-9]{40}$/i.test(addr)) {
        feedErr.textContent = t("msgErrInvalidWallet");
        feedErr.style.display = "block";
        return;
      }
      chrome.storage.local.set({ feedWallet: addr });
      loadDeployerFeed(addr, { feedErr, feedLoad, feedLocked, feedList });
    });
  }

  // Auto-load from saved wallet each time tab is opened
  chrome.storage.local.get({ healthWallet: "", feedWallet: "" }, (d) => {
    const saved = d.feedWallet || d.healthWallet;
    if (saved) {
      feedAddr.value = saved;
      loadDeployerFeed(saved, { feedErr, feedLoad, feedLocked, feedList });
    }
  });
}

async function loadDeployerFeed(wallet, { feedErr, feedLoad, feedLocked, feedList }) {
  feedErr.style.display    = "none";
  feedLocked.style.display = "none";
  feedList.innerHTML       = "";
  feedLoad.style.display   = "block";

  try {
    const { apiUrl } = await new Promise((r) =>
      chrome.storage.local.get({ apiUrl: DEFAULT_API_URL }, r)
    );

    const ctrl = new AbortController();
    const to   = setTimeout(() => ctrl.abort(), 10000);
    const resp = await fetch(
      `${apiUrl}/api/watch/alerts?wallet=${encodeURIComponent(wallet)}`,
      { signal: ctrl.signal }
    );
    clearTimeout(to);
    feedLoad.style.display = "none";

    if (resp.status === 403) {
      feedLocked.style.display = "block";
      return;
    }

    if (!resp.ok) {
      feedErr.textContent = `API error ${resp.status}`;
      feedErr.style.display = "block";
      return;
    }

    const data   = await resp.json();
    const alerts = data.alerts || [];
    renderDeployerAlerts(alerts, feedList);
  } catch (err) {
    feedLoad.style.display = "none";
    feedErr.textContent = err.name === "AbortError"
      ? t("statusTimeout")
      : (err.message || t("statusCannotReach"));
    feedErr.style.display = "block";
  }
}

function renderDeployerAlerts(alerts, listEl) {
  if (!alerts.length) {
    listEl.innerHTML = `<div class="feed-empty-msg">${t("feedNoAlerts") || "No deployer alerts yet"}</div>`;
    return;
  }

  const CHAIN_NAMES = { 56: "BSC", 1: "ETH", 137: "Polygon", 42161: "Arbitrum", 8453: "Base", 10: "Optimism", 204: "opBNB" };

  listEl.innerHTML = alerts.map((a) => {
    const chain    = CHAIN_NAMES[a.chain_id] || `Chain ${a.chain_id}`;
    const deployer = a.deployer_address ? shortAddr(a.deployer_address) : "Unknown";
    const contract = a.new_contract_address ? shortAddr(a.new_contract_address) : "Unknown";
    const reason   = a.watch_reason || "";
    const time     = a.created_at ? formatTime(a.created_at * 1000) : "";

    return `<div class="deployer-item">
      <div class="deployer-item-info">
        <div class="deployer-addr" title="${escapeHtml(a.deployer_address || "")}">
          Deployer: ${escapeHtml(deployer)}
        </div>
        <div class="deployer-contract" title="${escapeHtml(a.new_contract_address || "")}">
          Contract: ${escapeHtml(contract)} &middot; ${escapeHtml(chain)}
        </div>
        ${reason ? `<div class="deployer-reason">${escapeHtml(reason)}</div>` : ""}
      </div>
      <div class="deployer-time">${escapeHtml(time)}</div>
    </div>`;
  }).join("");
}
