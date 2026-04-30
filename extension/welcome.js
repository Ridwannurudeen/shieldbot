window.addEventListener("DOMContentLoaded", async () => {
  await initI18n();
  applyTranslations();

  const btn = document.getElementById("connectBtn");
  const statusMsg = document.getElementById("statusMsg");
  const closeLink = document.getElementById("closeLink");

  btn.addEventListener("click", async () => {
    btn.textContent = t("welcomeConnecting");
    btn.disabled = true;
    statusMsg.textContent = t("welcomeRequestingPerms");

    try {
      const granted = await chrome.permissions.request({
        origins: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"]
      });
      if (!granted) throw new Error(t("welcomePermDenied"));

      // Permissions granted — extension is now active (content scripts inject on all sites)
      btn.textContent = t("welcomeProtected");
      btn.style.background = "#16a34a";
      statusMsg.textContent = t("welcomeActiveMsg");
      closeLink.style.display = "block";

      // Non-blocking: verify API connection in the background
      try {
        const { apiUrl } = await chrome.storage.local.get({ apiUrl: "https://api.shieldbotsecurity.online" });
        const res = await fetch(`${apiUrl}/api/health`, {
          signal: AbortSignal.timeout(8000)
        });
        if (res.ok) {
          statusMsg.textContent = t("welcomeFullyConnected");
        } else {
          statusMsg.textContent = t("welcomeActiveOffline");
        }
      } catch (_) {
        statusMsg.textContent = t("welcomeActiveOffline");
      }
    } catch (err) {
      const msg = err.message || t("welcomePermDenied");
      btn.textContent = t("welcomeRetry");
      btn.style.background = "#dc2626";
      btn.disabled = false;
      statusMsg.textContent = msg;
    }
  });

  closeLink.addEventListener("click", () => {
    window.close();
  });
});
