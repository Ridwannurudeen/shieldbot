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

      statusMsg.textContent = t("welcomeCheckingConn");
      const { apiUrl } = await chrome.storage.local.get({ apiUrl: "https://api.shieldbotsecurity.online" });
      const res = await fetch(`${apiUrl}/api/health`, {
        signal: AbortSignal.timeout(8000)
      });
      if (!res.ok) throw new Error(t("welcomeHealthFailed", { status: res.status }));

      btn.textContent = t("welcomeProtected");
      btn.style.background = "#16a34a";
      statusMsg.textContent = t("welcomeActiveMsg");
      closeLink.style.display = "block";
    } catch (err) {
      const msg = err.message || t("welcomePermDenied");
      btn.textContent = t("welcomeConnFailed");
      btn.style.background = "#dc2626";
      btn.disabled = false;
      statusMsg.textContent = msg;
    }
  });

  closeLink.addEventListener("click", () => {
    window.close();
  });
});
