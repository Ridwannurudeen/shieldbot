document.getElementById("connectBtn").addEventListener("click", async () => {
  const btn = document.getElementById("connectBtn");
  const statusMsg = document.getElementById("statusMsg");
  const closeLink = document.getElementById("closeLink");

  btn.textContent = "Connecting\u2026";
  btn.disabled = true;
  statusMsg.textContent = "Requesting permissions\u2026";

  try {
    const granted = await chrome.permissions.request({
      origins: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"]
    });
    if (!granted) throw new Error("Permission denied");

    statusMsg.textContent = "Checking connection\u2026";
    const { apiUrl } = await chrome.storage.local.get({ apiUrl: "https://api.shieldbotsecurity.online" });
    const res = await fetch(`${apiUrl}/api/health`, {
      signal: AbortSignal.timeout(8000)
    });
    if (!res.ok) throw new Error(`Health check returned ${res.status}`);

    btn.textContent = "You\u2019re protected \u2713";
    btn.style.background = "#16a34a";
    statusMsg.textContent = "ShieldBot is active. Your transactions are now protected.";
    closeLink.style.display = "block";
  } catch (err) {
    const msg = err.message || "Unknown error";
    btn.textContent = "Connection failed \u2014 try again";
    btn.style.background = "#dc2626";
    btn.disabled = false;
    statusMsg.textContent = msg;
  }
});

document.getElementById("closeLink").addEventListener("click", () => {
  window.close();
});
