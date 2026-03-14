const DEFAULT_API_URL = "https://api.shieldbotsecurity.online";

document.addEventListener("DOMContentLoaded", async () => {
  const messagesEl = document.getElementById("messages");
  const inputEl = document.getElementById("chatInput");
  const sendBtn = document.getElementById("sendBtn");
  const typingEl = document.getElementById("typing");

  // Get or create a persistent user ID
  let { chatUserId } = await chrome.storage.local.get("chatUserId");
  if (!chatUserId) {
    chatUserId = crypto.randomUUID();
    await chrome.storage.local.set({ chatUserId });
  }

  // Load cached messages on open
  const { chatMessages = [] } = await chrome.storage.local.get("chatMessages");
  chatMessages.forEach(m => appendMessage(m.role, m.text));

  async function sendMessage() {
    const text = inputEl.value.trim();
    if (!text) return;
    inputEl.value = "";
    appendMessage("user", text);
    saveMessages();

    typingEl.style.display = "flex";
    sendBtn.disabled = true;

    try {
      const { apiUrl } = await chrome.storage.local.get({ apiUrl: DEFAULT_API_URL });
      const resp = await fetch(`${apiUrl}/api/agent/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text, user_id: chatUserId }),
        signal: AbortSignal.timeout(30000),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${resp.status}`);
      }

      const data = await resp.json();
      appendMessage("assistant", data.response);
    } catch (err) {
      appendMessage("assistant", `Error: ${err.message}`);
    } finally {
      typingEl.style.display = "none";
      sendBtn.disabled = false;
    }
    saveMessages();
  }

  function appendMessage(role, text) {
    const bubble = document.createElement("div");
    bubble.className = `chat-bubble ${role}`;
    bubble.textContent = text;
    messagesEl.appendChild(bubble);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function saveMessages() {
    const bubbles = messagesEl.querySelectorAll(".chat-bubble");
    const msgs = Array.from(bubbles).slice(-20).map(b => ({
      role: b.classList.contains("user") ? "user" : "assistant",
      text: b.textContent,
    }));
    chrome.storage.local.set({ chatMessages: msgs });
  }

  sendBtn.addEventListener("click", sendMessage);
  inputEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });
});
