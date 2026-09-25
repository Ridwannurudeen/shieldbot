import { useState, type FormEvent } from "react";

export default function Footer() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error" | "dup">("idle");
  const [message, setMessage] = useState("");

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = email.trim();
    if (!trimmed) return;

    setStatus("loading");
    setMessage("");

    try {
      const res = await fetch("https://api.shieldbotsecurity.online/api/beta-signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: trimmed }),
      });
      const data = await res.json();

      if (res.ok) {
        setStatus("success");
        setMessage(data.message || "You're on the list!");
        setEmail("");
      } else if (res.status === 409) {
        setStatus("dup");
        setMessage(data.detail || "Already signed up.");
      } else {
        setStatus("error");
        setMessage(data.detail || "Something went wrong.");
      }
    } catch {
      setStatus("error");
      setMessage("Network error. Please try again.");
    }
  }

  const msgColor =
    status === "success"
      ? "text-neon"
      : status === "error"
        ? "text-red-400"
        : status === "dup"
          ? "text-gray-400"
          : "";

  return (
    <footer className="py-16 border-t border-white/5">
      <div className="max-w-6xl mx-auto px-6">
        <div className="flex flex-col md:flex-row justify-between gap-10">
          {/* Brand */}
          <div>
            <div className="text-lg font-bold mb-2">
              <span className="text-white">Shield</span>
              <span className="text-neon">Bot</span>
            </div>
            <p className="text-sm text-gray-400">On-chain transaction firewall</p>

            <form onSubmit={handleSubmit} className="flex flex-wrap gap-2 mt-5 max-w-sm">
              <label htmlFor="footer-email" className="sr-only">
                Email address for product updates
              </label>
              <input
                id="footer-email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Email for product updates"
                required
                className="flex-1 min-w-0 min-h-[44px] px-3 bg-navy-light border border-white/15 rounded-lg text-sm text-white
                           placeholder:text-gray-400 outline-none focus:border-neon/50 transition-colors"
              />
              <button
                type="submit"
                disabled={status === "loading"}
                className="min-h-[44px] px-4 bg-white/10 text-white text-sm font-semibold rounded-lg hover:bg-white/20
                           transition-all disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
              >
                {status === "loading" ? "Submitting..." : "Stay Updated"}
              </button>
              <p role="status" className={`w-full text-sm ${msgColor}`}>
                {message}
              </p>
            </form>
          </div>

          {/* Link columns */}
          <div className="flex gap-16 flex-wrap">
            <div>
              <h2 className="text-xs text-gray-400 uppercase tracking-widest mb-3">
                Product
              </h2>
              <div className="flex flex-col md:gap-2">
                <a href="/dashboard" className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors">
                  Threat Dashboard
                </a>
                <a
                  href="https://youtu.be/NN95rom10R8"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  Demo Video
                </a>
                <a
                  href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  Chrome Extension
                </a>
                <a href="#how-it-works" className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors">
                  How It Works
                </a>
                <a href="/privacy.html" className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors">
                  Privacy Policy
                </a>
                <a href="/terms.html" className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors">
                  Terms of Service
                </a>
                <a href="/security.html" className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors">
                  Security
                </a>
              </div>
            </div>
            <div>
              <h2 className="text-xs text-gray-400 uppercase tracking-widest mb-3">
                Community
              </h2>
              <div className="flex flex-col md:gap-2">
                <a
                  href="https://github.com/Ridwannurudeen/shieldbot"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  GitHub
                </a>
                <a
                  href="https://t.me/shieldbot_bnb_bot"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  Telegram Bot
                </a>
                <a
                  href="https://x.com/shieldbot_"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  @shieldbot_
                </a>
                <a
                  href="mailto:support@shieldbotsecurity.online"
                  className="inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  support@shieldbotsecurity.online
                </a>
              </div>
            </div>
          </div>
        </div>

        <div className="text-center text-xs text-gray-400 mt-12">
          &copy; 2026 ShieldBot. Transaction security for 8 EVM chains.
        </div>
      </div>
    </footer>
  );
}
