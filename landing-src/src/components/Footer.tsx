import { useState, type FormEvent } from "react";
import { Mark } from "./Icon";

const linkClass = "inline-flex items-center min-h-[44px] md:min-h-0 text-sm text-onink hover:text-white focus-visible:outline-emerald-onink transition-colors duration-150 ease-out";

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
      ? "text-emerald-onink"
      : status === "error"
        ? "text-onink-error"
        : status === "dup"
          ? "text-onink-muted"
          : "";

  return (
    <footer className="bg-panel text-onink">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-14 lg:py-16">
        <div className="grid grid-cols-1 gap-12 lg:grid-cols-12">
          <div className="lg:col-span-5">
            <div className="flex items-center gap-2">
              <Mark size={28} className="text-emerald-onink" />
              <span className="text-lg font-bold"><span className="text-white">Shield</span><span className="text-emerald-onink">Bot</span></span>
            </div>
            <p className="mt-3 text-sm text-onink">The security layer that says what it checked.</p>

            <form onSubmit={handleSubmit} className="mt-6 max-w-sm">
              <label htmlFor="footer-email" className="sr-only">Email address for product updates</label>
              <div className="flex flex-wrap gap-2">
                <input
                  id="footer-email"
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="Email for product updates"
                  required
                  className="flex-1 min-w-0 h-11 px-3 bg-field border border-line-strong rounded-md text-sm text-ink placeholder:text-muted focus:border-emerald focus-visible:outline-emerald-onink transition-colors duration-150 ease-out"
                />
                <button type="submit" disabled={status === "loading"} className="h-11 px-4 bg-emerald text-onfill text-sm font-semibold rounded-lg shadow-button active:shadow-none hover:bg-emerald-deep active:bg-emerald-deep active:translate-y-px focus-visible:outline-emerald-onink transition-colors duration-150 ease-out disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap">
                  {status === "loading" ? "Sending…" : "Get updates"}
                </button>
              </div>
              <p role="status" className={`mt-2 text-sm ${msgColor}`}>{message}</p>
            </form>

            <div className="mt-6">
              <p className="text-[13px] text-onink">Built by Ridwan Nurudeen, founder and solo builder.</p>
              <div className="flex items-center gap-1 mt-2">
                <a href="https://x.com/Ggudman1" target="_blank" rel="noopener noreferrer" aria-label="@Ggudman1" className="flex items-center justify-center w-11 h-11 text-onink hover:text-white focus-visible:outline-emerald-onink transition-colors duration-150 ease-out">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.744l7.73-8.835L1.254 2.25H8.08l4.253 5.622L18.244 2.25zm-1.161 17.52h1.833L7.084 4.126H5.117L17.083 19.77z" /></svg>
                </a>
                <a href="https://github.com/Ridwannurudeen" target="_blank" rel="noopener noreferrer" aria-label="GitHub" className="flex items-center justify-center w-11 h-11 text-onink hover:text-white focus-visible:outline-emerald-onink transition-colors duration-150 ease-out">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z" /></svg>
                </a>
                <a href="https://t.me/Ggudman" target="_blank" rel="noopener noreferrer" aria-label="Telegram" className="flex items-center justify-center w-11 h-11 text-onink hover:text-white focus-visible:outline-emerald-onink transition-colors duration-150 ease-out">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.562 8.248-1.97 9.289c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12L7.08 14.784l-2.968-.924c-.645-.204-.657-.645.136-.953l11.57-4.461c.537-.194 1.006.131.744.802z" /></svg>
                </a>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 sm:grid-cols-3 lg:col-span-7">
            <div>
              <h2 className="text-xs font-bold uppercase tracking-[0.12em] text-onink-muted">Product</h2>
              <div className="mt-3 flex flex-col gap-2">
                <a href="#how-it-works" className={linkClass}>How it works</a>
                <a href="#on-chain" className={linkClass}>On-chain check</a>
                <a href="#chains" className={linkClass}>Coverage</a>
                <a href="#agent-security" className={linkClass}>For builders</a>
                <a href="/dashboard" className={linkClass}>Threat dashboard</a>
                <a href="#faq" className={linkClass}>FAQ</a>
                <a href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk" target="_blank" rel="noopener noreferrer" className={linkClass}>Chrome extension</a>
                <a href="https://api.shieldbotsecurity.online/docs" target="_blank" rel="noopener noreferrer" className={linkClass}>API docs</a>
              </div>
            </div>
            <div>
              <h2 className="text-xs font-bold uppercase tracking-[0.12em] text-onink-muted">Legal</h2>
              <div className="mt-3 flex flex-col gap-2">
                <a href="/privacy.html" className={linkClass}>Privacy Policy</a>
                <a href="/terms.html" className={linkClass}>Terms of Service</a>
                <a href="/security.html" className={linkClass}>Security</a>
              </div>
            </div>
            <div className="min-w-0">
              <h2 className="text-xs font-bold uppercase tracking-[0.12em] text-onink-muted">Community</h2>
              <div className="mt-3 flex flex-col gap-2">
                <a href="https://github.com/Ridwannurudeen/shieldbot" target="_blank" rel="noopener noreferrer" className={linkClass}>GitHub</a>
                <a href="https://t.me/shieldbot_bnb_bot" target="_blank" rel="noopener noreferrer" className={linkClass}>Telegram bot</a>
                <a href="https://x.com/shieldbot_" target="_blank" rel="noopener noreferrer" className={linkClass}>@shieldbot_</a>
                <a href="mailto:support@shieldbotsecurity.online" className={`${linkClass} [overflow-wrap:anywhere]`}>support@shieldbotsecurity.online</a>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-12 pt-6 border-t border-white/10 text-center text-xs text-onink-muted">© 2026 ShieldBot. Transaction security for 8 EVM chains.</div>
      </div>
    </footer>
  );
}
