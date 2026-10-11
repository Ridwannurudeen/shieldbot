import { useState, type FormEvent } from "react";

const linkClass = "inline-flex items-center min-h-[44px] md:min-h-[32px] text-[15px] text-ink hover:text-accent transition-colors duration-150 ease-out";
const headingClass = "text-xs font-medium uppercase tracking-[0.08em] text-secondary";

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
      ? "text-safe-text"
      : status === "error"
        ? "text-block-text"
        : status === "dup"
          ? "text-secondary"
          : "";

  return (
    <footer className="overflow-hidden border-t border-hairline bg-ground-alt">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-14 lg:pt-20">
        <div className="grid grid-cols-1 gap-12 lg:grid-cols-12">
          <div className="min-w-0 lg:col-span-5">
            <a href="#top" className="inline-flex min-h-[44px] items-center gap-2">
              <span className="mark-slot inline-block w-6 h-6" aria-hidden="true" />
              <span className="text-[22px] leading-none font-medium tracking-[-0.03em] text-ink">ShieldBot</span>
            </a>
            <p className="mt-3 max-w-[24em] text-[15px] leading-relaxed text-secondary">The security layer that says what it checked.</p>

            <form onSubmit={handleSubmit} className="mt-8 max-w-sm">
              <label htmlFor="footer-email" className="text-sm text-secondary">Email for product updates</label>
              <div className="mt-2 flex flex-wrap gap-2">
                <input
                  id="footer-email"
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="you@example.com"
                  required
                  className="h-11 min-w-0 flex-1 rounded-lg border border-hairline-strong bg-ground px-3 text-[15px] text-ink placeholder:text-secondary transition-colors duration-150 ease-out focus:border-accent"
                />
                <button
                  type="submit"
                  disabled={status === "loading"}
                  className="h-11 whitespace-nowrap rounded-lg bg-accent px-5 text-[15px] font-medium text-on-accent shadow-button transition-colors duration-150 ease-out hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {status === "loading" ? "Sending…" : "Get updates"}
                </button>
              </div>
              <p role="status" className={`mt-2 min-h-5 text-sm ${msgColor}`}>{message}</p>
            </form>

            <p className="mt-4 text-sm text-secondary">Built by Ridwan Nurudeen, founder and solo builder.</p>
          </div>

          <div className="grid grid-cols-2 gap-8 sm:grid-cols-3 lg:col-span-7">
            <div className="min-w-0">
              <h2 className={headingClass}>Product</h2>
              <div className="mt-4 flex flex-col gap-1">
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
            <div className="min-w-0">
              <h2 className={headingClass}>Legal</h2>
              <div className="mt-4 flex flex-col gap-1">
                <a href="/privacy.html" className={linkClass}>Privacy Policy</a>
                <a href="/terms.html" className={linkClass}>Terms of Service</a>
                <a href="/security.html" className={linkClass}>Security</a>
              </div>
            </div>
            <div className="col-span-2 min-w-0 sm:col-span-1">
              <h2 className={headingClass}>Community</h2>
              <div className="mt-4 flex flex-col gap-1">
                <a href="https://github.com/Ridwannurudeen/shieldbot" target="_blank" rel="noopener noreferrer" className={linkClass}>GitHub</a>
                <a href="https://t.me/shieldbot_bnb_bot" target="_blank" rel="noopener noreferrer" className={linkClass}>Telegram bot</a>
                <a href="https://x.com/shieldbot_" target="_blank" rel="noopener noreferrer" className={linkClass}>@shieldbot_</a>
                <a href="https://x.com/Ggudman1" target="_blank" rel="noopener noreferrer" className={linkClass}>Founder on X, @Ggudman1</a>
                <a href="https://github.com/Ridwannurudeen" target="_blank" rel="noopener noreferrer" className={linkClass}>Founder on GitHub</a>
                <a href="https://t.me/Ggudman" target="_blank" rel="noopener noreferrer" className={linkClass}>Founder on Telegram</a>
                <a href="mailto:support@shieldbotsecurity.online" className={`${linkClass} [overflow-wrap:anywhere]`}>support@shieldbotsecurity.online</a>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-14 flex flex-col gap-2 border-t border-hairline py-6 text-[13px] text-secondary sm:flex-row sm:justify-between">
          <span>© 2026 ShieldBot. Transaction security for 8 EVM chains.</span>
          <span>ShieldBot does not issue, sell or endorse any token.</span>
        </div>
      </div>
      <p
        className="mx-auto -mb-[0.2em] max-w-6xl select-none whitespace-nowrap px-4 text-center text-[clamp(64px,19vw,232px)] font-medium leading-none tracking-[-0.04em] text-transparent [-webkit-text-stroke:1px_rgb(var(--c-hairline-strong))] sm:px-6"
        aria-hidden="true"
      >
        ShieldBot
      </p>
    </footer>
  );
}
