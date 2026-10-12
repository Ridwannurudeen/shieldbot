import { useEffect, useState, type FormEvent } from "react";
import Badge from "./Badge";
import { labels } from "../firewallVerdict";
import { short } from "../registryFeed";

const linkClass = "inline-flex items-center min-h-[44px] md:min-h-[32px] text-[15px] text-ink hover:text-accent transition-colors duration-150 ease-out";
const headingClass = "text-xs font-medium uppercase tracking-[0.08em] text-secondary";
const docHeadingClass = "font-mono text-xs uppercase tracking-[0.08em] text-secondary";

// The three Robinhood Chain contracts, as docs/DEPLOYMENTS.md records them (OnChain.tsx lists them in full).
const contracts = [
  { name: "Registry", address: "0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138" },
  { name: "Guard", address: "0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e" },
  { name: "Guarded transfer", address: "0x336254bA85406D9af39357101b688E2B757751b3" },
];

interface Health {
  status: string;
  supported_chains: number[];
}

// GET /api/health once when the page loads, with the time its reply arrived. undefined while loading, null when it
// did not answer in 10 seconds; nothing is filled in.
function useHealth() {
  const [health, setHealth] = useState<{ reply: Health; at: Date } | null | undefined>(undefined);
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    const timeout = setTimeout(() => controller.abort(), 10_000);

    fetch("https://api.shieldbotsecurity.online/api/health", { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((reply: Health) => {
        if (active) setHealth({ reply, at: new Date() });
      })
      .catch(() => {
        if (active) setHealth(null);
      })
      .finally(() => clearTimeout(timeout));
    return () => {
      active = false;
      clearTimeout(timeout);
      controller.abort();
    };
  }, []);
  return health;
}

export default function Footer() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error" | "dup">("idle");
  const [message, setMessage] = useState("");
  const health = useHealth();

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
    <footer className="border-t border-hairline bg-ground-alt">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-14 lg:pt-20">
        <div className="grid grid-cols-1 gap-12 lg:grid-cols-12">
          <div className="min-w-0 lg:col-span-5">
            <a href="#top" className="inline-flex min-h-[44px] items-center gap-2">
              <span className="mark-slot inline-block w-6 h-6 empty:hidden" aria-hidden="true" />
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
                  className="h-11 min-w-0 flex-1 rounded-lg border border-unknown bg-ground px-3 text-[15px] text-ink placeholder:text-secondary transition-colors duration-150 ease-out focus:border-accent"
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
                <a href="#chains" className={linkClass}>Coverage</a>
                <a href="#on-chain" className={linkClass}>On-chain registry</a>
                <a href="#agent-security" className={linkClass}>For builders</a>
                <a href="/dashboard" className={linkClass}>Dashboard</a>
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
                <a href="https://x.com/Ggudman1" target="_blank" rel="noopener noreferrer" className={linkClass}>Founder: @Ggudman1</a>
                <a href="mailto:support@shieldbotsecurity.online" className={`${linkClass} [overflow-wrap:anywhere]`}>support@shieldbotsecurity.online</a>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-14 grid grid-cols-1 gap-10 border-t border-hairline-strong pt-8 md:grid-cols-2 lg:grid-cols-[minmax(0,5fr)_minmax(0,4fr)_minmax(0,3fr)] lg:gap-12">
          <div className="min-w-0">
            <h2 className={docHeadingClass}>Contracts · Robinhood Chain (4663)</h2>
            <dl className="mt-2 grid grid-cols-[max-content_minmax(0,1fr)] items-center gap-x-5 font-mono text-[13px] leading-5">
              {contracts.map((contract) => (
                <div key={contract.name} className="contents">
                  <dt className="text-secondary">{contract.name}</dt>
                  <dd className="min-w-0">
                    <a
                      href={`https://robin.etherscan.io/address/${contract.address}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex min-h-[44px] items-center text-ink underline decoration-hairline-strong md:min-h-8 underline-offset-4 transition-colors duration-150 ease-out hover:text-accent"
                    >
                      {short(contract.address)}
                    </a>
                  </dd>
                </div>
              ))}
            </dl>
            <p className="mt-3 text-[13px] leading-5 text-secondary">Deployed on Robinhood Chain on 27 September 2026.</p>
          </div>
          <div className="min-w-0">
            <h2 className={docHeadingClass}>Verdicts</h2>
            <ul className="mt-4 flex flex-wrap gap-2">
              {Object.values(labels).map(({ verdict, text }) => (
                <li key={verdict}>
                  <Badge verdict={verdict}>{text}</Badge>
                </li>
              ))}
            </ul>
            <p className="mt-3 text-[13px] leading-5 text-secondary">When a check cannot run, the verdict is Unknown, never Safe.</p>
            <p className="mt-2 text-[13px] leading-5 text-secondary">
              Registry records keep their own words: LOW, MEDIUM, HIGH, HONEYPOT, UNKNOWN. LOW and MEDIUM are drawn plain,{" "}
              <Badge verdict="registry">LOW</Badge>; the guard allows both while fresh.
            </p>
          </div>
          <div className="min-w-0">
            <h2 className={docHeadingClass}>API</h2>
            <p role="status" className="mt-4 font-mono text-[13px] leading-5 text-ink">
              {health === undefined
                ? "GET /api/health …"
                : health === null
                  ? "Unavailable. GET /api/health did not answer."
                  : `GET /api/health: ${health.reply.status}, ${health.reply.supported_chains.length} chains`}
            </p>
            {health && (
              <p className="mt-1 font-mono text-[13px] leading-5 text-secondary">
                Fetched {health.at.toISOString().slice(0, 19).replace("T", " ")} UTC
              </p>
            )}
          </div>
        </div>

        <div className="mt-10 flex flex-col gap-2 border-t border-hairline py-6 text-[13px] text-secondary sm:flex-row sm:justify-between">
          <span>© 2026 ShieldBot. Transaction security for 8 EVM chains.</span>
          <span>ShieldBot does not issue, sell or endorse any token.</span>
        </div>
      </div>
    </footer>
  );
}
