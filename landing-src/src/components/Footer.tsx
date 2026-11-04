import { useEffect, useState, type FormEvent } from "react";

interface Health {
  status: string;
  supported_chains: number[];
}

function useHealth() {
  const [health, setHealth] = useState<Health | null | undefined>(undefined);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    const timeout = setTimeout(() => controller.abort(), 10_000);

    fetch("https://api.shieldbotsecurity.online/api/health", {
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((reply: Health) => {
        if (active) setHealth(reply);
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

const links = [
  { label: "About", href: "/about.html" },
  { label: "Safety guide", href: "/safety.html" },
  { label: "Privacy", href: "/privacy.html" },
  { label: "Terms", href: "/terms.html" },
  { label: "Security", href: "/security.html" },
  { label: "Dashboard", href: "/dashboard" },
  { label: "Telegram bot", href: "https://t.me/shieldbot_bnb_bot" },
  { label: "GitHub", href: "https://github.com/Ridwannurudeen/shieldbot" },
  { label: "support@shieldbotsecurity.online", href: "mailto:support@shieldbotsecurity.online" },
];

export default function Footer() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error" | "dup">("idle");
  const [message, setMessage] = useState("");
  const health = useHealth();

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const trimmed = email.trim();
    if (!trimmed) return;

    setStatus("loading");
    setMessage("");

    try {
      const response = await fetch("https://api.shieldbotsecurity.online/api/beta-signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: trimmed }),
      });
      const data = await response.json();

      if (response.ok) {
        setStatus("success");
        setMessage(data.message || "You're on the list!");
        setEmail("");
      } else if (response.status === 409) {
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

  const healthText =
    health === undefined
      ? "API checking"
      : health === null || health.status !== "ok"
        ? "API unavailable"
        : `API up, ${health.supported_chains.length} chains`;

  return (
    <footer className="border-t border-hairline">
      <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6 md:py-12">
        <nav aria-label="Footer links">
          <ul className="flex flex-wrap gap-x-6 gap-y-1">
            {links.map(({ label, href }) => (
              <li key={label}>
                <a
                  href={href}
                  className="inline-flex min-h-11 items-center text-sm text-secondary transition-colors hover:text-ink"
                  {...(href.startsWith("http")
                    ? { target: "_blank", rel: "noopener noreferrer" }
                    : {})}
                >
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </nav>

        <div className="mt-7 flex flex-col gap-4 border-t border-hairline pt-6 sm:flex-row sm:items-center sm:justify-between">
          <form onSubmit={handleSubmit} className="flex max-w-md flex-wrap gap-2">
            <input
              type="email"
              autoComplete="email"
              aria-label="Email for updates"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="Email for updates"
              required
              className="h-11 min-w-0 flex-1 rounded-md border border-edge bg-ground px-3 text-sm text-ink placeholder:text-secondary focus:border-accent"
            />
            <button
              type="submit"
              disabled={status === "loading"}
              className="h-11 rounded-md bg-accent-fill px-4 text-sm font-medium text-on-accent transition-colors hover:bg-accent-fill-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {status === "loading" ? "Sending…" : "Get updates"}
            </button>
          </form>
          <p role="status">
            <a
              href="https://api.shieldbotsecurity.online/api/health"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex min-h-11 items-center font-mono text-xs text-secondary underline decoration-hairline-strong underline-offset-4 hover:text-ink"
            >
              {healthText}
            </a>
          </p>
        </div>

        {message && (
          <p className="mt-2 text-xs text-secondary" role="status">
            {message}
          </p>
        )}

        <p className="mt-7 border-t border-hairline pt-5 text-xs leading-5 text-secondary">
          © 2026 ShieldBot. ShieldBot does not issue, sell or endorse any token.
        </p>
      </div>
    </footer>
  );
}
