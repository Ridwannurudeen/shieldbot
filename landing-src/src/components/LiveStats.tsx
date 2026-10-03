import { useEffect, useState } from "react";
import StatTile from "./StatTile";

interface Stats {
  total_pending_seen: number;
  sandwiches_detected: number;
  suspicious_approvals: number;
  counting_since?: number;
}

// Chains the scanner accepts (utils/chain_info.py). tests/test_website_claims.py keeps this in sync.
const SUPPORTED_CHAINS = 8;

function isStats(d: unknown): d is Stats {
  const s = d as Stats;
  return (
    typeof s === "object" &&
    s !== null &&
    typeof s.total_pending_seen === "number" &&
    typeof s.sandwiches_detected === "number" &&
    typeof s.suspicious_approvals === "number"
  );
}

function fmt(n: number): string {
  // 999_500 rather than 1_000_000: at 999_999 the thousands branch would round to "1000K".
  if (n >= 999_500) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 10_000) return (n / 1_000).toFixed(0) + "K";
  return n.toLocaleString();
}

export default function LiveStats() {
  // undefined while loading, null when the live numbers could not be fetched.
  const [stats, setStats] = useState<Stats | null | undefined>(undefined);

  useEffect(() => {
    fetch("https://api.shieldbotsecurity.online/api/mempool/stats")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => setStats(isStats(d) ? d : null))
      .catch(() => setStats(null));
  }, []);

  const show = (n: number | undefined) =>
    stats ? fmt(n ?? 0) : stats === null ? "—" : "…";
  const items = [
    {
      label: "Pending transactions monitored",
      value: show(stats?.total_pending_seen),
    },
    {
      label: "Possible sandwich attacks flagged",
      value: show(stats?.sandwiches_detected),
    },
    {
      label: "Suspicious approvals flagged",
      value: show(stats?.suspicious_approvals),
    },
  ];

  const note =
    stats === undefined
      ? "Loading live data"
      : stats === null
        ? "Live data is unavailable right now"
        : stats.counting_since
          ? `Live mempool counters since ${new Date(stats.counting_since * 1000).toLocaleDateString()}, when the monitor last restarted`
          : "Live mempool counters since the monitor last restarted";
  const dot = `h-2 w-2 rounded-full ${stats ? "bg-emerald-bright motion-safe:animate-pulse" : "bg-line-strong"}`;

  return (
    <section aria-labelledby="live-stats-title" className="bg-surface-2 pt-14 pb-14 md:pt-[72px] md:pb-[72px] lg:pt-24 lg:pb-24">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <p id="live-stats-title" className="text-xs font-bold uppercase tracking-[0.12em] text-emerald">Live mempool counters</p>
        <div className="mt-3 rounded-2xl border border-line bg-surface p-6">
          <div className="flex items-center gap-2 text-[13px] text-muted">
            <span aria-hidden="true" className={dot} />
            <span>{note}</span>
          </div>
          <div className="mt-5 grid grid-cols-1 min-[360px]:grid-cols-2 gap-4 lg:grid-cols-4">
            {items.map((item) => (
              <StatTile
                key={item.label}
                value={item.value}
                label={item.label}
                state={stats === undefined ? "loading" : stats === null ? "unavailable" : "ready"}
              />
            ))}
          </div>
          <p className="mt-4 text-[13px] text-muted">Scans cover {SUPPORTED_CHAINS} chains.</p>
        </div>
      </div>
    </section>
  );
}
