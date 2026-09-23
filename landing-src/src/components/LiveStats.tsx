import { useEffect, useState } from "react";
import { motion } from "framer-motion";

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
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
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
    { label: "Chains supported for scans", value: String(SUPPORTED_CHAINS) },
  ];

  const note =
    stats === undefined
      ? "Loading live data"
      : stats === null
        ? "Live data is unavailable right now"
        : stats.counting_since
          ? `Live mempool counters since ${new Date(stats.counting_since * 1000).toLocaleDateString()}, when the monitor last restarted`
          : "Live mempool counters since the monitor last restarted";

  return (
    <div className="border-y border-white/5 bg-white/[0.02] py-8">
      <div className="max-w-6xl mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-6 text-center"
        >
          {items.map((item) => (
            <div key={item.label}>
              <div className="text-2xl md:text-3xl font-extrabold text-neon tracking-tight">
                {item.value}
              </div>
              <div className="text-xs text-gray-500 mt-1">{item.label}</div>
            </div>
          ))}
        </motion.div>
        <div className="flex items-center justify-center gap-1.5 mt-5">
          <div
            className={`w-1.5 h-1.5 rounded-full ${stats ? "bg-neon animate-pulse" : "bg-gray-600"}`}
          />
          <span className="text-xs text-gray-600">{note}</span>
        </div>
      </div>
    </div>
  );
}
