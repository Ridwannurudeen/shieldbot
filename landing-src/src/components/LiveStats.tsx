import { useEffect, useState } from "react";
import { motion } from "framer-motion";

interface Stats {
  total_pending_seen: number;
  sandwiches_detected: number;
  suspicious_approvals: number;
  monitored_chains: number[];
}

function fmt(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M+";
  if (n >= 1_000) return (n / 1_000).toFixed(0) + "K+";
  return n.toLocaleString();
}

const FALLBACK = {
  total_pending_seen: 21471914,
  sandwiches_detected: 1328,
  suspicious_approvals: 307074,
  monitored_chains: [1, 8453, 137, 10, 204, 42161, 56],
};

export default function LiveStats() {
  const [stats, setStats] = useState<Stats>(FALLBACK);

  useEffect(() => {
    fetch("https://api.shieldbotsecurity.online/api/mempool/stats")
      .then((r) => r.json())
      .then((d) => setStats(d))
      .catch(() => {});
  }, []);

  const items = [
    { label: "Transactions Monitored since Feb 2026", value: fmt(stats.total_pending_seen) },
    { label: "Sandwich Attacks Caught", value: fmt(stats.sandwiches_detected) },
    { label: "Suspicious Approvals Flagged", value: fmt(stats.suspicious_approvals) },
    { label: "Global Threat Intelligence Feeds", value: "7" },
  ];

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
          <div className="w-1.5 h-1.5 rounded-full bg-neon animate-pulse" />
          <span className="text-xs text-gray-600">Live data</span>
        </div>
      </div>
    </div>
  );
}
