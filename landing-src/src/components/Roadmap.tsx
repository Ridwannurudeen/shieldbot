import { motion } from "framer-motion";

const phases = [
  {
    phase: "Phase 1",
    title: "Foundation",
    status: "done",
    items: [
      "Chrome extension (phishing blocker, transaction firewall)",
      "Telegram bot (12 commands)",
      "REST API + TypeScript SDK",
      "7-chain mempool monitoring",
      "Live threat dashboard",
    ],
  },
  {
    phase: "Phase 2",
    title: "Detection Depth",
    status: "done",
    items: [
      "Bytecode fingerprinting for unverified contracts",
      "Human-readable transaction decoder",
      "Wallet health scanner + approval risk scoring",
      "Pre-sign asset delta simulation",
      "EIP-712 permit & signature request analysis",
    ],
  },
  {
    phase: "Phase 3",
    title: "Growth & Moat",
    status: "done",
    items: [
      "Deployer cluster risk scoring",
      "Serial scammer pattern detection",
      "Post-deployment contract monitoring",
      "Telegram threat alerts",
      "Watched deployer registry",
    ],
  },
  {
    phase: "Phase 3.5",
    title: "Agent Security (V3)",
    status: "done",
    items: [
      "Agent Transaction Firewall (policy engine, daily limits)",
      "MCP Server (9 tools, 3 resources, SSE transport)",
      "Portfolio Guardian (5-component health scoring)",
      "TypeScript & Python SDK (source; not yet published)",
      "Reputation Oracle (composite trust scores)",
      "Prompt Injection Scanner (4-layer detection)",
      "Threat Intelligence Graph (BFS + clustering)",
    ],
  },
  {
    phase: "Phase 4",
    title: "Robinhood Chain",
    status: "active",
    items: [
      "Robinhood Chain scanning with honest unknowns (live)",
      "Launch discovery and Telegram launch alerts (live)",
      "On-chain verdict registry and freshness guard (built and tested; deploying)",
      "Guarded USDG transfer that needs a fresh, good verdict (built and tested; deploying)",
      "Released browser extension coverage for Robinhood Chain",
    ],
  },
  {
    phase: "Phase 5",
    title: "Ecosystem & Scale",
    status: "upcoming",
    items: [
      "Publish the TypeScript and Python SDKs",
      "Firefox port (proposed)",
      "B2B DEX integrations",
      "Threat feed subscriptions",
    ],
  },
];

const statusStyle: Record<string, { label: string; labelColor: string; dot: string; border: string }> = {
  done: {
    label: "Complete",
    labelColor: "text-neon",
    dot: "bg-neon",
    border: "border-neon/30",
  },
  active: {
    label: "In Progress",
    labelColor: "text-blue-400",
    dot: "bg-blue-400",
    border: "border-blue-400/30",
  },
  upcoming: {
    label: "Upcoming",
    labelColor: "text-gray-500",
    dot: "bg-gray-600",
    border: "border-white/10",
  },
};

export default function Roadmap() {
  return (
    <section className="py-24 bg-white/[0.02] border-y border-white/5">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 tracking-tight">
          Roadmap
        </h2>
        <p className="text-gray-400 text-center max-w-md mx-auto mb-14">
          Where we are and where we're going.
        </p>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {phases.map((p, i) => {
            const s = statusStyle[p.status];
            return (
              <motion.div
                key={p.phase}
                initial={{ y: 30, opacity: 0 }}
                whileInView={{ y: 0, opacity: 1 }}
                viewport={{ once: true, amount: 0.2 }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                className={`bg-white/5 border ${s.border} rounded-2xl p-7`}
              >
                <div className="flex items-center justify-between mb-4">
                  <span className="text-xs font-mono text-gray-500">{p.phase}</span>
                  <div className="flex items-center gap-1.5">
                    <div className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
                    <span className={`text-xs font-semibold ${s.labelColor}`}>{s.label}</span>
                  </div>
                </div>
                <h3 className="text-lg font-bold mb-4">{p.title}</h3>
                <ul className="space-y-2">
                  {p.items.map((item) => (
                    <li key={item} className="flex items-start gap-2 text-sm text-gray-400">
                      <span className={`mt-1.5 w-1 h-1 rounded-full flex-shrink-0 ${s.dot}`} />
                      {item}
                    </li>
                  ))}
                </ul>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
