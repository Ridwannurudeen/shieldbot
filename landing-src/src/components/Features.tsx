import { motion } from "framer-motion";

const features = [
  {
    title: "Transaction Firewall",
    badge: null,
    desc: "Intercepts eth_sendTransaction and signature requests before your wallet signs. Blocks honeypots, drains, and malicious approvals in real time.",
    icon: "📡",
  },
  {
    title: "Auto-Block High-Risk Transactions",
    badge: "CORE FEATURE",
    desc: "When ShieldScore drops below the safety threshold, ShieldBot automatically blocks the transaction — no confirmation needed. Your assets are protected even if you miss the warning.",
    icon: "🚫",
  },
  {
    title: "Zero-Friction Silent Mode",
    badge: null,
    desc: "ShieldBot stays completely silent on verified safe dApps — Uniswap, Aave, OpenSea. No popup fatigue, no interruptions. You only hear from us when something is actually wrong.",
    icon: "🔕",
  },
  {
    title: "Smart Contract Audit",
    badge: null,
    desc: "Composite ShieldScore from 6 analyzer categories — structural, behavioral, market, honeypot, intent, and AI reasoning — weighted into a 0–100 safety score. Higher is safer: 90–100 is SAFE, 0–39 triggers BLOCK.",
    icon: "📋",
  },
  {
    title: "Phishing Blocker",
    badge: null,
    desc: "Checks every URL you visit against the GoPlus Phishing Detection API. Displays a red warning banner before you connect your wallet to a known phishing site.",
    icon: "🎣",
  },
  {
    title: "Wallet Shield",
    badge: null,
    desc: "Scans your wallet's active token approvals, flags risky ones with plain-English explanations, and generates one-click revoke transactions.",
    icon: "🛡️",
  },
  {
    title: "Campaign Graph Radar",
    badge: null,
    desc: "Traces deployer-funder links across chains to uncover coordinated scam campaigns and serial rug pullers — blocks entire networks, not just individual tokens.",
    icon: "🕸️",
  },
  {
    title: "On-Chain Threat Intel",
    badge: "BNB GREENFIELD",
    desc: "Forensic reports for every high-risk transaction are stored immutably on BNB Greenfield — tamper-proof, permanently verifiable on-chain evidence that exists long after the scam is gone.",
    icon: "🔬",
  },
];

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.1 } },
};

const item = {
  hidden: { y: 30, opacity: 0 },
  show: { y: 0, opacity: 1, transition: { duration: 0.5 } },
};

const badgeStyle: Record<string, string> = {
  "CORE FEATURE": "bg-neon/10 border border-neon/30 text-neon",
  "BNB GREENFIELD": "bg-yellow-500/10 border border-yellow-500/30 text-yellow-400",
};

export default function Features() {
  return (
    <section id="features" className="py-24">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 tracking-tight">
          Features
        </h2>
        <p className="text-gray-400 text-center max-w-md mx-auto mb-14">
          Everything you need to transact safely on-chain.
        </p>

        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, amount: 0.1 }}
          className="grid md:grid-cols-2 lg:grid-cols-3 gap-6"
        >
          {features.map((f) => (
            <motion.div
              key={f.title}
              variants={item}
              className="bg-white/5 backdrop-blur-md border border-neon/15 rounded-2xl p-7 group
                         hover:border-neon/40 hover:-translate-y-1 hover:shadow-neon transition-all duration-300"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="text-3xl">{f.icon}</div>
                {f.badge && (
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md tracking-widest ${badgeStyle[f.badge]}`}>
                    {f.badge}
                  </span>
                )}
              </div>
              <h3 className="text-lg font-bold mb-2">{f.title}</h3>
              <p className="text-gray-400 text-sm leading-relaxed">{f.desc}</p>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
