import { motion } from "framer-motion";

const features = [
  {
    title: "Transaction Firewall",
    badge: null,
    desc: "Catches transactions and signature requests before your wallet signs them, then shows the verdict and the reasons. For a warning you choose to cancel or sign; a request that times out or whose wallet chain is unknown is refused.",
    icon: "📡",
  },
  {
    title: "Honest About Unknowns",
    badge: "CORE FEATURE",
    desc: "If a data source fails, the verdict says Unknown instead of Safe. An incomplete check is never shown as a clean result, and a confirmed scam match always counts against the token.",
    icon: "❔",
  },
  {
    title: "Contract Risk Score",
    badge: null,
    desc: "Combines four weighted checks (contract code, market data, on-chain reputation and a buy and sell simulation) into one score. The extension shows it as a safety score out of 100, where higher is safer.",
    icon: "📋",
  },
  {
    title: "Robinhood Chain Launch Scanner",
    badge: "ROBINHOOD CHAIN",
    desc: "Finds new token launches on Robinhood Chain, simulates a buy and a sell on supported pool routes, and sends alerts in Telegram with /launchalerts.",
    icon: "🚀",
  },
  {
    title: "Phishing Warnings",
    badge: null,
    desc: "Checks the sites you visit against the GoPlus phishing database and shows a red warning banner on a known phishing site, before you connect your wallet.",
    icon: "🎣",
  },
  {
    title: "Wallet Shield",
    badge: null,
    desc: "Scans your wallet's token approvals, explains which ones are risky, and prepares revoke transactions for you to review and sign.",
    icon: "🛡️",
  },
  {
    title: "Campaign Graph Radar",
    badge: null,
    desc: "Links deployers and funders across chains to spot coordinated scam campaigns. A token tied to a known campaign gets a higher risk score.",
    icon: "🕸️",
  },
  {
    title: "On-Chain Verdicts",
    badge: "ROBINHOOD CHAIN",
    desc: "A verdict registry and a freshness guard let other contracts refuse a token unless it has a recent, good verdict. Built and tested; deployment to Robinhood Chain is in progress.",
    icon: "🔗",
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
  "ROBINHOOD CHAIN": "bg-lime-500/10 border border-lime-500/30 text-lime-400",
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
