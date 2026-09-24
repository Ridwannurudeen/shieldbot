import { motion } from "framer-motion";

const examples = [
  {
    verdict: "BLOCK RECOMMENDED",
    verdictColor: "text-red-400",
    verdictBg: "bg-red-500/10 border-red-500/30",
    score: 6,
    scoreColor: "text-red-400",
    threat: "Honeypot Contract",
    contract: "0x4f3a...c91b",
    explanation: "This contract is a Honeypot. You can buy, but you cannot sell — the transfer function is overridden to revert all outgoing transactions.",
    detail: "Structural analysis detected a hidden ownership modifier that blacklists all addresses post-purchase.",
  },
  {
    verdict: "HIGH RISK",
    verdictColor: "text-orange-400",
    verdictBg: "bg-orange-500/10 border-orange-500/30",
    score: 39,
    scoreColor: "text-orange-400",
    threat: "Unlimited Approval",
    contract: "0xa81d...f42e",
    explanation: "You are about to grant unlimited spending rights to an unverified contract. It can drain your entire token balance at any time, now or in the future.",
    detail: "This contract was deployed 3 hours ago and shares a deployer with 2 previously rugged tokens.",
  },
];

export default function AIThreatCard() {
  return (
    <section className="py-24 bg-white/[0.02] border-y border-white/5">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 tracking-tight">
          Every Warning Explained in Plain English
        </h2>
        <p className="text-gray-400 text-center max-w-lg mx-auto mb-14">
          No raw bytecode. ShieldBot tells you what it found and what the
          transaction would do, before you sign. The two cards below are
          illustrations of the extension's warnings.
        </p>

        <div className="grid md:grid-cols-2 gap-6 max-w-4xl mx-auto">
          {examples.map((ex, i) => (
            <motion.div
              key={ex.threat}
              initial={{ y: 30, opacity: 0 }}
              whileInView={{ y: 0, opacity: 1 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.5, delay: i * 0.15 }}
              className={`bg-[#0A0F1E] border rounded-2xl overflow-hidden ${ex.verdictBg}`}
            >
              {/* Header */}
              <div className="flex items-center justify-between px-5 py-3 border-b border-white/5">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-red-500" />
                  <div className="w-2 h-2 rounded-full bg-yellow-500" />
                  <div className="w-2 h-2 rounded-full bg-neon" />
                </div>
                <span className="text-xs text-gray-600 font-mono">ShieldBot — Transaction Firewall</span>
              </div>

              {/* Card body */}
              <div className="p-5">
                {/* Verdict + Score */}
                <div className="flex items-center justify-between mb-4">
                  <div className={`inline-flex items-center gap-2 text-sm font-bold px-3 py-1.5 rounded-lg border ${ex.verdictBg} ${ex.verdictColor}`}>
                    {ex.verdict.startsWith("BLOCK") ? "🚫" : "⚠️"} {ex.verdict}
                  </div>
                  <div className="text-right">
                    <div className={`text-2xl font-extrabold ${ex.scoreColor}`}>{ex.score}</div>
                    <div className="text-xs text-gray-600">Safety / 100</div>
                  </div>
                </div>

                {/* Threat type */}
                <div className="mb-3">
                  <div className="text-xs text-gray-500 mb-1 uppercase tracking-widest">Threat Detected</div>
                  <div className="text-white font-bold">{ex.threat}</div>
                  <div className="text-xs text-gray-600 font-mono mt-0.5">{ex.contract}</div>
                </div>

                {/* AI explanation */}
                <div className="bg-white/5 rounded-xl p-4 mb-3">
                  <div className="flex items-center gap-1.5 mb-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-neon animate-pulse" />
                    <span className="text-xs text-neon font-semibold">AI Analysis</span>
                  </div>
                  <p className="text-sm text-gray-300 leading-relaxed">"{ex.explanation}"</p>
                </div>

                {/* Technical detail */}
                <p className="text-xs text-gray-600 leading-relaxed">{ex.detail}</p>

                {/* Action buttons */}
                <div className="flex gap-3 mt-4">
                  <button className="flex-1 py-2 rounded-lg bg-red-500/20 border border-red-500/30 text-red-400 text-sm font-bold">
                    Block Transaction
                  </button>
                  <button className="px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-gray-400 text-sm">
                    Proceed Anyway
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
