import { motion } from "framer-motion";

const competitors = [
  { name: "Fire Extension", status: "Acquired by Kerberus", color: "text-yellow-400", dot: "bg-yellow-400" },
  { name: "Pocket Universe", status: "Acquired by Kerberus", color: "text-yellow-400", dot: "bg-yellow-400" },
  { name: "Wallet Guard", status: "Pivoted", color: "text-yellow-400", dot: "bg-yellow-400" },
  { name: "ShieldBot", status: "Live & growing", color: "text-neon", dot: "bg-neon" },
];

export default function WhyNow() {
  return (
    <section className="py-24 bg-white/[0.02] border-y border-white/5">
      <div className="max-w-6xl mx-auto px-6">
        <motion.div
          initial={{ y: 30, opacity: 0 }}
          whileInView={{ y: 0, opacity: 1 }}
          viewport={{ once: true, amount: 0.3 }}
          transition={{ duration: 0.6 }}
          className="grid md:grid-cols-2 gap-16 items-center"
        >
          {/* Left — copy */}
          <div>
            <div className="inline-flex items-center gap-2 bg-neon/10 border border-neon/20 text-neon text-xs font-semibold px-4 py-1.5 rounded-full mb-6">
              Market Opportunity
            </div>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-6">
              The landscape is consolidating.{" "}
              <span className="text-neon">We're building independently.</span>
            </h2>
            <p className="text-gray-400 leading-relaxed mb-6">
              Fire and Pocket Universe — two of the most-used Web3 transaction security
              tools — were both acquired by Kerberus in 2025. As the space consolidates
              under one roof, ShieldBot remains independent: open, multi-chain, and built
              specifically for the BNB ecosystem with broader coverage than any single competitor.
            </p>
            <p className="text-gray-400 leading-relaxed">
              $2.7B lost to Web3 scams in 2024 alone. The problem isn't going away
              — and neither are we.
            </p>
          </div>

          {/* Right — competitor table */}
          <div className="bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
            <div className="grid grid-cols-2 text-xs text-gray-500 uppercase tracking-widest px-6 py-3 border-b border-white/10">
              <span>Product</span>
              <span>Status</span>
            </div>
            {competitors.map((c, i) => (
              <div
                key={c.name}
                className={`grid grid-cols-2 px-6 py-4 items-center ${
                  i < competitors.length - 1 ? "border-b border-white/5" : ""
                } ${c.name === "ShieldBot" ? "bg-neon/5" : ""}`}
              >
                <span className={`font-semibold text-sm ${c.name === "ShieldBot" ? "text-white" : "text-gray-400"}`}>
                  {c.name}
                </span>
                <div className="flex items-center gap-2">
                  <div className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
                  <span className={`text-sm font-medium ${c.color}`}>{c.status}</span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
