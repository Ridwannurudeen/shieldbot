import { motion } from "framer-motion";

// Census window 2026-09-14T02:18:58Z to 2026-09-22T17:19:08Z; figures from docs/SUBMISSION.md.
const figures = [
  { value: "68,666", label: "new tokens first seen in a liquidity pool" },
  { value: "~8,000", label: "new tokens a day" },
  {
    value: "28.76%",
    label: "of mature tokens met a minimal liquidity or activity bar",
  },
  {
    value: "49%",
    label: "could not be resolved either way and are reported as unknown",
  },
];

export default function RobinhoodCensus() {
  return (
    <section id="robinhood-chain" className="py-24">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 tracking-tight">
          Why Robinhood Chain Needs Careful Checks
        </h2>
        <p className="text-gray-400 text-center max-w-2xl mx-auto mb-14">
          We watched Robinhood Chain for about 8.6 days. New tokens arrive fast,
          and most of them never show real liquidity or trading.
        </p>

        <motion.div
          initial={{ y: 30, opacity: 0 }}
          whileInView={{ y: 0, opacity: 1 }}
          viewport={{ once: true, amount: 0.3 }}
          transition={{ duration: 0.5 }}
          className="grid grid-cols-2 lg:grid-cols-4 gap-5"
        >
          {figures.map((f) => (
            <div
              key={f.label}
              className="bg-white/5 backdrop-blur-md border border-neon/15 rounded-2xl p-6 text-center"
            >
              <div className="text-3xl font-extrabold text-neon tracking-tight">
                {f.value}
              </div>
              <div className="text-xs text-gray-400 mt-2 leading-relaxed">
                {f.label}
              </div>
            </div>
          ))}
        </motion.div>

        <p className="text-xs text-gray-500 text-center max-w-3xl mx-auto mt-8 leading-relaxed">
          Observed from 14 to 22 September 2026. These figures describe the
          chain, not ShieldBot scans. A token is counted when it first appears
          in a liquidity pool, not when it is deployed, and missing evidence is
          reported as unknown, never as zero.{" "}
          <a
            href="https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/census-4663.md"
            target="_blank"
            rel="noopener noreferrer"
            className="text-gray-400 underline hover:text-neon"
          >
            Method and limits
          </a>
        </p>
      </div>
    </section>
  );
}
