import { motion } from "framer-motion";

const steps = [
  {
    num: "01",
    title: "Detect",
    desc: "Intercepts pending transactions and signature requests before your wallet signs.",
    icon: "🔍",
  },
  {
    num: "02",
    title: "Analyze",
    desc: "Decodes calldata, scans contracts, checks scam databases, and simulates outcomes.",
    icon: "⚡",
  },
  {
    num: "03",
    title: "Protect",
    desc: "Returns a verdict (SAFE, CAUTION, HIGH RISK or BLOCK RECOMMENDED, or UNKNOWN when a check could not run) with a plain-English explanation.",
    icon: "🛡️",
  },
];

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.12 } },
};

const item = {
  hidden: { y: 30, opacity: 0 },
  show: { y: 0, opacity: 1, transition: { duration: 0.5 } },
};

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="py-24">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 tracking-tight">
          How It Works
        </h2>
        <p className="text-gray-400 text-center max-w-md mx-auto mb-14">
          Three steps between you and a scam. A check usually takes a few
          seconds.
        </p>

        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, amount: 0.3 }}
          className="grid md:grid-cols-3 gap-6"
        >
          {steps.map((s) => (
            <motion.div
              key={s.num}
              variants={item}
              className="relative bg-white/5 backdrop-blur-md border border-neon/15 rounded-2xl p-8 group hover:border-neon/40 transition-colors"
            >
              <span className="text-xs font-mono text-neon/60 mb-4 block">
                {s.num}
              </span>
              <div className="text-3xl mb-4">{s.icon}</div>
              <h3 className="text-xl font-bold mb-2">{s.title}</h3>
              <p className="text-gray-400 text-sm leading-relaxed">{s.desc}</p>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
