import { motion } from "framer-motion";

const channels = [
  {
    icon: "🌐",
    title: "Chrome Extension",
    desc: "Intercepts transactions directly in your browser wallet",
    tag: "In Review",
    tagColor: "bg-yellow-500/15 text-yellow-400",
  },
  {
    icon: "💬",
    title: "Telegram Bot",
    desc: "Scan any contract by pasting the address in chat",
    tag: "Live",
    tagColor: "bg-neon/15 text-neon",
  },
  {
    icon: "🔀",
    title: "RPC Proxy",
    desc: "Route your wallet's RPC through ShieldBot for passive protection",
    tag: "Live",
    tagColor: "bg-neon/15 text-neon",
  },
  {
    icon: "🔌",
    title: "REST API",
    desc: "Integrate firewall checks into your dApp or bot",
    tag: "Live",
    tagColor: "bg-neon/15 text-neon",
  },
  {
    icon: "📦",
    title: "Python SDK",
    desc: "Programmatic access with async support",
    tag: "Coming Soon",
    tagColor: "bg-blue-500/15 text-blue-400",
  },
];

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.1 } },
};

const item = {
  hidden: { y: 20, opacity: 0 },
  show: { y: 0, opacity: 1, transition: { duration: 0.4 } },
};

export default function Channels() {
  return (
    <section id="channels" className="py-24">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 tracking-tight">
          Use ShieldBot Anywhere
        </h2>
        <p className="text-gray-400 text-center max-w-md mx-auto mb-14">
          Multiple integration points for every workflow.
        </p>

        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, amount: 0.3 }}
          className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5 max-w-4xl mx-auto"
        >
          {channels.map((ch) => (
            <motion.div
              key={ch.title}
              variants={item}
              className="bg-white/5 backdrop-blur-md border border-neon/15 rounded-2xl p-6 text-center"
            >
              <div className="text-3xl mb-3">{ch.icon}</div>
              <h4 className="font-bold mb-1">{ch.title}</h4>
              <p className="text-gray-400 text-xs mb-3">{ch.desc}</p>
              <span
                className={`inline-block text-xs font-semibold px-3 py-1 rounded-md ${ch.tagColor}`}
              >
                {ch.tag}
              </span>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
