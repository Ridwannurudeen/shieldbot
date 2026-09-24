import { motion } from "framer-motion";

const chains = [
  {
    name: "BNB Chain",
    color: "#F3BA2F",
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-6 h-6">
        <circle cx="16" cy="16" r="16" fill="#F3BA2F"/>
        <path d="M12.116 14.404 16 10.52l3.886 3.886 2.26-2.26L16 6l-6.144 6.144 2.26 2.26zM6 16l2.26-2.26L10.52 16l-2.26 2.26L6 16zm6.116 1.596L16 21.48l3.886-3.886 2.26 2.259L16 26l-6.144-6.144-.002-.003 2.262-2.257zM21.48 16l2.26-2.26L26 16l-2.26 2.26L21.48 16zm-3.188-.002h.002V16L16 18.292 13.708 16v-.004L16 13.708l2.292 2.29z" fill="#fff"/>
      </svg>
    ),
  },
  {
    name: "Ethereum",
    color: "#627EEA",
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-6 h-6">
        <circle cx="16" cy="16" r="16" fill="#627EEA"/>
        <path d="M16.498 4v8.87l7.497 3.35L16.498 4z" fill="#fff" fillOpacity=".6"/>
        <path d="M16.498 4 9 16.22l7.498-3.35V4z" fill="#fff"/>
        <path d="M16.498 21.968v6.027L24 17.616l-7.502 4.352z" fill="#fff" fillOpacity=".6"/>
        <path d="M16.498 27.995v-6.028L9 17.616l7.498 10.379z" fill="#fff"/>
        <path d="m16.498 20.573 7.497-4.353-7.497-3.348v7.701z" fill="#fff" fillOpacity=".2"/>
        <path d="m9 16.22 7.498 4.353v-7.701L9 16.22z" fill="#fff" fillOpacity=".6"/>
      </svg>
    ),
  },
  {
    name: "Base",
    color: "#0052FF",
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-6 h-6">
        <circle cx="16" cy="16" r="16" fill="#0052FF"/>
        <path d="M16.004 26c5.52 0 9.996-4.477 9.996-10S21.524 6 16.004 6C10.756 6 6.44 10.02 6 15.155h13.243v1.69H6C6.44 21.98 10.756 26 16.004 26z" fill="#fff"/>
      </svg>
    ),
  },
  {
    name: "Arbitrum",
    color: "#213147",
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-6 h-6">
        <circle cx="16" cy="16" r="16" fill="#213147"/>
        <path d="M16 6L7 11v10l9 5 9-5V11L16 6zm0 2.3 7 3.9v7.6l-7 3.9-7-3.9v-7.6l7-3.9z" fill="#12AAFF"/>
        <path d="m13.5 19.5-1.5-2.6 4-6.9h3l-5.5 9.5zm5 0-1.5-2.6 2-3.4 1.5 2.6-2 3.4z" fill="#fff"/>
      </svg>
    ),
  },
  {
    name: "Polygon",
    color: "#8247E5",
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-6 h-6">
        <circle cx="16" cy="16" r="16" fill="#8247E5"/>
        <path d="M21.188 13.063a1.21 1.21 0 0 0-1.188 0l-2.729 1.604-1.854 1.042-2.729 1.604a1.21 1.21 0 0 1-1.188 0l-2.146-1.25a1.177 1.177 0 0 1-.594-1.02v-2.396c0-.417.22-.808.594-1.021l2.146-1.23a1.21 1.21 0 0 1 1.188 0l2.146 1.23c.374.213.594.604.594 1.021v1.604l1.854-1.083v-1.604a1.177 1.177 0 0 0-.594-1.021l-3.958-2.292a1.21 1.21 0 0 0-1.188 0L7.594 10.5A1.177 1.177 0 0 0 7 11.521v4.604c0 .417.22.808.594 1.021l4 2.312a1.21 1.21 0 0 0 1.188 0l2.729-1.583 1.854-1.063 2.729-1.583a1.21 1.21 0 0 1 1.188 0l2.146 1.23c.374.212.594.604.594 1.02v2.396c0 .417-.22.808-.594 1.021l-2.125 1.25a1.21 1.21 0 0 1-1.188 0l-2.146-1.25a1.177 1.177 0 0 1-.594-1.021v-1.583l-1.854 1.083v1.583c0 .417.22.808.594 1.021l4 2.313a1.21 1.21 0 0 0 1.188 0l4-2.313c.374-.213.594-.604.594-1.021v-4.625a1.177 1.177 0 0 0-.594-1.021l-4.062-2.354z" fill="#fff"/>
      </svg>
    ),
  },
  {
    name: "Optimism",
    color: "#FF0420",
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-6 h-6">
        <circle cx="16" cy="16" r="16" fill="#FF0420"/>
        <path d="M11.36 20.12c-1.04 0-1.88-.27-2.52-.8-.64-.55-.96-1.3-.96-2.25 0-.19.02-.43.07-.71.13-.73.34-1.6.63-2.59.82-2.74 2.42-4.1 4.8-4.1.69 0 1.3.14 1.83.43.54.29.95.71 1.24 1.26.29.54.43 1.18.43 1.9 0 .18-.02.41-.06.7-.17.92-.38 1.79-.64 2.6-.41 1.32-1.02 2.31-1.83 2.97-.8.66-1.77.99-2.99.99zm.19-1.89c.49 0 .91-.16 1.27-.47.36-.32.65-.82.86-1.5.28-.9.49-1.74.62-2.52.04-.2.05-.38.05-.55 0-.93-.42-1.39-1.27-1.39-.5 0-.93.16-1.29.48-.36.31-.64.81-.86 1.5-.25.83-.46 1.67-.62 2.52-.03.19-.05.37-.05.54 0 .93.43 1.39 1.29 1.39zm7.83 1.77c-.1 0-.18-.03-.23-.1-.05-.07-.06-.16-.03-.26l2.15-8.36c.04-.13.1-.23.2-.3.1-.08.2-.12.33-.12h3.01c.89 0 1.6.2 2.12.61.53.4.79.97.79 1.7 0 .21-.03.43-.08.67-.25 1.12-.75 1.96-1.5 2.51-.74.55-1.74.82-2.99.82h-1.55l-.64 2.47c-.04.13-.11.23-.21.3-.1.08-.21.12-.34.12h-1.03zm4.08-4.97c.4 0 .74-.11 1.02-.32.28-.22.47-.54.57-.96.03-.14.05-.27.05-.39 0-.27-.07-.48-.22-.62-.15-.15-.39-.22-.72-.22h-1.44l-.55 2.51h1.29z" fill="#fff"/>
      </svg>
    ),
  },
  {
    name: "opBNB",
    color: "#F3BA2F",
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-6 h-6">
        <circle cx="16" cy="16" r="16" fill="#1A1A2E"/>
        <path d="M12.116 14.404 16 10.52l3.886 3.886 2.26-2.26L16 6l-6.144 6.144 2.26 2.26zM6 16l2.26-2.26L10.52 16l-2.26 2.26L6 16zm6.116 1.596L16 21.48l3.886-3.886 2.26 2.259L16 26l-6.144-6.144-.002-.003 2.262-2.257zM21.48 16l2.26-2.26L26 16l-2.26 2.26L21.48 16zm-3.188-.002h.002V16L16 18.292 13.708 16v-.004L16 13.708l2.292 2.29z" fill="#F3BA2F"/>
      </svg>
    ),
  },
  {
    // Generic chain-link mark: no third-party logo.
    name: "Robinhood Chain",
    color: "#84CC16",
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-6 h-6">
        <circle cx="16" cy="16" r="16" fill="#1A2E05"/>
        <path d="M13.5 18.5 18.5 13.5M11.2 16.2l-1.4 1.4a3.2 3.2 0 0 0 4.5 4.5l1.4-1.4M20.8 15.8l1.4-1.4a3.2 3.2 0 0 0-4.5-4.5l-1.4 1.4" stroke="#84CC16" strokeWidth="2" strokeLinecap="round"/>
      </svg>
    ),
  },
];

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08 } },
};

const item = {
  hidden: { scale: 0.8, opacity: 0 },
  show: { scale: 1, opacity: 1, transition: { duration: 0.4 } },
};

export default function Chains() {
  return (
    <section id="chains" className="py-24">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 tracking-tight">
          Supported Chains
        </h2>
        <p className="text-gray-400 text-center max-w-md mx-auto mb-14">
          Contract scans on all 8 chains. Mempool monitoring runs on the 4
          chains with a public mempool: BNB Chain, opBNB, Ethereum and
          Polygon. Base, Arbitrum, Optimism and Robinhood Chain have none, so
          contract scans cover them, and Robinhood Chain also gets launch
          scanning.
        </p>

        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, amount: 0.5 }}
          className="flex flex-wrap justify-center gap-4"
        >
          {chains.map((c) => (
            <motion.div
              key={c.name}
              variants={item}
              className="flex items-center gap-3 bg-white/5 backdrop-blur-md border border-neon/15 rounded-xl px-5 py-3
                         font-semibold text-sm text-gray-200 hover:border-neon/40 transition-colors"
            >
              {c.logo}
              {c.name}
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
