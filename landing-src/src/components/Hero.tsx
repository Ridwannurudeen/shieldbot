import { motion } from "framer-motion";
import ShieldVisual from "./ShieldVisual";

export default function Hero() {
  return (
    <section className="relative pt-32 pb-20 md:pt-40 md:pb-28 overflow-hidden">
      {/* Radial glow behind hero */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[800px] bg-[radial-gradient(circle,rgba(0,255,136,0.06)_0%,transparent_70%)] pointer-events-none" />

      <div className="max-w-6xl mx-auto px-6 grid md:grid-cols-2 gap-12 items-center">
        {/* Left — Copy */}
        <motion.div
          initial={{ x: -60, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ duration: 0.7, ease: "easeOut" }}
        >
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-extrabold tracking-tight leading-[1.1] mb-6">
            YOUR ON-CHAIN{" "}
            <span className="text-neon">FIREWALL</span>
          </h1>

          <p className="text-gray-400 text-lg md:text-xl leading-relaxed max-w-lg mb-8">
            ShieldBot intercepts, analyzes, and scores every transaction before
            you sign. AI-powered protection across 7 chains — so you never
            approve a drain again.
          </p>

          <div className="flex flex-wrap items-center gap-4">
            <a
              href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 bg-neon text-navy font-bold text-base px-8 py-3.5 rounded-lg hover:shadow-neon transition-all hover:-translate-y-0.5"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <circle cx="12" cy="12" r="4"/>
                <path d="M12 2a10 10 0 0 1 8.66 5H12a5 5 0 0 0-4.58 3H3.34A10 10 0 0 1 12 2z" opacity=".6"/>
                <path d="M12 22A10 10 0 0 1 3.34 17H7.42A5 5 0 0 0 12 19.92V22z" opacity=".6"/>
                <path d="M22 12a10 10 0 0 1-5.34 8.9l-2.08-3.6A5 5 0 0 0 17 12h5z" opacity=".6"/>
              </svg>
              Add to Chrome — Free
            </a>
            <a
              href="https://t.me/shieldbot_bnb_bot"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 border border-white/20 text-gray-300 font-semibold text-base px-6 py-3.5 rounded-lg hover:border-white/40 hover:text-white transition-all"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.562 8.248-1.97 9.289c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12L7.08 14.784l-2.968-.924c-.645-.204-.657-.645.136-.953l11.57-4.461c.537-.194 1.006.131.744.802z"/>
              </svg>
              Try Telegram Bot
            </a>
          </div>

          {/* Trust disclaimer */}
          <div className="flex items-center gap-2 mt-5">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10B981" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <span className="text-xs text-gray-500">
              ShieldBot <span className="text-gray-300 font-medium">never</span> asks for your private keys or seed phrase.
            </span>
          </div>

          {/* Chrome extension badge */}
          <div className="inline-flex items-center gap-2 bg-white/5 border border-white/10 rounded-lg px-4 py-2 mt-3">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="#9CA3AF">
              <circle cx="12" cy="12" r="4"/>
              <path d="M12 2a10 10 0 0 1 8.66 5H12a5 5 0 0 0-4.58 3H3.34A10 10 0 0 1 12 2z" opacity=".5"/>
              <path d="M12 22A10 10 0 0 1 3.34 17H7.42A5 5 0 0 0 12 19.92V22z" opacity=".5"/>
              <path d="M22 12a10 10 0 0 1-5.34 8.9l-2.08-3.6A5 5 0 0 0 17 12h5z" opacity=".5"/>
            </svg>
            <span className="text-xs text-gray-500">Chrome Extension — <span className="text-neon font-medium">Live on Web Store</span></span>
          </div>
        </motion.div>

        {/* Right — Shield visual */}
        <div className="hidden md:block">
          <ShieldVisual />
        </div>
      </div>
    </section>
  );
}
