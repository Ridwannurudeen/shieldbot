import { motion } from "framer-motion";

export default function Hero() {
  return (
    <section className="relative pt-28 pb-16 md:pt-32 md:pb-20 overflow-hidden">
      {/* Radial glow behind hero */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[800px] bg-[radial-gradient(circle,rgba(0,255,136,0.06)_0%,transparent_70%)] pointer-events-none" />

      <div className="relative max-w-6xl mx-auto px-4 sm:px-6 grid md:grid-cols-[minmax(0,1fr)_minmax(0,490px)] gap-10 md:gap-12 items-start">
        {/* Left — Copy */}
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.6, ease: "easeOut" }}
          className="md:pt-12"
        >
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-extrabold tracking-tight leading-[1.1] mb-6">
            Know before you sign.{" "}
            <span className="text-neon">And know when we don't.</span>
          </h1>

          <p className="text-gray-300 text-lg md:text-xl leading-relaxed max-w-xl mb-8">
            ShieldBot is the security layer that says what it checked. Every
            verdict carries its coverage, and a check that cannot run reads
            Unknown, never Safe. Strict mode blocks anything Unknown; Balanced
            mode warns and leaves the choice to you.
          </p>

          <div className="flex flex-wrap items-center gap-4">
            <a
              href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 bg-neon text-navy font-bold text-base px-6 sm:px-8 py-3.5 rounded-lg hover:shadow-neon transition-all hover:-translate-y-0.5"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <circle cx="12" cy="12" r="4"/>
                <path d="M12 2a10 10 0 0 1 8.66 5H12a5 5 0 0 0-4.58 3H3.34A10 10 0 0 1 12 2z" opacity=".6"/>
                <path d="M12 22A10 10 0 0 1 3.34 17H7.42A5 5 0 0 0 12 19.92V22z" opacity=".6"/>
                <path d="M22 12a10 10 0 0 1-5.34 8.9l-2.08-3.6A5 5 0 0 0 17 12h5z" opacity=".6"/>
              </svg>
              Add to Chrome
            </a>
            <a
              href="https://api.shieldbotsecurity.online/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 border border-white/20 text-gray-200 font-semibold text-base px-6 py-3.5 rounded-lg hover:border-white/40 hover:text-white transition-all"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M8 6l-6 6 6 6M16 6l6 6-6 6"/>
              </svg>
              API docs
            </a>
          </div>

          <p className="text-sm text-gray-400 mt-5">
            Free, no account. ShieldBot{" "}
            <span className="text-gray-200 font-medium">never</span> asks for
            your private keys or seed phrase.
          </p>
        </motion.div>

        {/* Right — the real extension overlay (landing-src/scripts/capture-hero-overlay.py) */}
        <figure>
          <picture>
            <source
              media="(max-width: 767px)"
              srcSet="/hero-overlay-mobile.webp"
              width={390}
              height={496}
            />
            <img
              src="/hero-overlay.webp"
              width={490}
              height={954}
              alt="The ShieldBot extension's warning dialog for a request that approves unlimited USDC spending on Ethereum. The verdict badge reads BLOCK RECOMMENDED — Safety: 0/100. The danger signals include Spender flagged by GoPlus: stealing_attack (SlowMist,BlockSec)."
              className="w-full h-auto rounded-2xl ring-1 ring-white/10 shadow-[0_25px_50px_rgba(0,0,0,0.5)] max-md:rounded-b-none max-md:[mask-image:linear-gradient(to_bottom,#000_94%,transparent)]"
            />
          </picture>
          <figcaption className="text-sm text-gray-400 mt-4 leading-relaxed">
            The extension's 3.1.0 overlay (listed on the Chrome Web Store as
            ShieldAI Transaction Firewall; the 3.1.0 update is pending), fed the
            API's reply for this request on 26 September 2026. It recommends
            blocking an unlimited USDC approval to the wallet behind the 2021
            BadgerDAO front-end attack, which GoPlus flags for stealing attacks.
          </figcaption>
        </figure>
      </div>
    </section>
  );
}
