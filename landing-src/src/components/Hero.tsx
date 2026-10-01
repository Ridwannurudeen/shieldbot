import { motion } from "framer-motion";
import Button from "./Button";
import Icon from "./Icon";
import VerdictDemo from "./VerdictDemo";

export default function Hero() {
  return (
    <section className="relative pt-24 md:pt-28 lg:pt-32 pb-14 md:pb-[72px] lg:pb-24 border-b border-line">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 grid gap-12 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] lg:gap-16 items-start">
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.6, ease: "easeOut" }}
        >
          <p className="text-xs font-bold uppercase tracking-[0.12em] text-emerald">
            Chrome extension, Telegram bot and API for 8 EVM chains
          </p>
          <h1 className="mt-4 text-display-sm md:text-display text-ink">
            Know before you sign.
            <br />
            <span className="text-emerald">And know when we don't.</span>
          </h1>
          <p className="mt-6 max-w-[560px] text-lg md:text-xl leading-[1.55] text-body">
            ShieldBot checks a transaction before your wallet signs it and tells
            you what it found, in plain English. When a check cannot run, it
            says Unknown instead of Safe.
          </p>
          <div className="mt-8 flex flex-col sm:flex-row gap-3">
            <Button href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk">
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="currentColor"
                aria-hidden="true"
              >
                <circle cx="12" cy="12" r="4" />
                <path
                  d="M12 2a10 10 0 0 1 8.66 5H12a5 5 0 0 0-4.58 3H3.34A10 10 0 0 1 12 2z"
                  opacity=".6"
                />
                <path
                  d="M12 22A10 10 0 0 1 3.34 17H7.42A5 5 0 0 0 12 19.92V22z"
                  opacity=".6"
                />
                <path
                  d="M22 12a10 10 0 0 1-5.34 8.9l-2.08-3.6A5 5 0 0 0 17 12h5z"
                  opacity=".6"
                />
              </svg>
              Add to Chrome
            </Button>
            <Button variant="secondary" href="https://t.me/shieldbot_bnb_bot">
              <Icon name="chat" size={16} />
              Open the Telegram bot
            </Button>
          </div>
          <p className="mt-5 text-sm text-muted">
            Free, no account. ShieldBot{" "}
            <span className="font-semibold text-body">never</span> asks for your
            private keys or seed phrase.
          </p>
        </motion.div>
        <VerdictDemo />
      </div>
    </section>
  );
}
