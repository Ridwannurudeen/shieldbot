import type { ReactNode } from "react";
import { motion } from "framer-motion";

const steps: { num: string; title: string; desc: string; icon: ReactNode }[] = [
  {
    num: "01",
    title: "Intercept",
    desc: "Catches transactions and signature requests before your wallet signs them.",
    icon: (
      <>
        <path d="M12 20h9" />
        <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" />
      </>
    ),
  },
  {
    num: "02",
    title: "Check",
    desc: "Decodes the call, scans the contract (code, market data, on-chain reputation and, where the chain has one, a buy and sell simulation) and checks scam databases.",
    icon: (
      <>
        <circle cx="11" cy="11" r="7" />
        <path d="m20 20-3.5-3.5" />
      </>
    ),
  },
  {
    num: "03",
    title: "Report",
    desc: "Shows SAFE, CAUTION, HIGH RISK or BLOCK RECOMMENDED with the reasons, or UNKNOWN with the reason a check could not run. For a warning you choose to cancel or sign (Strict mode removes that choice for BLOCK RECOMMENDED, UNKNOWN and any result whose checks did not all run). A request it cannot check is refused, such as one that times out, one whose wallet chain is unknown or differs from the transaction's, or one sent through an older wallet method or from a frame or popup the page can script.",
    icon: (
      <>
        <path d="M12 3 4 6v6c0 5 3.4 8.6 8 9.9 4.6-1.3 8-4.9 8-9.9V6l-8-3Z" />
        <path d="M9.8 9.6a2.3 2.3 0 0 1 4.4.9c0 1.6-2.2 2-2.2 3.3" />
        <path d="M12 16.8h.01" />
      </>
    ),
  },
];

const checks = [
  {
    title: "Phishing warnings",
    desc: "Checks the sites you visit against the GoPlus phishing database and shows a red banner on a known phishing site, before you connect your wallet.",
  },
  {
    title: "Wallet Health",
    desc: "Scans your wallet's ERC-20 token approvals and explains which ones are risky. Revoking stays with you: the API includes an unsigned revoke transaction for each risky approval.",
  },
  {
    title: "Campaign graph",
    desc: "Links deployers and funders across chains to spot coordinated scam campaigns. A token tied to a known campaign gets a higher risk score.",
  },
  {
    title: "Robinhood Chain launches",
    desc: "Finds new token launches, simulates a buy and a sell on supported pool routes, and sends alerts in Telegram with /launchalerts.",
  },
  {
    title: "On-chain verdicts",
    desc: "A verdict registry and a freshness guard let other contracts refuse a token unless it has a recent, good verdict. Built and tested; deployment to Robinhood Chain is in progress.",
  },
];

const channels: { title: string; desc: string; link: string; href: string; icon: ReactNode }[] = [
  {
    title: "Chrome extension",
    desc: "Checks transactions before your browser wallet signs them.",
    link: "Add to Chrome",
    href: "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk",
    icon: (
      <>
        <rect x="3" y="4" width="18" height="16" rx="2" />
        <path d="M3 9h18" />
      </>
    ),
  },
  {
    title: "Telegram bot",
    desc: "Paste a contract address in chat to get a risk report.",
    link: "Open the bot",
    href: "https://t.me/shieldbot_bnb_bot",
    icon: <path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12Z" />,
  },
  {
    title: "REST API",
    desc: "Firewall checks for your dApp or bot.",
    link: "API docs",
    href: "https://api.shieldbotsecurity.online/docs",
    icon: <path d="m8 7-5 5 5 5M16 7l5 5-5 5" />,
  },
  {
    title: "MCP server and SDKs",
    desc: "For AI agents. The TypeScript and Python SDKs are source in the GitHub repo, not yet on npm or PyPI.",
    link: "Agent security",
    href: "#agent-security",
    icon: (
      <>
        <rect x="7" y="7" width="10" height="10" rx="1" />
        <path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4" />
      </>
    ),
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

function Icon({ children }: { children: ReactNode }) {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="py-20">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 tracking-tight">
          How It Works
        </h2>
        <p className="text-gray-400 text-center max-w-md mx-auto mb-12">
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
              className="bg-white/5 border border-neon/15 rounded-2xl p-7"
            >
              <div className="flex items-center justify-between mb-4 text-neon">
                <Icon>{s.icon}</Icon>
                <span className="text-xs font-mono text-neon/70">{s.num}</span>
              </div>
              <h3 className="text-xl font-bold mb-2">{s.title}</h3>
              <p className="text-gray-400 text-sm leading-relaxed">{s.desc}</p>
            </motion.div>
          ))}
        </motion.div>

        <div className="grid lg:grid-cols-2 gap-6 mt-6">
          <div className="bg-white/5 border border-white/10 rounded-2xl p-7">
            <h3 className="text-lg font-bold mb-4">It also checks</h3>
            <ul className="space-y-4">
              {checks.map((c) => (
                <li key={c.title} className="text-sm leading-relaxed">
                  <span className="font-semibold text-gray-100">{c.title}.</span>{" "}
                  <span className="text-gray-400">{c.desc}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="bg-white/5 border border-white/10 rounded-2xl p-7">
            <h3 className="text-lg font-bold mb-4">Where it runs</h3>
            <ul className="space-y-5">
              {channels.map((ch) => (
                <li key={ch.title} className="flex gap-4">
                  <span className="text-neon mt-0.5 flex-shrink-0">
                    <Icon>{ch.icon}</Icon>
                  </span>
                  <div className="text-sm leading-relaxed">
                    <div className="font-semibold text-gray-100">{ch.title}</div>
                    <p className="text-gray-400">{ch.desc}</p>
                    <a
                      href={ch.href}
                      {...(ch.href.startsWith("#")
                        ? {}
                        : { target: "_blank", rel: "noopener noreferrer" })}
                      className="inline-flex items-center min-h-[44px] text-neon underline underline-offset-4 hover:text-white"
                    >
                      {ch.link}
                    </a>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}
