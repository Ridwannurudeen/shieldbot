import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

const faqs = [
  {
    q: "What is ShieldBot?",
    a: "ShieldBot is a real-time Web3 transaction security firewall. It intercepts every on-chain transaction before you sign it, runs an AI-powered risk analysis, and alerts you to threats like rug pulls, honeypots, phishing sites, and malicious smart contracts — across 7 blockchains.",
  },
  {
    q: "How does ShieldBot detect rug pulls and scams?",
    a: "ShieldBot combines multiple detection layers: it scans smart contract bytecode for known exploit patterns, checks token liquidity and ownership concentration, queries real-time mempool data for suspicious activity, cross-references phishing databases, and uses Claude AI to analyze contract logic. A risk score from 0–100 is returned before you confirm any transaction.",
  },
  {
    q: "Which blockchains does ShieldBot support?",
    a: "ShieldBot currently supports BNB Chain, opBNB, Ethereum, Base, Arbitrum, Polygon, and Optimism — with more chains being added. All 7 chains are monitored in real time through the browser extension and Telegram bot.",
  },
  {
    q: "Is ShieldBot free to use?",
    a: "Yes. The ShieldBot Chrome extension and Telegram bot are both free. There are no subscription fees to get real-time transaction warnings, phishing protection, and risk scoring.",
  },
  {
    q: "Does ShieldBot store my private keys or wallet data?",
    a: "No. ShieldBot never asks for, stores, or transmits your private keys or seed phrases. It only analyzes transaction data (contract addresses, token metadata, on-chain activity) that is already publicly visible on the blockchain.",
  },
  {
    q: "What happens when ShieldBot detects a threat?",
    a: "If a high-risk transaction is detected, ShieldBot displays an immediate warning before you sign — showing the risk score, threat type, and a plain-English explanation of what was found. For phishing sites, a red banner appears on the page. You always retain full control and can choose to proceed or cancel.",
  },
  {
    q: "How is ShieldBot different from other crypto security tools?",
    a: "Most security tools check transactions after the fact or only scan static token lists. ShieldBot works in real time — it intercepts transactions before signing, combines on-chain mempool data with AI contract analysis, and covers 7 chains in a single tool. It also includes a Telegram bot for users who don't use a browser extension.",
  },
  {
    q: "How do I install ShieldBot?",
    a: "Install the ShieldAI extension directly from the Chrome Web Store — it's free and requires no account. The Telegram bot is also available at t.me/shieldbot_bnb_bot — send any contract address or token to get an instant risk analysis.",
  },
  {
    q: "What is a wallet drainer and how does ShieldAI stop it?",
    a: "A wallet drainer exploits ERC-20 approval functions or EIP-712 permit signatures to transfer all tokens from your wallet in a single transaction. Standard phishing warnings can't detect these because they operate at the URL layer, not the transaction layer. ShieldAI intercepts at eth_sendTransaction and simulates the exact asset delta before you sign — if your full balance would leave your wallet, the transaction is blocked.",
  },
  {
    q: "What is ShieldScore?",
    a: "ShieldScore is a 0–100 risk rating assigned to every transaction before you sign. 0–39 is SAFE, 40–69 is CAUTION, 70–89 is HIGH RISK, and 90–100 triggers an automatic BLOCK. The score combines bytecode fingerprinting, deployer wallet history, Tenderly simulation results, and GoPlus threat intelligence.",
  },
  {
    q: "Does ShieldAI work with MetaMask?",
    a: "Yes. ShieldAI hooks into the browser's window.ethereum provider at page load, compatible with MetaMask, Trust Wallet, Binance Web3 Wallet, and any EIP-6963 wallet. The hook runs before any DApp code, so it intercepts all transaction requests regardless of which wallet is connected.",
  },
  {
    q: "Will ShieldAI slow down my transactions?",
    a: "The risk analysis adds approximately 1–3 seconds before the wallet signature dialog appears. SAFE transactions proceed normally after the check. Only HIGH RISK and BLOCK verdicts interrupt the signing flow, giving you the chance to review or cancel.",
  },
];

export default function FAQ() {
  const [open, setOpen] = useState<number | null>(null);

  return (
    <section id="faq" className="py-24 bg-navy">
      <div className="max-w-3xl mx-auto px-6">
        <motion.div
          initial={{ y: 30, opacity: 0 }}
          whileInView={{ y: 0, opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
          className="text-center mb-14"
        >
          <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-4">
            Frequently Asked Questions
          </h2>
          <p className="text-gray-400">
            Everything you need to know about Web3 transaction security.
          </p>
        </motion.div>

        <div className="space-y-3">
          {faqs.map((faq, i) => (
            <motion.div
              key={i}
              initial={{ y: 20, opacity: 0 }}
              whileInView={{ y: 0, opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: i * 0.05 }}
              className="border border-white/10 rounded-xl overflow-hidden bg-navy-light"
            >
              <button
                onClick={() => setOpen(open === i ? null : i)}
                className="w-full flex items-center justify-between px-6 py-5 text-left gap-4 hover:bg-white/5 transition-colors"
              >
                <span className="font-semibold text-white text-sm md:text-base">
                  {faq.q}
                </span>
                <span
                  className={`text-neon text-xl flex-shrink-0 transition-transform duration-300 ${
                    open === i ? "rotate-45" : ""
                  }`}
                >
                  +
                </span>
              </button>

              <AnimatePresence initial={false}>
                {open === i && (
                  <motion.div
                    key="content"
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.3, ease: "easeInOut" }}
                    className="overflow-hidden"
                  >
                    <p className="px-6 pb-5 text-gray-400 text-sm md:text-base leading-relaxed">
                      {faq.a}
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
