import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import Icon from "./Icon";
import SectionHeader from "./SectionHeader";

const faqs = [
  {
    q: "What is ShieldBot?",
    a: "ShieldBot is a transaction security tool for EVM chains. Its browser extension, listed on the Chrome Web Store as ShieldAI Transaction Firewall, checks transactions before you sign them. The Telegram bot, API and MCP server scan contracts and tokens on 8 chains, including Robinhood Chain.",
  },
  {
    q: "How does ShieldBot detect rug pulls and scams?",
    a: "It combines contract code checks (including bytecode patterns for unverified contracts), market and liquidity data, on-chain reputation, honeypot checks (a buy and sell simulation where the chain has one, GoPlus's honeypot flags elsewhere) and scam databases. Optional AI analysis adds a written summary. If one of these checks cannot run, the result says Unknown instead of Safe.",
  },
  {
    q: "Which blockchains does ShieldBot support?",
    a: "Ethereum, BNB Chain, opBNB, Base, Arbitrum, Polygon, Optimism and Robinhood Chain. Contract scans work on all 8. Mempool monitoring covers the 4 chains with a public mempool: Ethereum, BNB Chain, opBNB and Polygon. Base, Arbitrum, Optimism and Robinhood Chain have none, so contract scans cover them, and ShieldBot also scans new Robinhood Chain launches. Coverage depends on each chain's data providers, and missing data is reported as Unknown.",
  },
  {
    q: "What does ShieldBot do on Robinhood Chain?",
    a: "It scans Robinhood Chain tokens, including a buy and sell simulation on supported pool routes, finds new launches and sends launch alerts in Telegram. An on-chain verdict registry and a freshness guard were deployed on Robinhood Chain on 27 September 2026, along with a guarded transfer contract that checks the guard. The released browser extension does not cover Robinhood Chain yet.",
  },
  {
    q: "Is ShieldBot free to use?",
    a: "Yes. The Chrome extension and the Telegram bot are free to install and use, and neither needs an account.",
  },
  {
    q: "Does ShieldBot have a token?",
    a: "No. ShieldBot does not issue, sell, control or endorse any token. An earlier extension release used the BNB Chain token 0x4904c02efa081cb7685346968bac854cdf4e7777 as an access gate; that gate has been removed. Tokens using the ShieldBot name, including SBOT (named shieldbot, 0x8adba5e2f8ebe8a6f8d9f4c8151fba7ce2328900) and SHIELD (named shieldbot_, 0x7bf4c3cd40710b027282b6b85d86f75acfcbd0f1), two Robinhood Chain tokens paired with NVDA in pools opened on 15 September 2026, are not ShieldBot products.",
  },
  {
    q: "Does ShieldBot store my private keys or wallet data?",
    a: "No. ShieldBot never asks for, stores or sends your private keys or seed phrase. The extension sends the transaction details and the site's origin to the ShieldBot API so they can be checked.",
  },
  {
    q: "What happens when ShieldBot detects a threat?",
    a: "Before you sign, ShieldBot shows the verdict, a safety score and a plain-English explanation of what it found. On a known phishing site, a red banner appears on the page. For a warning, you choose whether to cancel or sign anyway; Strict mode takes that choice away for Block Recommended and Unknown results and when the check could not run. The extension also refuses a request on its own when the check times out after 60 seconds, when your wallet's chain is unknown, unsupported, different from the transaction's or changes during the check (including a wallet_sendCalls batch with a call on another chain), when the request comes from a frame or popup the page can script, or when the site uses the older send or sendAsync methods.",
  },
  {
    q: "What is the safety score?",
    a: "The extension shows a safety score out of 100, where higher is safer. It is 100 minus ShieldBot's risk score. 70 or above is SAFE, 51 to 69 is CAUTION, 30 to 50 is HIGH RISK, and 29 or below is BLOCK RECOMMENDED. If a check could not run, the score shows as Unknown instead of a number.",
  },
  {
    q: "How is ShieldBot different from other crypto security tools?",
    a: "Many tools only check a URL or a token list. ShieldBot checks the actual transaction before you sign, simulates buys and sells to catch honeypots where the chain allows it, and tells you plainly when it could not check something. It also works through Telegram, an API and an MCP server for AI agents.",
  },
  {
    q: "How do I install ShieldBot?",
    a: "Install the extension from the Chrome Web Store, where it is listed as ShieldAI Transaction Firewall. It is free and needs no account. You can also use the Telegram bot at t.me/shieldbot_bnb_bot: send a contract address to get a risk report.",
  },
  {
    q: "What is a wallet drainer and how does ShieldBot help?",
    a: "A wallet drainer tricks you into approving a contract, or signing a permit, that can then move your tokens. ShieldBot catches the approval or signature request before you sign, explains it, and flags unlimited approvals to risky contracts. When transaction simulation is enabled, it also shows which assets would leave your wallet. You decide whether to cancel or sign.",
  },
  {
    q: "Does ShieldBot work with MetaMask?",
    a: "ShieldBot hooks the browser's window.ethereum provider when a page loads and listens for EIP-6963 wallet announcements, so it is designed for MetaMask and other injected wallets. Testing across every wallet is still in progress.",
  },
  {
    q: "Will ShieldBot slow down my transactions?",
    a: "A check usually takes a few seconds before your wallet's signature window opens. Every check shows its verdict: after a SAFE result you continue straight away, and after a warning you can review, cancel or sign anyway.",
  },
];

export default function FAQ() {
  const [open, setOpen] = useState<number | null>(null);

  return (
    <section id="faq" aria-labelledby="faq-title" className="bg-surface-2 py-14 md:py-[72px] lg:py-24">
      <div className="max-w-3xl mx-auto px-4 sm:px-6">
        <SectionHeader
          id="faq-title"
          eyebrow="FAQ"
          title="Questions people ask"
          lead="Everything about what ShieldBot checks, what it cannot, and what it does with your data."
        />

        <motion.div
          initial={{ y: 8, opacity: 0 }}
          whileInView={{ y: 0, opacity: 1 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.4, ease: [0.2, 0, 0, 1] }}
          className="mt-10 space-y-3"
        >
          {faqs.map((faq, i) => (
            <div key={i} className="rounded-xl border border-line bg-surface transition-colors hover:border-line-strong">
              <h3>
                <button
                  type="button"
                  onClick={() => setOpen(open === i ? null : i)}
                  aria-expanded={open === i}
                  aria-controls={`faq-answer-${i}`}
                  className="flex w-full items-center justify-between gap-4 px-6 py-5 text-left"
                >
                  <span className="text-base font-semibold text-ink">{faq.q}</span>
                  <Icon name="chevron" size={20} className={`shrink-0 text-muted transition-transform duration-250 ${open === i ? "rotate-180" : ""}`} />
                </button>
              </h3>

              <AnimatePresence initial={false}>
                {open === i && (
                  <motion.div
                    key="content"
                    id={`faq-answer-${i}`}
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.25, ease: [0.2, 0, 0, 1] }}
                    className="overflow-hidden"
                  >
                    <p className="px-6 pb-5 text-[15px] leading-relaxed text-body">{faq.a}</p>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
