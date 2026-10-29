import { useState } from "react";
import Icon from "./Icon";

const faqs = [
  {
    q: "What is ShieldBot?",
    a: "A transaction security tool for EVM chains. The browser extension checks transactions before you sign; the Telegram bot, API and MCP server scan contracts on 9 chains, including Robinhood Chain and BOT Chain.",
  },
  {
    q: "How does ShieldBot detect rug pulls and scams?",
    a: "Contract code checks (including bytecode patterns for unverified contracts), market and liquidity data, on-chain reputation, honeypot checks (a buy and sell simulation where the chain has one, GoPlus flags elsewhere) and scam databases. If one of these cannot run, the result says Unknown instead of Safe.",
  },
  {
    q: "Which blockchains does ShieldBot support?",
    a: "Ethereum, BNB Chain, opBNB, Base, Arbitrum, Polygon, Optimism, Robinhood Chain and BOT Chain. Contract scans run on all 9 chains. Mempool monitoring covers the 4 chains with a public mempool: Ethereum, BNB Chain, opBNB and Polygon. Missing data is reported as Unknown.",
  },
  {
    q: "What does ShieldBot do on Robinhood Chain?",
    a: "It scans Robinhood Chain tokens with a buy and sell simulation on supported pool routes, finds new launches and sends alerts in Telegram. A verdict registry, a freshness guard and a guarded transfer contract were deployed on Robinhood Chain on 27 September 2026.",
  },
  {
    q: "What does ShieldBot do on BOT Chain?",
    a: "It simulates buys and sells on supported BDEX V2 and V3 pools paired with WBOT; tokens without a supported pool read Unknown for sellability. It checks GoPlus address labels for the token and, when Blockscout supplies its creator, the creator; /rescue bot: scans BOT Chain approvals. Telegram /scan and /token results can be recorded in the verdict registry deployed on BOT Chain on 26 October 2026. A guard and a guarded transfer that read it were deployed on BOT Chain on 29 October 2026.",
  },
  {
    q: "How do I install ShieldBot, and what does it cost?",
    a: "Install the extension from the Chrome Web Store. It is free and needs no account, and so is the Telegram bot at t.me/shieldbot_bnb_bot: send a contract address to get a risk report.",
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
    a: "Before you sign, ShieldBot shows the verdict, a safety score and a plain-English explanation. On a known phishing site a warning banner appears. For a warning you choose to cancel or sign; Strict mode takes that choice away for Block Recommended and Unknown results and when the check could not run. The extension also refuses a request on its own when the check times out after 60 seconds, when your wallet's chain is unknown, unsupported or changes during the check (including a wallet_sendCalls batch with a call on another chain), when the request comes from a frame or popup the page can script, or when the site uses the older send or sendAsync methods.",
  },
  {
    q: "What is the safety score?",
    a: "The extension shows a safety score out of 100, where higher is safer. It is 100 minus ShieldBot's risk score. 70 or above is SAFE, 51 to 69 is CAUTION, 30 to 50 is HIGH RISK, and 29 or below is BLOCK RECOMMENDED. If a check could not run, the score shows as Unknown instead of a number.",
  },
  {
    q: "I think I signed something bad. What now?",
    a: "Revoke the approval first, in your wallet's approval settings or at revoke.cash, then move what is left to a fresh wallet and do not sign any refund or recovery offer. In Telegram, /rescue <wallet> counts your ERC-20 allowances on a chain and lists the risky ones, and /report <address> <reason> flags the address. The full steps are in the Safety guide at shieldbotsecurity.online/safety.html.",
  },
];

// One column, read like a document: the heading, then the questions numbered down the page. One answer opens at a
// time; the panel opens from 0fr to 1fr in 300 ms (index.css .acc-panel), so nothing measures height, and a closed
// answer is inert.
export default function FAQ() {
  const [open, setOpen] = useState<number | null>(0);

  return (
    <section id="faq" aria-labelledby="faq-title" className="border-t border-hairline bg-ground py-16 md:py-24">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="max-w-[52rem]">
          <p className="font-mono text-xs uppercase tracking-[0.08em] text-secondary">FAQ</p>
          <h2 id="faq-title" className="mt-3 text-h2-sm md:text-h2 text-ink">
            Questions people ask
          </h2>
          <p className="mt-4 text-[17px] md:text-lg leading-relaxed text-secondary">
            Something else?{" "}
            <a
              href="mailto:support@shieldbotsecurity.online"
              className="text-accent underline underline-offset-4 transition-colors duration-150 hover:text-ink"
            >
              Write to support
            </a>
            .
          </p>

          <ol className="mt-10 border-b border-hairline-strong md:mt-12">
            {faqs.map((faq, i) => {
              const expanded = open === i;
              return (
                <li key={i} className="border-t border-hairline-strong">
                  <h3>
                    <button
                      type="button"
                      id={`faq-question-${i}`}
                      onClick={() => setOpen(expanded ? null : i)}
                      aria-expanded={expanded}
                      aria-controls={`faq-answer-${i}`}
                      className="group grid w-full grid-cols-[32px_minmax(0,1fr)_16px] items-baseline gap-x-3 py-5 text-left sm:grid-cols-[44px_minmax(0,1fr)_16px]"
                    >
                      <span className={`font-mono text-xs ${expanded ? "text-accent" : "text-secondary"}`}>
                        {String(i + 1).padStart(2, "0")}
                      </span>
                      <span className="text-base font-medium leading-6 text-ink md:text-[17px]">{faq.q}</span>
                      <Icon
                        name="chevron"
                        size={16}
                        className={`self-center transition-transform duration-300 ease-out ${expanded ? "rotate-180 text-ink" : "text-secondary group-hover:text-ink"}`}
                      />
                    </button>
                  </h3>
                  <div
                    id={`faq-answer-${i}`}
                    role="region"
                    aria-labelledby={`faq-question-${i}`}
                    data-open={expanded}
                    inert={!expanded}
                    className="acc-panel"
                  >
                    <div>
                      <p className="max-w-[44em] pb-6 pl-[44px] pr-7 text-[15px] leading-relaxed text-secondary [overflow-wrap:anywhere] sm:pl-[56px]">{faq.a}</p>
                    </div>
                  </div>
                </li>
              );
            })}
          </ol>
        </div>
      </div>
    </section>
  );
}
