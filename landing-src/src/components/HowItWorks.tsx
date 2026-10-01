import { motion } from "framer-motion";
import FeatureCard from "./FeatureCard";
import Icon, { type IconName } from "./Icon";
import SectionHeader from "./SectionHeader";

const steps: { num: string; title: string; desc: string; icon: IconName }[] = [
  {
    num: "01",
    title: "Intercept",
    desc: "Catches transactions and signature requests before your wallet signs them.",
    icon: "pen",
  },
  {
    num: "02",
    title: "Check",
    desc: "Decodes the call, scans the contract (code, market data, on-chain reputation and, where the chain has one, a buy and sell simulation) and checks scam databases.",
    icon: "search",
  },
  {
    num: "03",
    title: "Report",
    desc: "Shows SAFE, CAUTION, HIGH RISK or BLOCK RECOMMENDED with the reasons, or UNKNOWN with the reason a check could not run. For a warning you choose to cancel or sign (Strict mode removes that choice for BLOCK RECOMMENDED, UNKNOWN and any result whose checks did not all run). A request it cannot check is refused, such as one that times out, one whose wallet chain is unknown or differs from the transaction's, or one sent through an older wallet method or from a frame or popup the page can script.",
    icon: "shield",
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
    desc: "A verdict registry and a freshness guard let other contracts refuse a token unless it has a recent, good verdict. Both were deployed on Robinhood Chain on 27 September 2026.",
  },
];

const channels: { title: string; desc: string; link: string; href: string; icon: IconName }[] = [
  {
    title: "Chrome extension",
    desc: "Checks transactions before your browser wallet signs them.",
    link: "Add to Chrome",
    href: "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk",
    icon: "grid",
  },
  {
    title: "Telegram bot",
    desc: "Paste a contract address in chat to get a risk report.",
    link: "Open the bot",
    href: "https://t.me/shieldbot_bnb_bot",
    icon: "chat",
  },
  {
    title: "REST API",
    desc: "Firewall checks for your dApp or bot.",
    link: "API docs",
    href: "https://api.shieldbotsecurity.online/docs",
    icon: "code",
  },
  {
    title: "MCP server and SDKs",
    desc: "For AI agents. The TypeScript and Python SDKs are source in the GitHub repo, not yet on npm or PyPI.",
    link: "For builders",
    href: "#agent-security",
    icon: "bot",
  },
];

export default function HowItWorks() {
  return (
    <section id="how-it-works" aria-labelledby="how-it-works-title" className="bg-surface py-14 md:py-[72px] lg:py-24">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <SectionHeader
          id="how-it-works-title"
          eyebrow="How it works"
          title="Three steps between you and a scam."
          lead="A check usually takes a few seconds, before your wallet's signature window opens."
        />

        <motion.div
          initial={{ opacity: 0, y: 8 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.4, ease: [0.2, 0, 0, 1] }}
          className="mt-10 grid grid-cols-1 gap-6 lg:grid-cols-3"
        >
          {steps.map((step) => (
            <FeatureCard key={step.num} title={step.title} icon={step.icon} number={step.num}>
              {step.desc}
            </FeatureCard>
          ))}
        </motion.div>

        <div className="mt-12 grid grid-cols-1 gap-12 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
          <div className="min-w-0 rounded-3xl bg-surface-2 p-6">
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
                  loading="lazy"
                  alt="The ShieldBot extension's warning dialog for a request that approves unlimited USDC spending on Ethereum. The verdict badge reads BLOCK RECOMMENDED — Safety: 0/100. The danger signals include Spender flagged by GoPlus: stealing_attack (SlowMist,BlockSec)."
                  className="w-full h-auto rounded-2xl ring-1 ring-line"
                />
              </picture>
              <figcaption className="mt-4 text-[13px] leading-relaxed text-muted">
                The extension's 3.1.0 overlay (listed on the Chrome Web Store as
                ShieldAI Transaction Firewall; the 3.1.0 update is not yet released), fed
                the API's reply for this request on 26 September 2026. It
                recommends blocking an unlimited USDC approval to the wallet
                behind the 2021 BadgerDAO front-end attack, which GoPlus flags for
                stealing attacks. The Proxy/upgradeable contract signal describes
                USDC's own contract, an upgradeable proxy, not the spender.
              </figcaption>
            </figure>
          </div>

          <div className="min-w-0">
            <h3 className="text-xl font-semibold text-ink">It also checks</h3>
            <ul className="mt-5 space-y-4">
              {checks.map((check) => (
                <li key={check.title} className="text-sm leading-relaxed">
                  <span className="font-semibold text-ink">{check.title}.</span>{" "}
                  <span className="text-body">{check.desc}</span>
                </li>
              ))}
            </ul>

            <h3 className="mt-10 text-xl font-semibold text-ink">Where it runs</h3>
            <ul className="mt-5 space-y-5">
              {channels.map((channel) => (
                <li key={channel.title} className="flex gap-4">
                  <span className="mt-0.5 shrink-0 text-emerald">
                    <Icon name={channel.icon} size={24} />
                  </span>
                  <div className="text-sm leading-relaxed">
                    <div className="font-semibold text-ink">{channel.title}</div>
                    <p className="text-body">{channel.desc}</p>
                    <a
                      href={channel.href}
                      {...(channel.href.startsWith("#")
                        ? {}
                        : { target: "_blank", rel: "noopener noreferrer" })}
                      className="inline-flex min-h-[44px] items-center text-emerald underline underline-offset-4 hover:text-emerald-deep"
                    >
                      {channel.link}
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
