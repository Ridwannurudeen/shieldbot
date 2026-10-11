import { useState } from "react";
import Icon, { type IconName } from "./Icon";

const steps: { num: string; title: string; desc: string }[] = [
  {
    num: "01",
    title: "Intercept",
    desc: "Catches transactions and signature requests before your wallet signs them.",
  },
  {
    num: "02",
    title: "Check",
    desc: "Decodes the call, scans the contract (code, market data, on-chain reputation and, where the chain has one, a buy and sell simulation) and checks scam databases.",
  },
  {
    num: "03",
    title: "Report",
    desc: "Shows SAFE, CAUTION, HIGH RISK or BLOCK RECOMMENDED with the reasons, or UNKNOWN with the reason a check could not run. For a warning you choose to cancel or sign (Strict mode removes that choice for BLOCK RECOMMENDED, UNKNOWN and any result whose checks did not all run).",
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


// The accent band: the three steps as an accordion beside the real BLOCK capture in a drawn browser frame,
// then the other checks and the channels on the white ground.
export default function HowItWorks() {
  const [open, setOpen] = useState(0);

  return (
    <>
      <section
        id="how-it-works"
        aria-labelledby="how-it-works-title"
        className="band bg-accent text-white"
      >
        <div className="max-w-6xl mx-auto px-4 py-[72px] sm:px-6 md:py-28">
          <div className="mx-auto max-w-3xl text-center">
            <p className="text-sm font-medium text-white/90">How it works</p>
            <h2
              id="how-it-works-title"
              className="mt-3 text-h2-sm md:text-h2 text-white"
            >
              Three steps between you and a scam.
            </h2>
            <p className="mx-auto mt-4 max-w-[36em] text-[17px] md:text-lg leading-relaxed text-white/90">
              A check usually takes a few seconds, before your wallet's
              signature window opens.
            </p>
          </div>

          <div className="mt-12 grid grid-cols-1 items-start gap-10 md:mt-16 lg:grid-cols-2 lg:gap-12">
            <ol className="grid gap-2">
              {steps.map((step, i) => {
                const expanded = open === i;
                return (
                  <li
                    key={step.num}
                    className={`rounded-[10px] border transition-colors duration-150 ease-out ${expanded ? "border-white/70 bg-white/[0.12]" : "border-transparent hover:bg-white/[0.06]"}`}
                  >
                    <h3>
                      <button
                        type="button"
                        id={`step-${step.num}`}
                        aria-expanded={expanded}
                        aria-controls={`step-${step.num}-panel`}
                        onClick={() => setOpen(i)}
                        className="grid w-full grid-cols-[32px_1fr] items-center gap-4 rounded-[10px] px-5 py-5 text-left md:px-6"
                      >
                        <span
                          className={`grid h-8 w-8 place-items-center rounded-full border text-sm font-medium transition-colors duration-150 ease-out ${expanded ? "border-white bg-white text-accent" : "border-white/60 text-white"}`}
                        >
                          {i + 1}
                        </span>
                        <span className="text-lg font-medium leading-7 tracking-[-0.01em] text-white">
                          {step.title}
                        </span>
                      </button>
                    </h3>
                    <div
                      id={`step-${step.num}-panel`}
                      role="region"
                      aria-labelledby={`step-${step.num}`}
                      data-open={expanded}
                      inert={!expanded}
                      className="acc-panel"
                    >
                      <div>
                        <p className="pb-5 pl-[68px] pr-5 text-[15px] leading-[23px] text-white/90 md:pl-[72px] md:pr-6">
                          {step.desc}
                        </p>
                      </div>
                    </div>
                  </li>
                );
              })}
            </ol>

            <figure className="min-w-0 rounded-2xl border border-white/20 bg-white/10 p-3.5 sm:p-7">
              <div className="overflow-hidden rounded-[10px] bg-ground shadow-[0_20px_40px_rgba(0,0,0,0.18)]">
                <div
                  className="flex h-9 items-center gap-3.5 border-b border-hairline px-3.5"
                  aria-hidden="true"
                >
                  <span className="flex gap-1.5">
                    <i className="h-2.5 w-2.5 rounded-full bg-hairline" />
                    <i className="h-2.5 w-2.5 rounded-full bg-hairline" />
                    <i className="h-2.5 w-2.5 rounded-full bg-hairline" />
                  </span>
                  <span className="flex h-6 flex-1 items-center justify-center rounded-full bg-ground-alt text-xs text-secondary">
                    dapp.example
                  </span>
                  <span className="h-4 w-4" />
                </div>
                <div className="flex justify-center bg-[#26262A] px-4 pt-4 sm:px-8 sm:pt-6">
                  <div className="w-full max-w-[360px] overflow-hidden rounded-t lg:h-[400px] lg:[-webkit-mask-image:linear-gradient(#000_80%,transparent)] lg:[mask-image:linear-gradient(#000_80%,transparent)]">
                    <picture>
                      <source
                        media="(max-width: 1023px)"
                        srcSet="/hero-overlay-mobile.webp"
                        width={390}
                        height={496}
                      />
                      <img
                        src="/hero-overlay.webp"
                        width={490}
                        height={1019}
                        loading="lazy"
                        alt="The ShieldBot extension's warning dialog for a request that approves unlimited USDC spending on Ethereum. The verdict badge reads BLOCK RECOMMENDED — Safety: 0/100. The danger signals include Spender flagged by GoPlus: stealing_attack (SlowMist,BlockSec)."
                        className="block w-full h-auto"
                      />
                    </picture>
                  </div>
                </div>
              </div>
              <figcaption className="mt-3 text-xs leading-[18px] text-white/90">
                The browser frame is drawn; the dialog is a capture of the
                extension's overlay at unreleased commit 2b54a1b (3.1.0 on the
                Chrome Web Store, as ShieldAI Transaction Firewall, still shows
                the earlier dark dialog), fed the API's reply for this request
                on 26 September 2026. It recommends blocking an unlimited USDC
                approval to the wallet behind the 2021 BadgerDAO front-end
                attack, which GoPlus flags for stealing attacks. The
                Proxy/upgradeable contract signal describes USDC's own
                contract, an upgradeable proxy, not the spender.
              </figcaption>
            </figure>
          </div>
        </div>
      </section>

      <section
        aria-labelledby="also-checks-title"
        className="border-b border-hairline py-16 md:py-24"
      >
        <div className="max-w-6xl mx-auto px-4 sm:px-6 grid grid-cols-1 gap-12 lg:grid-cols-2 lg:gap-16">
          <div className="min-w-0">
            <h2
              id="also-checks-title"
              className="text-2xl font-medium tracking-[-0.02em] text-ink"
            >
              It also checks
            </h2>
            <ul className="mt-6 divide-y divide-hairline border-y border-hairline">
              {checks.map((check) => (
                <li key={check.title} className="py-4 text-[15px] leading-relaxed">
                  <span className="font-medium text-ink">{check.title}.</span>{" "}
                  <span className="text-secondary">{check.desc}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="min-w-0">
            <h2 className="text-2xl font-medium tracking-[-0.02em] text-ink">
              Where it runs
            </h2>
            <ul className="mt-6 divide-y divide-hairline border-y border-hairline">
              {channels.map((channel) => (
                <li key={channel.title} className="flex gap-4 py-4">
                  <span className="mt-0.5 shrink-0 text-accent">
                    <Icon name={channel.icon} size={24} />
                  </span>
                  <div className="text-[15px] leading-relaxed">
                    <div className="font-medium text-ink">{channel.title}</div>
                    <p className="text-secondary">{channel.desc}</p>
                    <a
                      href={channel.href}
                      {...(channel.href.startsWith("#")
                        ? {}
                        : { target: "_blank", rel: "noopener noreferrer" })}
                      className="inline-flex min-h-[44px] items-center text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover"
                    >
                      {channel.link}
                    </a>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>
    </>
  );
}
