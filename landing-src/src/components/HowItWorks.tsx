import type { CSSProperties } from "react";
import { CHECK_ORDER } from "./CheckRow";
import Icon, { type IconName } from "./Icon";
import VerdictRecord from "./VerdictRecord";
import { verdictOf } from "../firewallVerdict";
import { recordedReplies } from "../recordedReplies";
import { useReading } from "../reading";

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


// The process track: the three steps along one rule on the paper ground, open (no accordion), ending in the
// record a check produces, drawn from the recorded BLOCK reply (src/recordedReplies.ts). No capture here: the
// hero holds the captures. On view the track draws itself step by step (index.css): each segment of the rule draws,
// its node lights and its step rises from dim; the last, magenta segment ends on the record, which then reads itself.
const recorded = recordedReplies.block;
const recordedChip = verdictOf(recorded).label;

export default function HowItWorks() {
  const track = useReading<HTMLOListElement>();
  return (
    <>
      <section
        id="how-it-works"
        aria-labelledby="how-it-works-title"
        className="border-b border-hairline bg-ground-alt py-16 md:py-24"
      >
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <div className="max-w-3xl">
            <p className="font-mono text-xs uppercase tracking-[0.08em] text-secondary">
              How it works
            </p>
            <h2
              id="how-it-works-title"
              className="mt-3 text-h2-sm md:text-h2 text-ink"
            >
              Three steps between you and a scam.
            </h2>
            <p className="mt-4 max-w-[36em] text-[17px] md:text-lg leading-relaxed text-secondary">
              A check usually takes a few seconds, before your wallet's
              signature window opens.
            </p>
          </div>

          <ol
            ref={track}
            data-read="wait"
            className="mt-12 grid grid-cols-1 md:mt-16 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.5fr)]">
            {steps.map((step, i) => {
              const last = i === steps.length - 1;
              return (
                <li
                  key={step.num}
                  style={{ "--s": i } as CSSProperties}
                  className={`pt-step ${last ? "pt-last " : ""}relative min-w-0 border-l pl-6 lg:border-l-0 lg:border-t lg:pl-0 lg:pt-8 ${last ? "border-accent" : "border-hairline-strong pb-10 lg:pb-0 lg:pr-10"}`}
                >
                  <span
                    aria-hidden="true"
                    className={`pt-node absolute -left-[5px] top-1.5 h-[9px] w-[9px] rounded-[2px] lg:-top-[5px] lg:left-0 ${last ? "bg-accent" : "border border-ink bg-ground-alt"}`}
                  />
                  <p className="font-mono text-xs tracking-[0.08em] text-secondary">
                    {step.num}
                  </p>
                  <h3 className="mt-2 text-xl font-medium leading-7 tracking-[-0.01em] text-ink">
                    {step.title}
                  </h3>
                  <p className="mt-2 max-w-[34em] text-[15px] leading-[23px] text-secondary">
                    {step.desc}
                  </p>
                  {i === 1 && (
                    <p className="mt-4 font-mono text-xs leading-[18px] text-secondary">
                      {CHECK_ORDER.join(" · ")}
                    </p>
                  )}
                  {last && (
                    <div
                      className="mt-6"
                      style={{ "--vr-d": "1500ms" } as CSSProperties}
                    >
                      <VerdictRecord
                        animate
                        variant="compact"
                        chip={{ verdict: recordedChip.verdict, label: recordedChip.text }}
                        coverage={recorded.coverage}
                        reason={recorded.plain_english}
                        chain={{ id: recorded.chain_id, name: recorded.network }}
                        evidenceHash={recorded.evidence_hash}
                        source="The recorded POST /api/firewall reply of 26 September 2026, as served."
                      />
                    </div>
                  )}
                </li>
              );
            })}
          </ol>
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
