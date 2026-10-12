import type { CSSProperties } from "react";
import { CHECK_ORDER } from "./CheckRow";
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
    desc: "Decodes the call, scans the contract (code, market, reputation and, where the chain has one, a buy and sell simulation) and checks scam databases.",
  },
  {
    num: "03",
    title: "Report",
    desc: "Shows SAFE, CAUTION, HIGH RISK or BLOCK RECOMMENDED with the reasons, or UNKNOWN with the check that could not run. You cancel or sign; Strict mode holds BLOCK RECOMMENDED, UNKNOWN and any incomplete check.",
  },
];

// The process track: the three steps along one rule on the paper ground, open (no accordion). On view the track
// draws itself step by step (index.css): each segment of the rule draws, its node lights and its step rises from
// 0.6; the last segment is the magenta one. One linked line under it names where ShieldBot runs.
export default function HowItWorks() {
  const track = useReading<HTMLOListElement>();
  return (
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
            A check takes a few seconds, before the signature window opens.
          </p>
        </div>

        <ol
          ref={track}
          data-read="wait"
          className="mt-12 grid grid-cols-1 md:mt-16 lg:grid-cols-3">
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
              </li>
            );
          })}
        </ol>

        <p className="mt-12 text-[15px] leading-relaxed text-secondary md:mt-16">
          Runs as a{" "}
          <a
            href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk"
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover"
          >
            Chrome extension
          </a>
          , a{" "}
          <a href="https://t.me/shieldbot_bnb_bot" target="_blank" rel="noopener noreferrer" className="text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover">
            Telegram bot
          </a>
          , a{" "}
          <a href="https://api.shieldbotsecurity.online/docs" target="_blank" rel="noopener noreferrer" className="text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover">
            REST API
          </a>{" "}
          and an{" "}
          <a href="#agent-security" className="text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover">
            MCP server
          </a>{" "}
          for agents.
        </p>
      </div>
    </section>
  );
}
