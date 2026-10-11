import { useRef, useState, type KeyboardEvent, type ReactNode } from "react";

// Five features, ordered by what sets ShieldBot apart. Each panel is text first. A product picture is a
// capture of the extension's overlay (landing-src/scripts/capture-hero-overlay.py) or a recorded answer
// from docs/SUBMISSION.md; a feature with no capture yet shows a line drawing labelled as an illustration.
// Nothing here talks to the network.
const VIRTUAL = "0xc6911796042b15d7fa4f6cde69e245ddcd3d9c31";
const SUBMISSION =
  "https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/SUBMISSION.md";

const features: {
  id: string;
  tab: string;
  eyebrow: string;
  title: string;
  desc: string;
  points: string[];
}[] = [
  {
    id: "unknown",
    tab: "Unknown",
    eyebrow: "When a check cannot run",
    title: "Unknown, with the reason. Never Safe.",
    desc: "If a data provider does not answer, the chain has no sell simulation route or the request cannot be read, the overlay reads UNKNOWN and names the check that did not run.",
    points: [
      "The reason is printed on the dialog, after Why:",
      "Strict mode removes the option to sign an Unknown request",
      "The Telegram bot marks an incomplete scan UNKNOWN, never safe",
    ],
  },
  {
    id: "registry",
    tab: "On-chain guard",
    eyebrow: "On-chain registry and guard",
    title: "Contracts ask before funds move.",
    desc: "On Robinhood Chain, a contract calls the ShieldBot guard before it moves a token. The guard reads the verdict registry and allows the token when its latest record is LOW or MEDIUM and within the age limit the caller sets.",
    points: [
      "HIGH and HONEYPOT are refused even after the record expires",
      "Registry, guard and guarded transfer deployed on Robinhood Chain on 27 September 2026",
      "Permission is not a safety guarantee: the guard accepts MEDIUM risk",
    ],
  },
  {
    id: "transaction",
    tab: "Transaction check",
    eyebrow: "Browser extension",
    title: "A verdict before the wallet opens.",
    desc: "The extension decodes each transaction a page sends to your wallet (which function, which spender, how much) and shows SAFE, CAUTION, HIGH RISK, BLOCK RECOMMENDED or UNKNOWN with a safety score and the reasons.",
    points: [
      "Decoded calldata, so an unlimited approval reads as Unlimited",
      "Danger signals are listed even when the verdict is SAFE",
      "You choose to cancel or sign; Strict mode holds BLOCK RECOMMENDED",
    ],
  },
  {
    id: "signatures",
    tab: "Signature requests",
    eyebrow: "Typed data and messages",
    title: "Signatures read like transactions.",
    desc: "Signature requests are checked by the server like transactions and shown in readable form: permits, Permit2, and Seaport and Blur marketplace orders.",
    points: [
      "A Sign-In with Ethereum message made for another site is flagged BLOCK RECOMMENDED, and so is every eth_sign request",
      "Typed data the server cannot read is Unknown",
      "The text of a message you sign is never sent",
    ],
  },
  {
    id: "phishing",
    tab: "Phishing banner",
    eyebrow: "Every site you open",
    title: "A warning on known phishing sites.",
    desc: "The address of each https site you open is checked against phishing intelligence, and a warning banner appears when the site is flagged, before you connect your wallet.",
    points: [
      "The check sends the site's origin: scheme, host and port",
      "Results are kept for the browser session",
    ],
  },
];

function Capture({
  src,
  alt,
  caption,
}: {
  src: string;
  alt: string;
  caption: ReactNode;
}) {
  return (
    <figure className="min-w-0">
      <div className="flex justify-center rounded-xl border border-hairline bg-[#26262A] px-4 pt-5 sm:px-10 sm:pt-8">
        <img
          src={src}
          width={490}
          height={480}
          loading="lazy"
          alt={alt}
          className="block w-full max-w-[400px] h-auto rounded-t-md [-webkit-mask-image:linear-gradient(#000_88%,transparent)] [mask-image:linear-gradient(#000_88%,transparent)]"
        />
      </div>
      <figcaption className="mt-3 text-xs leading-[18px] text-secondary">
        {caption}
      </figcaption>
    </figure>
  );
}

function Illustration({
  subject,
  children,
}: {
  subject: string;
  children: ReactNode;
}) {
  return (
    <figure className="min-w-0">
      <div className="relative grid h-[300px] place-items-center rounded-xl border border-dashed border-hairline-strong bg-ground-alt sm:h-[360px]">
        <span className="absolute left-3 top-3 rounded border border-hairline-strong bg-ground px-2 py-0.5 text-xs font-medium text-secondary">
          Illustration
        </span>
        {children}
      </div>
      <figcaption className="mt-3 text-xs leading-[18px] text-secondary">
        Illustration, not a capture: no capture of this {subject} has been
        recorded yet. The text beside it is from the extension's store listing.
      </figcaption>
    </figure>
  );
}

function Media({ id }: { id: string }) {
  if (id === "unknown")
    return (
      <Capture
        src="/hero-overlay-unknown.webp"
        alt="The ShieldBot extension's dialog for a token approval on Robinhood Chain whose token has no supported pool. The verdict badge reads UNKNOWN. Why: No DexScreener pairs on requested chain (robinhood); Initialize logs scanned over blocks 85694876-85724875; No supported pool found; Unknown fields: buy_tax, sell_tax, can_sell. The danger signals include Top 10 holders own 100.0% of supply (burn, locked, pool and locker addresses excluded)."
        caption="Recorded /api/firewall reply of 11 October 2026, chain 4663, UNKNOWN. Upper part of the dialog, overlay at unreleased commit 2b54a1b."
      />
    );
  if (id === "transaction")
    return (
      <Capture
        src="/hero-overlay-safe.webp"
        alt="The ShieldBot extension's dialog for a 250 ARB approval to Uniswap's SwapRouter02 on Arbitrum One. The verdict badge reads SAFE — Safety: 93.6/100. The danger signals include Proxy/upgradeable contract."
        caption="Recorded /api/firewall reply of 11 October 2026, chain 42161, SAFE. Upper part of the dialog, overlay at unreleased commit 2b54a1b."
      />
    );
  if (id === "registry")
    return (
      <figure className="min-w-0">
        <div className="overflow-x-auto rounded-xl bg-panel p-5 font-mono text-[12.5px] leading-[1.7] text-on-panel sm:p-7 sm:text-[13.5px]">
          <pre>
            <span className="text-on-panel-2">// Ask before moving funds.</span>
            {
              "\n(bool allowed, uint8 reason) =\n    guard.check(subject, maxAge);\n\n"
            }
            <span className="text-on-panel-2">
              // Recorded, 27 September 2026
            </span>
            {"\nguard.check(VIRTUAL, 900)\n  allowed = "}
            <span className="text-accent-on-panel">true</span>
            {"\n  reason  = 0  ALLOWED\n\n"}
            <span className="text-on-panel-2">
              // Derived, not a recorded call
            </span>
            {"\nguard.check(0x3435…26dd, 900)\n  allowed = "}
            <span className="text-block-on-panel">false</span>
            {"\n  reason  = 4  HONEYPOT"}
          </pre>
        </div>
        <figcaption className="mt-3 text-xs leading-[18px] text-secondary">
          Recorded: scripts/verify_deployment.py against the live contracts on
          27 September 2026 reported allowed=True, reason=0 for{" "}
          <a
            href={`https://robin.etherscan.io/address/${VIRTUAL}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent underline underline-offset-2 transition-colors duration-150 hover:text-accent-hover"
          >
            VIRTUAL
          </a>{" "}
          with maxAge 900 s (
          <a
            href={SUBMISSION}
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent underline underline-offset-2 transition-colors duration-150 hover:text-accent-hover"
          >
            docs/SUBMISSION.md
          </a>
          ). Derived: the registry's record for 0x3435…26dd, as served on 11
          October 2026, is HONEYPOT, and the guard's source returns reason 4
          for a HONEYPOT record at any age.
        </figcaption>
      </figure>
    );
  if (id === "signatures")
    return (
      <Illustration subject="dialog">
        <svg
          viewBox="0 0 280 220"
          className="w-[240px] sm:w-[280px]"
          fill="none"
          stroke="rgb(var(--c-ink))"
          strokeWidth="1.25"
          aria-hidden="true"
        >
          <rect x="20" y="10" width="240" height="200" rx="12" />
          <text
            x="40"
            y="42"
            fill="rgb(var(--c-ink))"
            stroke="none"
            fontSize="13"
          >
            Signature request
          </text>
          {[60, 98, 136].map((y, i) => (
            <g key={y}>
              <rect
                x="40"
                y={y}
                width="200"
                height="28"
                rx="6"
                stroke="rgb(var(--c-hairline-strong))"
              />
              <text
                x="52"
                y={y + 18}
                fill="rgb(var(--c-secondary))"
                stroke="none"
                fontSize="11"
              >
                {["Permit2", "spender", "amount"][i]}
              </text>
              <line
                x1="150"
                y1={y + 14}
                x2={[226, 214, 200][i]}
                y2={y + 14}
                stroke="rgb(var(--c-hairline-strong))"
                strokeWidth="6"
                strokeLinecap="round"
              />
            </g>
          ))}
          <rect
            x="40"
            y="176"
            width="94"
            height="22"
            rx="6"
            stroke="rgb(var(--c-hairline-strong))"
          />
          <rect x="146" y="176" width="94" height="22" rx="6" />
        </svg>
      </Illustration>
    );
  return (
    <Illustration subject="banner">
      <svg
        viewBox="0 0 300 220"
        className="w-[260px] sm:w-[300px]"
        fill="none"
        stroke="rgb(var(--c-ink))"
        strokeWidth="1.25"
        aria-hidden="true"
      >
        <rect x="10" y="10" width="280" height="200" rx="10" />
        <line
          x1="10"
          y1="36"
          x2="290"
          y2="36"
          stroke="rgb(var(--c-hairline-strong))"
        />
        <rect
          x="80"
          y="17"
          width="140"
          height="12"
          rx="6"
          stroke="rgb(var(--c-hairline-strong))"
        />
        <rect
          x="10"
          y="36"
          width="280"
          height="34"
          stroke="rgb(var(--c-block))"
        />
        <text
          x="24"
          y="58"
          fill="rgb(var(--c-block-text))"
          stroke="none"
          fontSize="12"
        >
          Warning banner: site flagged as phishing
        </text>
        {[92, 112, 132].map((y, i) => (
          <line
            key={y}
            x1="30"
            y1={y}
            x2={[250, 210, 170][i]}
            y2={y}
            stroke="rgb(var(--c-hairline-strong))"
            strokeWidth="6"
            strokeLinecap="round"
          />
        ))}
        <rect
          x="30"
          y="156"
          width="96"
          height="30"
          rx="6"
          stroke="rgb(var(--c-hairline-strong))"
        />
      </svg>
    </Illustration>
  );
}

export default function FeatureTabs() {
  const [active, setActive] = useState(0);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);

  function select(i: number) {
    setActive(i);
    tabs.current[i]?.focus();
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const current = tabs.current.indexOf(event.target as HTMLButtonElement);
    const last = features.length - 1;
    const next = {
      ArrowRight: current === last ? 0 : current + 1,
      ArrowLeft: current === 0 ? last : current - 1,
      Home: 0,
      End: last,
    }[event.key];
    if (next === undefined) return;
    event.preventDefault();
    select(next);
  }

  return (
    <section
      id="features"
      aria-labelledby="features-title"
      className="border-b border-hairline bg-ground-alt py-16 md:py-24"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-sm font-medium text-accent">What it does</p>
          <h2
            id="features-title"
            className="mt-3 text-h2-sm md:text-h2 text-ink"
          >
            ShieldBot in action
          </h2>
          <p className="mt-4 text-[17px] md:text-lg leading-relaxed text-secondary">
            One engine behind the extension, the Telegram bot and the on-chain
            guard. Each tab shows a recorded answer or says it is an
            illustration.
          </p>
        </div>

        <div
          role="tablist"
          aria-label="Features"
          onKeyDown={onKeyDown}
          className="mt-10 grid grid-cols-2 overflow-hidden rounded-t-xl border border-hairline bg-ground sm:grid-cols-6 md:mt-12 lg:grid-cols-5"
        >
          {features.map((feature, i) => {
            const selected = i === active;
            return (
              <button
                key={feature.id}
                ref={(el) => {
                  tabs.current[i] = el;
                }}
                type="button"
                role="tab"
                id={`feature-tab-${feature.id}`}
                aria-selected={selected}
                aria-controls={`feature-panel-${feature.id}`}
                tabIndex={selected ? 0 : -1}
                onClick={() => setActive(i)}
                className={`-mb-px -mr-px flex min-h-[56px] items-center justify-center border-b border-r border-hairline px-3 text-center text-[15px] font-medium transition-colors duration-150 ease-out focus-visible:[outline-offset:-3px] md:min-h-[60px] lg:col-span-1 ${i < 3 ? "sm:col-span-2" : i === 3 ? "sm:col-span-3" : "col-span-2 sm:col-span-3"} ${selected ? "bg-accent-tint text-accent shadow-[inset_0_-2px_0_rgb(var(--c-accent))]" : "text-secondary hover:text-ink"}`}
              >
                {feature.tab}
              </button>
            );
          })}
        </div>

        {features.map((feature, i) => (
          <div
            key={feature.id}
            role="tabpanel"
            id={`feature-panel-${feature.id}`}
            aria-labelledby={`feature-tab-${feature.id}`}
            tabIndex={0}
            hidden={i !== active}
            className="tab-fade rounded-b-xl border border-t-0 border-hairline bg-ground px-4 py-8 sm:px-8 md:py-12 lg:px-12 lg:py-14"
          >
            <div className="grid grid-cols-1 items-center gap-10 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] lg:gap-14">
              <div className="min-w-0">
                <p className="text-sm font-medium text-accent">
                  {feature.eyebrow}
                </p>
                <h3 className="mt-3 text-[26px] font-medium leading-[1.2] tracking-[-0.02em] text-ink md:text-[30px]">
                  {feature.title}
                </h3>
                <p className="mt-4 text-base leading-[26px] text-secondary">
                  {feature.desc}
                </p>
                <ul className="mt-5 grid gap-3">
                  {feature.points.map((point) => (
                    <li
                      key={point}
                      className="grid grid-cols-[18px_1fr] gap-3 text-[15px] leading-[23px] text-ink"
                    >
                      <span
                        className="mt-[8px] h-1.5 w-1.5 justify-self-center rounded-full bg-accent"
                        aria-hidden="true"
                      />
                      {point}
                    </li>
                  ))}
                </ul>
              </div>
              <Media id={feature.id} />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
