import { useState } from "react";
import VerdictRecord from "./VerdictRecord";
import { verdictOf } from "../firewallVerdict";
import { recordedReplies } from "../recordedReplies";

// The hero figure: one recorded /api/firewall reply drawn as a verdict record, beside the capture of the
// extension's overlay fed that same reply (landing-src/scripts/capture-hero-overlay.py). The switcher picks one
// of three recordings; a record and a capture are only ever shown together for the same reply. On each pick the
// record resolves (VerdictRecord's animate) while the capture slot shows the overlay's real loading dialog,
// then the verdict dialog; the final frame is the base style, so reduced motion shows it at once. Nothing here
// talks to the network.
type Pick = "block" | "unknown" | "safe";

const picks: { id: Pick; label: string }[] = [
  { id: "block", label: "BLOCK" },
  { id: "unknown", label: "UNKNOWN" },
  { id: "safe", label: "SAFE" },
];

function Capture({ pick }: { pick: Pick }) {
  if (pick === "block")
    return (
      <picture>
        <source
          media="(max-width: 639px)"
          srcSet="/hero-overlay-mobile.webp"
          width={390}
          height={496}
        />
        <img
          src="/hero-overlay.webp"
          width={490}
          height={1019}
          alt="The ShieldBot extension's warning dialog for a request that approves unlimited USDC spending on Ethereum. The verdict badge reads BLOCK RECOMMENDED — Safety: 0/100. The danger signals include Spender flagged by GoPlus: stealing_attack (SlowMist,BlockSec)."
          className="block w-full h-auto"
        />
      </picture>
    );
  if (pick === "unknown")
    return (
      <img
        src="/hero-overlay-unknown.webp"
        width={490}
        height={480}
        alt="The ShieldBot extension's dialog for a token approval on Robinhood Chain whose token has no supported pool. The verdict badge reads UNKNOWN. Why: No DexScreener pairs on requested chain (robinhood); Initialize logs scanned over blocks 85694876-85724875; No supported pool found; Unknown fields: buy_tax, sell_tax, can_sell. The danger signals include Top 10 holders own 100.0% of supply (burn, locked, pool and locker addresses excluded)."
        className="block w-full h-auto"
      />
    );
  return (
    <img
      src="/hero-overlay-safe.webp"
      width={490}
      height={480}
      alt="The ShieldBot extension's dialog for a 250 ARB approval to Uniswap's SwapRouter02 on Arbitrum One. The verdict badge reads SAFE — Safety: 93.6/100. The danger signals include Proxy/upgradeable contract."
      className="block w-full h-auto"
    />
  );
}

const captions: Record<Pick, string> = {
  block:
    "Recorded reply of 26 September 2026, chain 1, BLOCK RECOMMENDED. The dialog is a capture of the extension's overlay at unreleased commit 2b54a1b, fed that reply.",
  unknown:
    "Recorded reply of 11 October 2026, chain 4663, UNKNOWN. Upper part of the dialog, a capture of the extension's overlay at unreleased commit 2b54a1b, fed that reply.",
  safe: "Recorded reply of 11 October 2026, chain 42161, SAFE. Upper part of the dialog, a capture of the extension's overlay at unreleased commit 2b54a1b, fed that reply.",
};

export default function HeroRecord() {
  const [pick, setPick] = useState<Pick>("unknown");
  const reply = recordedReplies[pick];
  const { label } = verdictOf(reply);

  return (
    <div>
      <div
        role="group"
        aria-label="Recorded replies"
        className="flex flex-wrap items-center gap-x-4 gap-y-2"
      >
        <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-secondary">
          Recorded replies
        </span>
        <div className="flex gap-1">
          {picks.map(({ id, label: text }) => (
            <button
              key={id}
              type="button"
              aria-pressed={pick === id}
              onClick={() => setPick(id)}
              className={[
                "h-9 rounded-lg border px-3 font-mono text-xs tracking-[0.04em] transition-colors duration-150",
                pick === id
                  ? "border-ink bg-ink text-white"
                  : "border-hairline-strong bg-ground text-ink hover:bg-ground-alt",
              ].join(" ")}
            >
              {text}
            </button>
          ))}
        </div>
      </div>
      <div
        key={pick}
        className="mt-4 grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_380px] lg:gap-8"
      >
        <VerdictRecord
          animate
          chip={{ verdict: label.verdict, label: label.text }}
          coverage={reply.coverage}
          reasons={reply.coverage_reasons}
          reason={reply.plain_english}
          recordedAt={reply.sent_at}
          chain={{ id: reply.chain_id, name: reply.network }}
          evidenceHash={reply.evidence_hash}
          source="Fields of the recorded POST /api/firewall reply, as served."
        />
        <figure className="min-w-0">
          <div className="story-fade relative overflow-hidden rounded-lg border border-hairline bg-ground sm:h-[440px]">
            <div className="hero-loading absolute inset-0 hidden place-items-center bg-ground-alt sm:grid">
              <img
                src="/hero-overlay-loading.webp"
                width={490}
                height={246}
                alt="The ShieldBot extension's dialog while it checks the request. It reads Analyzing transaction..."
                className="w-[340px] h-auto rounded"
              />
            </div>
            <div className="hero-verdict">
              <Capture pick={pick} />
            </div>
          </div>
          <figcaption className="mt-3 text-xs leading-[18px] text-secondary">
            {captions[pick]} {"Recorded examples, not live scans. The extension's loading dialog, shown first, is a capture too."}
          </figcaption>
        </figure>
      </div>
    </div>
  );
}
