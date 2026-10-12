import { useEffect, useState } from "react";
import VerdictRecord from "./VerdictRecord";
import { PauseButton } from "./Button";
import { verdictOf } from "../firewallVerdict";
import { recordedReplies } from "../recordedReplies";
import { useAlive } from "../reading";
import { short, useFeed, utc } from "../registryFeed";

// The hero figure: one recorded /api/firewall reply told as a story (index.css, "The hero story"), about 7 s, then
// held. 1. A signing card, an illustration: a placeholder dApp asks to sign the recorded call. 2. The extension's
// real loading dialog (a capture) slides in over it. 3. The verdict record beside it takes a large reading of the
// six checks. 4. The chip stamps and the overlay's verdict dialog (a capture of the overlay fed that same reply)
// replaces the loading one. 5. The commit card: the recorded replies were never published, so it shows the newest
// live registry record the page already fetched (src/registryFeed.ts), labelled as another token's record, never
// this request's. A record and a capture are only ever shown together for the same reply. The story replays on each
// pick, and 14 s after it last started while it is on screen (useAlive: not off screen, not in a hidden tab, not
// paused, never with reduced motion); whenever it is not, the frame on screen holds (data-paused). The final frame is
// the base style, so reduced motion shows it at once.
// Nothing here sends a request: the commit card reads the shared feed.
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
    "Recorded reply of 11 October 2026, chain 4663, UNKNOWN. Upper dialog: a capture of the extension's overlay at unreleased commit 2b54a1b, fed that reply.",
  safe: "Recorded reply of 11 October 2026, chain 42161, SAFE. Upper dialog: a capture of the extension's overlay at unreleased commit 2b54a1b, fed that reply.",
};

// The commit card's record: the registry's newest confirmed record, or in the feed's fallback the newest blocked
// launch's record. undefined while loading, null when the feed did not answer.
function useNewest() {
  const { recent, launches, records, fetchedAt } = useFeed();
  if (Array.isArray(recent))
    return {
      record: recent[0] ?? null,
      label: "Newest confirmed registry record",
      fetchedAt,
    };
  const first =
    recent === "fallback" ? launches && (launches[0] ?? null) : recent;
  return {
    record: first && records[first.token_address],
    label: "Registry record of the newest launch ShieldBot blocked",
    fetchedAt,
  };
}

// Every element is mounted from the start, so a record that arrives after the story started still ticks in on cue.
function Commit() {
  const { record, label, fetchedAt } = useNewest();
  const confirmed = record?.onchain_status === "confirmed";
  const value = (text: string | number | null | undefined) =>
    record === undefined ? "…" : (text ?? "Unavailable");
  return (
    <div className="hero-commit absolute inset-x-3 bottom-3 rounded-lg border border-hairline bg-ground px-4 py-3 shadow-lg">
      <p className="font-mono text-[11px] uppercase leading-4 tracking-[0.08em] text-secondary">
        {label} · live, not the request above
        {record && fetchedAt && ` · fetched ${utc(fetchedAt.getTime() / 1000)}`}
      </p>
      <p className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[13px] leading-5 text-ink">
        <span className="inline-flex items-center gap-2 font-sans font-medium">
          <svg
            className={confirmed ? "hero-seal" : "hero-seal invisible"}
            width="18"
            height="18"
            viewBox="0 0 18 18"
            fill="none"
            aria-hidden="true"
          >
            <rect x="1" y="1" width="16" height="16" rx="2" pathLength="1" />
            <path d="m5 9.5 2.5 2.5L13 6.5" pathLength="1" />
          </svg>
          {record
            ? confirmed
              ? "Confirmed on Robinhood Chain"
              : `Status ${record.onchain_status}`
            : record === undefined
              ? "Loading the registry record"
              : "Unavailable: the registry feed did not answer"}
        </span>
        <span>
          <span className="text-secondary">Block </span>
          <span className="hero-tick">{value(record?.observed_block)}</span>
        </span>
        <span>
          <span className="text-secondary">Evidence </span>
          <span className="hero-tick">
            {value(record?.evidence_hash && short(record.evidence_hash))}
          </span>
        </span>
        <span>
          <span className="text-secondary">Token </span>
          {value(record && short(record.subject))}
        </span>
      </p>
    </div>
  );
}

export default function HeroRecord() {
  const [pick, setPick] = useState<Pick>("unknown");
  const [run, setRun] = useState(0);
  const { ref, on, paused, setPaused } = useAlive<HTMLDivElement>();
  const reply = recordedReplies[pick];
  const { label } = verdictOf(reply);

  // While the hero is on screen the story eases to 0.6 opacity (data-out, index.css) and plays again, 14 s after it
  // last started.
  useEffect(() => {
    if (!on) return;
    const element = ref.current!;
    const fade = setTimeout(() => (element.dataset.out = ""), 13_600);
    const again = setTimeout(() => {
      delete element.dataset.out;
      setRun(run + 1);
    }, 14_000);
    return () => {
      clearTimeout(fade);
      clearTimeout(again);
      delete element.dataset.out;
    };
  }, [on, pick, run]);

  return (
    <div ref={ref} data-paused={on ? undefined : ""}>
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
        <PauseButton paused={paused} setPaused={setPaused} />
      </div>
      <div
        key={`${pick}${run}`}
        className="hero-run mt-4 grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_380px] lg:gap-8"
      >
        <div className="vr-hero min-w-0">
          <VerdictRecord
            animate
            request={`${reply.request.method} · to ${reply.request.to}`}
            chip={{ verdict: label.verdict, label: label.text }}
            coverage={reply.coverage}
            reasons={reply.coverage_reasons}
            reason={reply.plain_english}
            recordedAt={reply.sent_at}
            chain={{ id: reply.chain_id, name: reply.network }}
            evidenceHash={reply.evidence_hash}
          />
        </div>
        <figure className="min-w-0 max-lg:order-first">
          <div className="relative h-[540px] overflow-hidden rounded-lg border border-hairline bg-ground-alt sm:h-[520px] lg:h-[420px]">
            <div className="hero-card absolute inset-x-4 top-4 rounded-lg border border-hairline bg-ground p-4 shadow-sm">
              <p className="flex justify-between font-mono text-[11px] leading-4 text-secondary">
                <span>app.example</span>
                <span>Signature request</span>
              </p>
              <p className="mt-2 text-[15px] font-medium text-ink">
                Approve token spending
              </p>
              <dl className="mt-3 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 font-mono text-xs leading-[18px]">
                <dt className="text-secondary">Method</dt>
                <dd>{reply.request.method}</dd>
                <dt className="text-secondary">Token</dt>
                <dd>{reply.request.to}</dd>
                <dt className="text-secondary">Spender</dt>
                <dd>{reply.request.spender}</dd>
                <dt className="text-secondary">Chain</dt>
                <dd>
                  {reply.chain_id} · {reply.network}
                </dd>
              </dl>
              <p className="mt-4 grid grid-cols-2 gap-2 text-center text-sm font-medium">
                <span className="rounded-lg border border-hairline-strong py-2">
                  Reject
                </span>
                <span className="rounded-lg bg-ink py-2 text-white">Sign</span>
              </p>
            </div>
            <div className="absolute inset-x-6 top-16 h-[330px]">
              <div className="hero-loading absolute inset-x-0 top-0 overflow-hidden rounded-lg border border-hairline shadow-xl">
                <img
                  src="/hero-overlay-loading.webp"
                  width={490}
                  height={246}
                  alt="The ShieldBot extension's dialog while it checks the request. It reads Analyzing transaction..."
                  className="block w-full h-auto"
                />
              </div>
              <div className="hero-verdict relative max-h-full overflow-hidden rounded-lg border border-hairline bg-ground shadow-xl after:absolute after:inset-x-0 after:bottom-0 after:h-14 after:bg-gradient-to-t after:from-ground">
                <Capture pick={pick} />
              </div>
            </div>
            <Commit />
          </div>
          <figcaption className="mt-3 text-xs leading-[18px] text-secondary">
            {captions[pick]} Recorded examples, not live scans. The signing card is an illustration: a placeholder dApp asking to
            sign the recorded call.
          </figcaption>
        </figure>
      </div>
    </div>
  );
}
