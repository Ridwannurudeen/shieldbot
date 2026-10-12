import { useEffect, useState } from "react";
import Badge from "./Badge";
import VerdictRecord from "./VerdictRecord";
import { PauseButton } from "./Button";
import { CHECK_ORDER } from "./CheckRow";
import { verdictOf } from "../firewallVerdict";
import { recordedReplies } from "../recordedReplies";
import { useAlive } from "../reading";
import { short, useFeed, utc } from "../registryFeed";

// The hero figure: one recorded /api/firewall reply told as a story (index.css, "The hero story"), about 7 s, on
// its verdict's field (a deep gradient in the verdict's own hue, index.css .field-*). At the top of the field, what
// ShieldBot says: the chip, one sentence of the reply's plain_english and its measure line (risk_score, or the
// coverage keys below 1 when the reply is incomplete). 1. A signing card, an illustration: a placeholder dApp asks
// to sign the recorded call. 2. The extension's real loading dialog (a capture) slides in over it. 3. The verdict
// record beside it takes a large reading of the six checks. 4. The chip stamps, the field's light brightens once
// and the overlay's verdict dialog (a capture of the overlay fed that same reply) replaces the loading one. 5. The
// commit card: the recorded replies were never published, so it shows the newest live registry record the page
// already fetched (src/registryFeed.ts), labelled as another token's record, never this request's. A record and a
// capture are only ever shown together for the same reply. The captures stay the real white dialog, on paper
// plates in both themes.
// The picks cycle BLOCK, UNKNOWN, SAFE: 10 s after a story started the next one mounts; in the 400 ms before, the
// story eases to 0.6 (data-out) while the next field fades in over the last one, so the next story starts on its own
// field. A click plays that pick, its field fading in as it mounts, and the cycle continues from it.
// The cycle runs only while the hero is on screen (useAlive: not off screen, not in a hidden tab, not paused, never
// with reduced motion); whenever it is not, the frame on screen holds (data-paused). The final frame is the base
// style, so reduced motion shows it at once and the buttons switch picks instantly.
// Nothing here sends a request: the commit card reads the shared feed.
type Pick = "block" | "unknown" | "safe";

const picks: { id: Pick; label: string }[] = [
  { id: "block", label: "BLOCK" },
  { id: "unknown", label: "UNKNOWN" },
  { id: "safe", label: "SAFE" },
];

// What the reply says, every word a field of it: the first sentence of plain_english, or for an incomplete reply its
// last (the first lists the coverage reasons, which the measure line and the record already print); then risk_score,
// or each coverage key below 1 with its value, and the chain.
function saysOf(pick: Pick) {
  const reply = recordedReplies[pick];
  const { incomplete } = verdictOf(reply);
  const sentences = reply.plain_english.split(/(?<=\.) /);
  const measure = incomplete
    ? CHECK_ORDER.filter((key) => reply.coverage[key] < 1).map(
        (key) => `${key} ${reply.coverage[key]}`,
      )
    : [`risk_score ${reply.risk_score}`];
  return {
    sentence: incomplete ? sentences[sentences.length - 1] : sentences[0],
    measure: [...measure, `chain ${reply.chain_id}`].join(" · "),
  };
}

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
    <div className="hero-commit absolute inset-x-3 bottom-3 rounded-lg bg-paper px-4 py-3 text-on-paper shadow-lg">
      <p className="font-mono text-[11px] uppercase leading-4 tracking-[0.08em] text-on-paper-2">
        {label} · live, not the request above
        {record && fetchedAt && ` · fetched ${utc(fetchedAt.getTime() / 1000)}`}
      </p>
      <p className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[13px] leading-5">
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
          <span className="text-on-paper-2">Block </span>
          <span className="hero-tick">{value(record?.observed_block)}</span>
        </span>
        <span>
          <span className="text-on-paper-2">Evidence </span>
          <span className="hero-tick">
            {value(record?.evidence_hash && short(record.evidence_hash))}
          </span>
        </span>
        <span>
          <span className="text-on-paper-2">Token </span>
          {value(record && short(record.subject))}
        </span>
      </p>
    </div>
  );
}

export default function HeroRecord() {
  // pick is the story on stage and field the field it stands on (the next pick's for the last 400 ms of a cycle);
  // from is the field before, which stays under the incoming one while it fades in; run remounts the story, so a click
  // on the pick already shown plays it again.
  const [{ pick, field, from, run }, setStage] = useState<{
    pick: Pick;
    field: Pick;
    from: Pick;
    run: number;
  }>({
    pick: "block",
    field: "block",
    from: "block",
    run: 0,
  });
  const { ref, on, paused, setPaused } = useAlive<HTMLDivElement>();
  const reply = recordedReplies[pick];
  const { label } = verdictOf(reply);
  const says = saysOf(pick);
  const show = (next: Pick) =>
    setStage((stage) => ({
      pick: next,
      field: next,
      from: stage.field,
      run: stage.run + 1,
    }));

  // While the hero is on screen, 9.6 s after the story started it eases to 0.6 opacity (data-out, index.css) as the
  // next pick's field fades in, and at 10 s the next story mounts on it. Stopped before that (paused, off screen, a
  // hidden tab), the stage goes back to the current pick's own field.
  useEffect(() => {
    if (!on) return;
    const element = ref.current!;
    const next =
      picks[(picks.findIndex(({ id }) => id === pick) + 1) % picks.length].id;
    const fade = setTimeout(() => {
      element.dataset.out = "";
      setStage((stage) => ({ ...stage, field: next, from: stage.field }));
    }, 9_600);
    const advance = setTimeout(() => {
      delete element.dataset.out;
      show(next);
    }, 10_000);
    return () => {
      clearTimeout(fade);
      clearTimeout(advance);
      delete element.dataset.out;
      setStage((stage) =>
        stage.field === stage.pick
          ? stage
          : { ...stage, field: stage.pick, from: stage.pick },
      );
    };
  }, [on, run]);

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
              onClick={() => show(id)}
              className={[
                "h-9 rounded-lg border px-3 font-mono text-xs tracking-[0.04em] transition-colors duration-150",
                pick === id
                  ? "border-ink bg-ink text-on-ink"
                  : "border-edge bg-ground text-ink hover:bg-ground-alt",
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
        className="mt-4 grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_380px] lg:gap-8"
      >
        <div className="hero-dim vr-hero min-w-0">
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
          <div className="relative h-[700px] overflow-hidden rounded-lg border border-hairline light:border-edge/40 sm:h-[680px] lg:h-[580px]">
            <div
              aria-hidden="true"
              className={`field-${from} absolute inset-0`}
            />
            <div
              key={field}
              aria-hidden="true"
              className={`hero-field field-${field} absolute inset-0`}
            />
            <div aria-hidden="true" className="hero-light absolute inset-0" />
            <div className="hero-dim absolute inset-0">
              <div className="hero-says absolute inset-x-4 top-4 text-paper">
                <Badge verdict={label.verdict} size="lg" field>
                  {label.text}
                </Badge>
                <p className="mt-3 text-[22px] font-medium leading-[26px] tracking-[-0.01em] max-[359px]:text-[19px] max-[359px]:leading-[23px]">
                  {says.sentence}
                </p>
                <p className="mt-2 font-mono text-[11px] uppercase leading-4 tracking-[0.08em] text-paper/80">
                  {says.measure}
                </p>
              </div>
              <div className="hero-card absolute inset-x-4 top-[176px] rounded-lg bg-paper p-4 text-on-paper shadow-lg">
                <p className="flex justify-between font-mono text-[11px] leading-4 text-on-paper-2">
                  <span>app.example</span>
                  <span>Signature request</span>
                </p>
                <p className="mt-2 text-[15px] font-medium">
                  Approve token spending
                </p>
                <dl className="mt-3 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 font-mono text-xs leading-[18px]">
                  <dt className="text-on-paper-2">Method</dt>
                  <dd>{reply.request.method}</dd>
                  <dt className="text-on-paper-2">Token</dt>
                  <dd>{reply.request.to}</dd>
                  <dt className="text-on-paper-2">Spender</dt>
                  <dd>{reply.request.spender}</dd>
                  <dt className="text-on-paper-2">Chain</dt>
                  <dd>
                    {reply.chain_id} · {reply.network}
                  </dd>
                </dl>
                {/* The card imitates a third-party dialog, so its buttons are constant literals, not our tokens. */}
                <p className="mt-4 grid grid-cols-2 gap-2 text-center text-sm font-medium">
                  <span className="rounded-lg border border-[#D6D5D0] py-2">
                    Reject
                  </span>
                  <span className="rounded-lg bg-[#141414] py-2 text-paper">
                    Sign
                  </span>
                </p>
              </div>
              <div className="absolute inset-x-6 top-[224px] h-[330px]">
                <div className="hero-loading absolute inset-x-0 top-0 overflow-hidden rounded-lg bg-paper shadow-lg">
                  <img
                    src="/hero-overlay-loading.webp"
                    width={490}
                    height={246}
                    alt="The ShieldBot extension's dialog while it checks the request. It reads Analyzing transaction..."
                    className="block w-full h-auto"
                  />
                </div>
                <div className="hero-verdict relative max-h-full overflow-hidden rounded-lg bg-paper shadow-lg after:absolute after:inset-x-0 after:bottom-0 after:h-14 after:bg-gradient-to-t after:from-paper">
                  <Capture pick={pick} />
                </div>
              </div>
              <Commit />
            </div>
          </div>
          <figcaption className="hero-dim mt-3 text-xs leading-[18px] text-secondary">
            {captions[pick]} Recorded examples, not live scans. The signing card
            is an illustration: a placeholder dApp asking to sign the recorded
            call.
          </figcaption>
        </figure>
      </div>
    </div>
  );
}
