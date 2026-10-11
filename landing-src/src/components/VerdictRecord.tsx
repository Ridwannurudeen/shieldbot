import Badge, { type Verdict } from "./Badge";
import CheckRow, { CheckReasons } from "./CheckRow";
import { short, shortenHex, utc } from "../registryFeed";

// VerdictRecord: the page's one way of drawing a verdict. Top to bottom:
//   1. the check-row (CheckRow.tsx): one cell per coverage key in CHECK_ORDER, filled when the check ran,
//      dashed when it ran in part or not at all, each with its key as text and, when the reply gives one,
//      the reason it did not fully run;
//   2. the verdict chip (Badge.tsx: five firewall shapes and the registry's neutral one);
//   3. the reason, one sentence from the reply or the registry;
//   4. the evidence in IBM Plex Mono, joined by a fine magenta rule: recorded time, chain, observed block,
//      publication time, evidence hash, guard outcome.
// Every hex string of 40 or more digits in any prop is shown shortened (0x1234…abcd), so a record never
// prints a full 64-hex hash; tests/test_website_claims.py renders it with one in every field to check.
//
// Props, all real fields of a recorded reply (src/recordedReplies.ts) or of a live API answer. Never pass a
// stand-in value. For every optional field: undefined leaves its line out (the source has no such field);
// null prints "Unavailable" (the source has the field but did not answer, or answered without it).
//   chip          { verdict, label }: the chip's shape and text. The caller maps its vocabulary: an
//                 /api/firewall or /api/scan reply through verdictOf (src/firewallVerdict.ts); a registry
//                 record (LOW, MEDIUM, HIGH, HONEYPOT, UNKNOWN) through registryChip (src/registryVerdict.ts).
//   coverage      reply.coverage. Leave it out for a source with no coverage (a registry record): no row.
//   reasons       reply.coverage_reasons, printed verbatim under the row for each cell not fully run. With no
//                 coverage (an /api/scan reply, whose coverage keys are not the six checks), each served
//                 reason is printed on its own under "Not checked", so an Unknown still says why.
//   reason        reply.plain_english, or the registry's served reason.
//   recordedAt    ISO time a recorded call was sent (hero-overlay-recordings.json sent_at).
//   chain         { id, name } of the reply or record.
//   block         registry observed_block.
//   publishedAt   registry published_at, Unix seconds.
//   evidenceHash  reply or registry evidence_hash; shortened here, so a full hash may be passed.
//   guard         the guard's answer as served or recorded, e.g. "allowed=True, reason=0".
//   source        the provenance line under the record: where the fields came from and when.
//   variant       "full" (hero, figures) or "compact" (a row in a list).
//   animate       play the resolve once on mount (cells fill in order, then the chip, then the body);
//                 the final frame is the base style, so reduced motion shows it at once. Remount (a new
//                 key) to replay.
export interface VerdictRecordProps {
  chip: { verdict: Verdict; label: string };
  coverage?: Partial<Record<string, number | boolean | null>>;
  reasons?: Partial<Record<string, string | null>> | null;
  reason?: string | null;
  recordedAt?: string | null;
  chain?: { id: number; name: string } | null;
  block?: number | null;
  publishedAt?: number | null;
  evidenceHash?: string | null;
  guard?: string | null;
  source?: string;
  variant?: "full" | "compact";
  animate?: boolean;
}

function recordedTime(iso: string) {
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

export default function VerdictRecord({
  chip,
  coverage,
  reasons,
  reason,
  recordedAt,
  chain,
  block,
  publishedAt,
  evidenceHash,
  guard,
  source,
  variant = "full",
  animate = false,
}: VerdictRecordProps) {
  const full = variant === "full";
  const evidence: [string, string | null | undefined][] = [
    [
      "Recorded",
      recordedAt === undefined
        ? undefined
        : recordedAt && recordedTime(recordedAt),
    ],
    [
      "Chain",
      chain === undefined ? undefined : chain && `${chain.id} · ${chain.name}`,
    ],
    [
      "Block",
      block === undefined ? undefined : block === null ? null : String(block),
    ],
    ["Published", publishedAt === undefined ? undefined : utc(publishedAt)],
    [
      "Evidence",
      evidenceHash === undefined
        ? undefined
        : evidenceHash && short(evidenceHash),
    ],
    ["Guard", guard && shortenHex(guard)],
  ];
  const lines = evidence.filter(([, value]) => value !== undefined);
  const served = coverage
    ? []
    : Object.entries(reasons ?? {}).flatMap(([key, text]) =>
        text ? [{ key, reason: text }] : [],
      );

  return (
    <article
      className={[
        "min-w-0 rounded-lg border border-hairline bg-ground",
        animate && "vr-animate",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {coverage && (
        <div
          className={
            full
              ? "border-b border-hairline px-5 py-5 sm:px-7"
              : "border-b border-hairline px-4 py-3"
          }
        >
          {full && (
            <p className="mb-3 font-mono text-[11px] uppercase leading-4 tracking-[0.08em] text-secondary">
              Checks
            </p>
          )}
          <CheckRow coverage={coverage} reasons={reasons} variant={variant} />
        </div>
      )}
      {served.length > 0 && (
        <div
          className={
            full
              ? "border-b border-hairline px-5 py-5 sm:px-7"
              : "border-b border-hairline px-4 py-3"
          }
        >
          <p className="mb-3 font-mono text-[11px] uppercase leading-4 tracking-[0.08em] text-secondary">
            Not checked
          </p>
          <CheckReasons entries={served} full={full} />
        </div>
      )}
      <div className={full ? "px-5 py-5 sm:px-7 sm:py-6" : "px-4 py-3"}>
        <div
          className={
            full
              ? "border-l border-accent pl-4 sm:pl-5"
              : "border-l border-accent pl-3"
          }
        >
          <div className="vr-chip">
            <Badge verdict={chip.verdict} size={full ? "lg" : "md"}>
              {chip.label}
            </Badge>
          </div>
          <div className="vr-body">
            {reason !== undefined && (
              <p
                className={
                  full
                    ? "mt-3 max-w-[40em] text-[17px] leading-[26px] text-ink"
                    : "mt-2 text-sm leading-[21px] text-ink"
                }
              >
                {reason === null ? "Unavailable" : shortenHex(reason)}
              </p>
            )}
            {lines.length > 0 && (
              <dl
                className={
                  full
                    ? "mt-4 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-5 gap-y-1.5 font-mono text-[13px] leading-5"
                    : "mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs leading-[18px]"
                }
              >
                {lines.map(([label, value]) => (
                  <div
                    key={label}
                    className={full ? "contents" : "flex gap-1.5"}
                  >
                    <dt
                      className={
                        full
                          ? "relative uppercase tracking-[0.06em] text-secondary before:absolute before:-left-4 before:top-2.5 before:h-px before:w-2.5 before:bg-accent sm:before:-left-5 sm:before:w-3"
                          : "uppercase tracking-[0.06em] text-secondary"
                      }
                    >
                      {label}
                    </dt>
                    <dd className="min-w-0 text-ink [overflow-wrap:anywhere]">
                      {value ?? "Unavailable"}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        </div>
        {source && (
          <p
            className={
              full
                ? "vr-body mt-4 text-xs leading-[18px] text-secondary"
                : "vr-body mt-2 text-xs leading-[18px] text-secondary"
            }
          >
            {source}
          </p>
        )}
      </div>
    </article>
  );
}
