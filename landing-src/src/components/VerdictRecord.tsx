import Badge, { type Verdict } from "./Badge";
import CheckRow, { CheckReasons } from "./CheckRow";
import { short, shortenHex, utc } from "../registryFeed";

export interface VerdictRecordProps {
  request?: string;
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
}

function recordedTime(iso: string) {
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

export default function VerdictRecord({
  request,
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
}: VerdictRecordProps) {
  const evidence: [string, string | null | undefined][] = [
    [
      "Recorded",
      recordedAt === undefined
        ? undefined
        : recordedAt && recordedTime(recordedAt),
    ],
    ["Chain", chain === undefined ? undefined : chain && `${chain.id} · ${chain.name}`],
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
    <article className="min-w-0 rounded-md border border-hairline bg-ground">
      {coverage && (
        <div className="border-b border-hairline px-4 py-4 sm:px-6 sm:py-5">
          {request && (
            <p className="mb-4 break-words font-mono text-xs leading-5 text-ink">
              <span className="mr-3 text-[11px] uppercase tracking-[0.08em] text-secondary">
                Request
              </span>
              {shortenHex(request)}
            </p>
          )}
          <p className="mb-3 font-mono text-[11px] uppercase leading-4 tracking-[0.08em] text-secondary">
            Checks
          </p>
          <CheckRow coverage={coverage} reasons={reasons} />
        </div>
      )}
      {served.length > 0 && (
        <div className="border-b border-hairline px-4 py-4 sm:px-6 sm:py-5">
          <p className="mb-3 font-mono text-[11px] uppercase leading-4 tracking-[0.08em] text-secondary">
            Not checked
          </p>
          <CheckReasons entries={served} />
        </div>
      )}
      <div className="px-4 py-4 sm:px-6 sm:py-5">
        <div className="border-l border-accent pl-4 sm:pl-5">
          <Badge verdict={chip.verdict} size="lg">
            {chip.label}
          </Badge>
          {reason !== undefined && (
            <p className="mt-3 max-w-[40em] text-base leading-6 text-ink">
              {reason === null ? "Unavailable" : shortenHex(reason)}
            </p>
          )}
          {lines.length > 0 && (
            <dl className="mt-4 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-5 gap-y-1.5 font-mono text-xs leading-5">
              {lines.map(([label, value]) => (
                <div key={label} className="contents">
                  <dt className="uppercase tracking-[0.06em] text-secondary">
                    {label}
                  </dt>
                  <dd className="min-w-0 break-words text-ink">
                    {value ?? "Unavailable"}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      </div>
    </article>
  );
}
