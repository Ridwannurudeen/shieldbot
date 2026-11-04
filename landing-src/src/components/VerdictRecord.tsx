import Badge, { type Verdict } from "./Badge";
import { CheckReasons } from "./CheckRow";
import { short, utc } from "../registryFeed";

export interface VerdictRecordProps {
  chip: { verdict: Verdict; label: string };
  reasons?: Partial<Record<string, string | null>> | null;
  chain?: { id: number; name: string } | null;
  block?: number | null;
  publishedAt?: number | null;
  evidenceHash?: string | null;
}

export default function VerdictRecord({
  chip,
  reasons,
  chain,
  block,
  publishedAt,
  evidenceHash,
}: VerdictRecordProps) {
  const evidence: [string, string | null | undefined][] = [
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
  ];
  const lines = evidence.filter(([, value]) => value !== undefined);
  const served = Object.entries(reasons ?? {}).flatMap(([key, text]) =>
    text ? [{ key, reason: text }] : [],
  );

  return (
    <article className="min-w-0 rounded-md border border-hairline bg-ground">
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
