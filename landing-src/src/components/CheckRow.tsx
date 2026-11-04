import { shortenHex } from "../registryFeed";

export const CHECK_ORDER = [
  "structural",
  "market",
  "behavioral",
  "honeypot",
  "intent",
  "signature",
] as const;

type CellState = "ran" | "partial" | "none" | "absent";
type Value = number | boolean | null | undefined;

function stateOf(value: Value): CellState {
  if (value === undefined || value === null) return "absent";
  const number = Number(value);
  if (number >= 1) return "ran";
  return number > 0 ? "partial" : "none";
}

function stateText(state: CellState) {
  if (state === "ran") return "ran";
  if (state === "partial") return "partial";
  if (state === "none") return "did not run";
  return "Unavailable";
}

export function CheckReasons({
  entries,
}: {
  entries: { key: string; reason: string }[];
}) {
  return (
    <dl className="grid gap-y-1.5 font-mono text-xs leading-[18px] sm:grid-cols-[max-content_1fr] sm:gap-x-4">
      {entries.map(({ key, reason }) => (
        <div key={key} className="contents">
          <dt className="text-secondary">{key}</dt>
          <dd className="min-w-0 text-ink [overflow-wrap:anywhere]">
            {shortenHex(reason)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export default function CheckRow({
  coverage,
  reasons,
}: {
  coverage: Partial<Record<string, number | boolean | null>>;
  reasons?: Partial<Record<string, string | null>> | null;
}) {
  const cells = CHECK_ORDER.map((key) => {
    const value = coverage[key];
    const state = stateOf(value);
    return { key, value, state, reason: state === "ran" ? null : reasons?.[key] };
  });
  const unfilled = cells.flatMap(({ key, reason }) =>
    reason ? [{ key, reason }] : [],
  );

  return (
    <div>
      <ol className="grid grid-cols-3 gap-x-2 gap-y-3 sm:grid-cols-6 sm:gap-x-3">
        {cells.map(({ key, value, state }) => (
          <li key={key} className="flex min-w-0 flex-col items-start gap-1.5">
            <span
              aria-hidden="true"
              className={`h-7 w-7 rounded-[2px] border sm:h-8 sm:w-8 ${
                state === "ran"
                  ? "border-ink bg-ink"
                  : state === "absent"
                    ? "border-ink bg-ground"
                    : "border-dashed border-ink"
              }`}
            />
            <span className="font-mono text-[11px] leading-4 text-secondary">
              {key}
              <span className="mt-1 block text-ink">{stateText(state)}</span>
            </span>
          </li>
        ))}
      </ol>
      {unfilled.length > 0 && (
        <div className="mt-4">
          <CheckReasons entries={unfilled} />
        </div>
      )}
    </div>
  );
}
