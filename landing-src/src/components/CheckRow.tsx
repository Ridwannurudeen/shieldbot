import type { CSSProperties } from "react";
import { shortenHex } from "../registryFeed";

// The check-row: one square cell per coverage key of a reply, always in this order (the order the API
// itself serves the keys in). The order is fixed here, never taken from the object, so every row on the
// page lines up; tests/test_website_claims.py pins it.
export const CHECK_ORDER = [
  "structural",
  "market",
  "behavioral",
  "honeypot",
  "intent",
  "signature",
] as const;

export type CheckKey = (typeof CHECK_ORDER)[number];

// A coverage value of 1 means the check ran fully; between 0 and 1 it ran in part; 0 it did not run. A key
// the reply does not carry, or carries as null, reads Unavailable, never 0. Booleans count as 1 or 0, as in the
// overlay's rule.
type CellState = "ran" | "partial" | "none" | "absent";
type Value = number | boolean | null | undefined;

function stateOf(value: Value): CellState {
  if (value === undefined || value === null) return "absent";
  const n = Number(value);
  if (n >= 1) return "ran";
  return n > 0 ? "partial" : "none";
}

function stateText(state: CellState, value: Value) {
  if (state === "ran") return "ran";
  if (state === "partial") return `ran in part (${Number(value)})`;
  if (state === "none") return "did not run (0)";
  return "Unavailable";
}

// The served reason for each check that did not fully run, verbatim, with long hex shortened.
export function CheckReasons({
  entries,
  full,
}: {
  entries: { key: string; reason: string }[];
  full: boolean;
}) {
  return (
    <dl
      className={
        full
          ? "vr-body grid gap-y-1.5 font-mono text-xs leading-[18px] sm:grid-cols-[max-content_1fr] sm:gap-x-4"
          : "vr-body grid gap-y-1 font-mono text-[11px] leading-4 sm:grid-cols-[max-content_1fr] sm:gap-x-3"
      }
    >
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
  variant,
}: {
  coverage: Partial<Record<string, number | boolean | null>>;
  reasons?: Partial<Record<string, string | null>> | null;
  variant: "full" | "compact";
}) {
  const cells = CHECK_ORDER.map((key) => {
    const value = coverage[key];
    const state = stateOf(value);
    return {
      key,
      value,
      state,
      reason: state === "ran" ? null : reasons?.[key],
    };
  });
  const full = variant === "full";
  const unfilled = cells.flatMap(({ key, reason }) =>
    reason ? [{ key, reason }] : [],
  );

  return (
    <div>
      <ol
        className={
          full
            ? "grid grid-cols-3 gap-x-2 gap-y-3 sm:grid-cols-[repeat(6,minmax(0,96px))] sm:gap-x-3"
            : "flex gap-1"
        }
      >
        {cells.map(({ key, value, state }, i) => (
          <li
            key={key}
            className={full ? "flex min-w-0 flex-col items-start gap-1.5" : ""}
            title={full ? undefined : `${key}: ${stateText(state, value)}`}
          >
            <span
              aria-hidden="true"
              className={[
                "relative block flex-none rounded-[2px] border",
                // Unavailable is the ink outline of the legend (Mechanism.tsx); the other states draw their own edge
                // over a hairline.
                state === "absent"
                  ? "border-ink bg-ground"
                  : "border-hairline-strong",
                full ? "h-7 w-7 sm:h-8 sm:w-8" : "h-3 w-3",
              ].join(" ")}
            >
              <span
                className={[
                  "vr-cell absolute -inset-px rounded-[2px]",
                  state === "ran" && "bg-ink",
                  (state === "partial" || state === "none") &&
                    "border border-dashed border-ink",
                ]
                  .filter(Boolean)
                  .join(" ")}
                style={{ "--i": i } as CSSProperties}
              >
                {state === "partial" && (
                  <span
                    className="absolute inset-x-0 bottom-0 bg-unknown"
                    style={{ height: `${Number(value) * 100}%` }}
                  />
                )}
              </span>
            </span>
            <span
              className={
                full
                  ? "font-mono text-[11px] leading-4 text-secondary"
                  : "sr-only"
              }
            >
              {key}
              {full ? (
                state !== "ran" && (
                  <span className="text-ink">
                    {" "}
                    {state === "absent" ? "Unavailable" : Number(value)}
                  </span>
                )
              ) : (
                <>: {stateText(state, value)}</>
              )}
              {full && (
                <span className="sr-only">: {stateText(state, value)}</span>
              )}
            </span>
          </li>
        ))}
      </ol>
      {unfilled.length > 0 && (
        <div className={full ? "mt-4" : "mt-2"}>
          <CheckReasons entries={unfilled} full={full} />
        </div>
      )}
    </div>
  );
}
