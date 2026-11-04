import type { ReactNode } from "react";

export type Verdict = "safe" | "caution" | "high" | "block" | "unknown" | "registry";

// Five verdicts on three hues, told apart by shape as well as colour: BLOCK a solid red fill, HIGH RISK a
// heavy red edge with "!", CAUTION a grey hairline with "!", SAFE a green hairline, UNKNOWN a solid grey
// fill with a dashed edge and "?".
// A sixth shape, registry, is not a firewall verdict: it draws a registry record's LOW or MEDIUM (src/registryVerdict.ts)
// as a plain grey edge on a raised fill, no glyph and no green. The shapes are the same in both themes; only the
// token values change.
const shapes: Record<Verdict, { classes: string; glyph?: string }> = {
  block: { classes: "bg-block text-white border border-block" },
  high: { classes: "text-block-text border-2 border-block-edge", glyph: "!" },
  caution: { classes: "text-ink border border-edge", glyph: "!" },
  safe: { classes: "text-safe-text border border-safe" },
  unknown: { classes: "bg-unknown text-on-unknown border border-dashed border-on-unknown", glyph: "?" },
  registry: { classes: "bg-ground-alt text-ink border border-edge" },
};

export default function Badge({
  verdict,
  size = "md",
  children,
  className,
}: {
  verdict: Verdict;
  size?: "md" | "lg";
  children: ReactNode;
  className?: string;
}) {
  const { glyph } = shapes[verdict];
  const classes = shapes[verdict].classes;
  return (
    <span
      className={[
        "inline-flex items-center gap-1 rounded font-medium",
        size === "md" ? "px-2 py-0.5 text-xs tracking-[0.04em]" : "px-3 py-1.5 text-lg sm:text-xl leading-[1.15]",
        classes,
        className,
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {glyph && <span aria-hidden="true">{glyph}</span>}
      {children}
    </span>
  );
}
