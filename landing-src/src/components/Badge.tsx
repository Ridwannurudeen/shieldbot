import type { ReactNode } from "react";

export type Verdict = "safe" | "caution" | "high" | "block" | "unknown";

export default function Badge({
  verdict,
  variant = "soft",
  children,
  className,
}: {
  verdict: Verdict;
  variant?: "soft" | "solid";
  children: ReactNode;
  className?: string;
}) {
  const tones =
    variant === "soft"
      ? {
          safe: "bg-safe-tint text-safe-fg border-safe-line",
          caution: "bg-caution-tint text-caution-fg border-caution-line",
          high: "bg-high-tint text-high-fg border-high-line",
          block: "bg-block-tint text-block-fg border-block-line",
          unknown: "bg-unknown-hatch text-unknown-fg border-unknown-line",
        }
      : {
          safe: "bg-safe-fg text-white border-safe-fg",
          caution: "bg-caution-fg text-white border-caution-fg",
          high: "bg-high-fg text-white border-high-fg",
          block: "bg-block-fg text-white border-block-fg",
          unknown: "bg-unknown-hatch-solid text-white border-unknown-line",
        };

  return (
    <span
      className={[
        "inline-flex items-center rounded-md px-2.5 py-1 text-xs font-bold uppercase tracking-[0.08em] border",
        tones[verdict],
        className,
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {children}
    </span>
  );
}
