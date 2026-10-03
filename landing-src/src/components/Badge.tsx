import type { ReactNode } from "react";

export type Verdict = "safe" | "caution" | "high" | "block" | "unknown";

export default function Badge({
  verdict,
  variant = "soft",
  size = "md",
  children,
  className,
}: {
  verdict: Verdict;
  variant?: "soft" | "solid";
  size?: "md" | "lg";
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
          safe: "bg-safe-fg text-onfill border-safe-fg",
          caution: "bg-caution-fg text-onfill border-caution-fg",
          high: "bg-high-fg text-onfill border-high-fg",
          block: "bg-block-fg text-onfill border-block-fg",
          unknown: "bg-unknown-hatch-solid text-white border-unknown-line",
        };

  return (
    <span
      className={[
        size === "md"
          ? "inline-flex items-center rounded-md px-2.5 py-1 text-xs font-bold uppercase tracking-[0.08em] border"
          : "inline-flex items-center rounded-lg px-3 py-1.5 text-lg min-[390px]:text-xl sm:text-2xl min-[1024px]:text-xl min-[1100px]:text-2xl font-extrabold uppercase tracking-[0.02em] leading-[1.15] border",
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
