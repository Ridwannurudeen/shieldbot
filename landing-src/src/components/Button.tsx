import type { ReactNode } from "react";

export default function Button(props: { variant?: "primary" | "secondary" | "ghost"; size?: "md" | "sm"; href?: string; onClick?: () => void; type?: "button" | "submit"; disabled?: boolean; className?: string; children: ReactNode; ariaLabel?: string; ariaPressed?: boolean; ariaExpanded?: boolean; ariaControls?: string }) {
  const { variant = "primary", size = "md", href, onClick, type, disabled, className, children, ariaLabel, ariaPressed, ariaExpanded, ariaControls } = props;
  const classes = [
    "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors duration-150 ease-out disabled:opacity-50 disabled:cursor-not-allowed",
    size === "md" ? "h-11 px-5 text-[15px]" : "h-10 px-4 text-sm",
    variant === "primary" && "bg-accent text-on-accent shadow-button hover:bg-accent-hover active:bg-accent-hover",
    variant === "secondary" && "bg-ground text-ink border border-hairline-strong shadow-sm hover:bg-ground-alt",
    variant === "ghost" && "bg-transparent text-secondary hover:bg-ground-alt hover:text-ink",
    className,
  ].filter(Boolean).join(" ");

  if (href) {
    const external = href.startsWith("http");
    return <a href={href} onClick={onClick} aria-label={ariaLabel} aria-pressed={ariaPressed} aria-expanded={ariaExpanded} aria-controls={ariaControls} className={classes} {...(external ? { target: "_blank", rel: "noopener noreferrer" } : {})}>{children}</a>;
  }

  return <button type={type ?? "button"} onClick={onClick} disabled={disabled} aria-label={ariaLabel} aria-pressed={ariaPressed} aria-expanded={ariaExpanded} aria-controls={ariaControls} className={classes}>{children}</button>;
}

// Pause and play for a part of the page that keeps moving (useAlive, src/reading.ts); hidden with reduced motion,
// where nothing moves.
export function PauseButton({ paused, setPaused }: { paused: boolean; setPaused: (paused: boolean) => void }) {
  return (
    <button type="button" onClick={() => setPaused(!paused)} className="h-9 rounded-lg border border-hairline-strong bg-ground px-3 font-mono text-xs text-ink transition-colors duration-150 hover:bg-ground-alt motion-reduce:hidden">
      {paused ? "Play motion" : "Pause motion"}
    </button>
  );
}
