import type { ReactNode } from "react";

export default function Button(props: { variant?: "primary" | "secondary" | "ghost"; size?: "md" | "sm"; href?: string; onClick?: () => void; type?: "button" | "submit"; disabled?: boolean; className?: string; children: ReactNode; ariaLabel?: string; ariaPressed?: boolean; ariaExpanded?: boolean; ariaControls?: string }) {
  const { variant = "primary", size = "md", href, onClick, type, disabled, className, children, ariaLabel, ariaPressed, ariaExpanded, ariaControls } = props;
  const classes = [
    "inline-flex items-center justify-center gap-2 rounded-lg font-semibold transition-colors duration-150 ease-out disabled:opacity-50 disabled:cursor-not-allowed",
    size === "md" ? "h-12 px-6 text-[15px]" : "h-10 px-4 text-sm",
    variant === "primary" && "bg-emerald text-onfill shadow-button hover:bg-emerald-deep active:bg-emerald-deep active:translate-y-px active:shadow-none",
    variant === "secondary" && "bg-surface text-ink border border-line-strong shadow-sm hover:border-ink",
    variant === "ghost" && "bg-transparent text-muted hover:bg-surface-3 hover:text-ink",
    className,
  ].filter(Boolean).join(" ");

  if (href) {
    const external = href.startsWith("http");
    return <a href={href} onClick={onClick} aria-label={ariaLabel} aria-pressed={ariaPressed} aria-expanded={ariaExpanded} aria-controls={ariaControls} className={classes} {...(external ? { target: "_blank", rel: "noopener noreferrer" } : {})}>{children}</a>;
  }

  return <button type={type ?? "button"} onClick={onClick} disabled={disabled} aria-label={ariaLabel} aria-pressed={ariaPressed} aria-expanded={ariaExpanded} aria-controls={ariaControls} className={classes}>{children}</button>;
}
