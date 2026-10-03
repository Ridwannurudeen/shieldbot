import type { ReactNode } from "react";
import Icon, { type IconName } from "./Icon";

export default function FeatureCard({
  title,
  children,
  icon,
  number,
  link,
}: {
  title: string;
  children: ReactNode;
  icon?: IconName;
  number?: string;
  link?: { label: string; href: string };
}) {
  const external = link?.href.startsWith("http");

  return (
    <div className="rounded-2xl border border-line bg-surface p-6 shadow-sm transition-colors hover:border-line-strong">
      {(icon || number) && (
        <div className="flex items-center justify-between">
          {icon ? <Icon name={icon} size={24} className="text-emerald" /> : <span />}
          {number && <span className="font-mono text-xs text-emerald">{number}</span>}
        </div>
      )}
      <h3 className={`${icon || number ? "mt-4 " : ""}text-lg font-semibold text-ink`}>{title}</h3>
      <div className="mt-2 text-sm leading-relaxed text-body">{children}</div>
      {link && (
        <a
          className="inline-flex min-h-[44px] items-center text-emerald underline underline-offset-4 hover:text-emerald-deep"
          href={link.href}
          {...(external ? { target: "_blank", rel: "noopener noreferrer" } : {})}
        >
          {link.label}
        </a>
      )}
    </div>
  );
}
