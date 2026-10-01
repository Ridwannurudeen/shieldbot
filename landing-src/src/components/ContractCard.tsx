import { useRef, useState } from "react";
import Icon from "./Icon";

export default function ContractCard({
  name,
  role,
  address,
  links,
}: {
  name: string;
  role: string;
  address: string;
  links: { label: string; href: string }[];
}) {
  const [copied, setCopied] = useState(false);
  const resetTimer = useRef<number | undefined>(undefined);
  const short = `${address.slice(0, 6)}…${address.slice(-4)}`;

  async function copyAddress() {
    window.clearTimeout(resetTimer.current);
    await navigator.clipboard.writeText(address);
    setCopied(true);
    resetTimer.current = window.setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="rounded-2xl border border-line bg-surface p-6">
      <h3 className="font-mono text-sm font-bold text-ink">{name}</h3>
      <p className="mt-2 text-sm text-body">{role}</p>
      <div className="mt-4 flex items-center gap-2 font-mono text-[13px] text-body">
        <span className="lg:hidden">{short}</span>
        <span className="hidden lg:inline break-all">{address}</span>
        <button
          type="button"
          aria-label="Copy the address"
          onClick={copyAddress}
          className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-muted hover:bg-surface-3 hover:text-ink"
        >
          <Icon name={copied ? "check" : "copy"} size={16} />
        </button>
        <span className="sr-only" aria-live="polite">
          {copied ? "Address copied" : ""}
        </span>
      </div>
      <p className="mt-3 text-[13px] text-muted">Deployed 27 September 2026</p>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[13px]">
        {links.map((link) => (
          <a
            key={link.href}
            className="text-emerald underline underline-offset-4 hover:text-emerald-deep"
            href={link.href}
            target="_blank"
            rel="noopener noreferrer"
          >
            {link.label}
          </a>
        ))}
      </div>
    </div>
  );
}
