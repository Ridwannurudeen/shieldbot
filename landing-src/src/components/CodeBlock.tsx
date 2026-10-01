import { useRef, useState } from "react";
import Icon from "./Icon";

export default function CodeBlock({ code, label }: { code: string; label?: string }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const resetTimer = useRef<number | undefined>(undefined);

  async function copyCode() {
    window.clearTimeout(resetTimer.current);

    try {
      await navigator.clipboard.writeText(code);
      setCopyState("copied");
      resetTimer.current = window.setTimeout(() => setCopyState("idle"), 1500);
    } catch {
      setCopyState("failed");
      resetTimer.current = window.setTimeout(() => setCopyState("idle"), 2000);
    }
  }

  return (
    <div>
      {label && <p className="text-[13px] text-muted">{label}</p>}
      <div className="relative rounded-2xl border border-line bg-surface-3">
        <button
          type="button"
          aria-label="Copy the commands"
          onClick={copyCode}
          className="absolute right-3 top-3 inline-flex h-8 min-w-8 items-center justify-center rounded-lg px-2 text-muted hover:bg-surface hover:text-ink"
        >
          {copyState === "failed" ? "Could not copy" : <Icon name={copyState === "copied" ? "check" : "copy"} size={16} />}
        </button>
        <pre
          tabIndex={0}
          aria-label="Command block"
          className="overflow-x-auto p-4 pr-14 font-mono text-[13px] leading-relaxed text-body whitespace-pre"
        >
          {code}
        </pre>
      </div>
      <p className="mt-2 text-[13px] text-caution-fg" aria-live="polite">
        {copyState === "copied" ? "Commands copied" : copyState === "failed" ? "Could not copy" : ""}
      </p>
    </div>
  );
}
