import { useRef, useState } from "react";
import Icon from "./Icon";

export default function CodeBlock({
  code,
  label,
}: {
  code: string;
  label?: string;
}) {
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
    <div className="rounded-md border border-hairline bg-ground-alt">
      <div className="flex min-h-11 items-center justify-between gap-3 px-3">
        {label ? <p className="text-xs text-secondary">{label}</p> : <span />}
        <button
          type="button"
          aria-label="Copy the code"
          onClick={copyCode}
          className="inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-md text-secondary hover:bg-ground hover:text-ink"
        >
          {copyState === "failed" ? (
            <span className="text-xs font-medium">Error</span>
          ) : (
            <Icon name={copyState === "copied" ? "check" : "copy"} size={16} />
          )}
        </button>
      </div>
      <pre
        tabIndex={0}
        aria-label="Code block"
        className="whitespace-pre-wrap break-words px-4 pb-4 font-mono text-xs leading-5 text-ink"
      >
        {code}
      </pre>
      {copyState === "failed" && (
        <p className="px-4 pb-3 text-xs text-ink" role="status">
          Could not copy. Select the code and copy it by hand.
        </p>
      )}
      <p className="sr-only" aria-live="polite">
        {copyState === "copied" ? "Code copied" : ""}
      </p>
    </div>
  );
}
