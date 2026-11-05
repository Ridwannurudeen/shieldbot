import { useEffect, useRef, useState } from "react";
import Icon from "./Icon";

export default function CodeBlock({ code, label }: { code: string; label?: string }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const resetTimer = useRef<number | undefined>(undefined);
  // Long lines scroll sideways on a narrow screen; a line under the block says so while any line is cut off.
  const pre = useRef<HTMLPreElement>(null);
  const [overflows, setOverflows] = useState(false);

  useEffect(() => {
    const element = pre.current as HTMLPreElement;
    const measure = () => setOverflows(element.scrollWidth > element.clientWidth);
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

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
      <div className="rounded-2xl border border-hairline bg-ground-alt">
        <div className="flex h-11 items-center justify-between gap-3 px-3">
          {label ? <p className="text-[13px] text-secondary">{label}</p> : <span />}
          <button
            type="button"
            aria-label="Copy the commands"
            onClick={copyCode}
            className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-secondary hover:bg-ground hover:text-ink"
          >
            {copyState === "failed" ? (
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="text-ink"><path d="M12 3 2.5 20h19L12 3Z" /><path d="M12 9v4M12 17h.01" /></svg>
            ) : <Icon name={copyState === "copied" ? "check" : "copy"} size={16} />}
          </button>
        </div>
        <pre
          ref={pre}
          tabIndex={0}
          aria-label="Command block"
          className="overflow-x-auto p-4 pt-3 font-mono text-[13px] leading-relaxed text-ink whitespace-pre"
        >
          {code}
        </pre>
      </div>
      {overflows && (
        <p className="mt-2 flex items-center gap-1.5 text-[13px] text-secondary">
          Scroll the block sideways to read each line in full
          <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
            <path d="M3 8h10M9 4l4 4-4 4" fill="none" stroke="currentColor" strokeWidth="1.6" />
          </svg>
        </p>
      )}
      {copyState === "failed" && <p className="mt-2 text-[13px] text-ink" role="status">Could not copy. Select the commands and copy them by hand.</p>}
      <p className="sr-only" aria-live="polite">{copyState === "copied" ? "Commands copied" : ""}</p>
    </div>
  );
}
