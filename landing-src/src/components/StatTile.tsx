export default function StatTile({
  value,
  label,
  state = "ready",
}: {
  value: string;
  label: string;
  state?: "ready" | "loading" | "unavailable";
}) {
  return (
    <div className="rounded-2xl border border-line bg-surface p-5 shadow-sm">
      <div className="font-mono text-2xl md:text-[28px] font-bold leading-none tracking-tight text-ink tabular-nums">
        {state === "loading" ? "…" : state === "unavailable" ? "—" : value}
      </div>
      <div className="mt-2 text-[13px] text-muted">{label}</div>
    </div>
  );
}
