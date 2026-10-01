export default function SectionHeader({ id, eyebrow, title, lead }: { id: string; eyebrow: string; title: string; lead?: string }) {
  return <div className="max-w-3xl"><p className="text-xs font-bold uppercase tracking-[0.12em] text-emerald">{eyebrow}</p><h2 id={id} className="mt-3 text-h2-sm md:text-h2 text-ink">{title}</h2>{lead && <p className="mt-4 text-[17px] md:text-lg leading-relaxed text-body">{lead}</p>}</div>;
}
