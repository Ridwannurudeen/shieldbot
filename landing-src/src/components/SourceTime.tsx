export default function SourceTime({
  href,
  at,
  className = "",
}: {
  href: string;
  at: Date | null;
  className?: string;
}) {
  if (!at) return null;
  const time = at.toISOString().slice(11, 16);
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={`inline-flex min-h-11 items-center font-mono text-xs text-secondary underline decoration-hairline-strong underline-offset-4 hover:text-ink ${className}`}
      aria-label={`Source fetched at ${time} UTC`}
    >
      {time} UTC
    </a>
  );
}
