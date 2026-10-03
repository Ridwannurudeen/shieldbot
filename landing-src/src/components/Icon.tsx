import type { ReactNode } from "react";

export type IconName = "shield" | "check" | "cross" | "question" | "info" | "search" | "pen" | "link" | "code" | "chat" | "bot" | "copy" | "external" | "chevron" | "pause" | "play" | "menu" | "close" | "grid" | "sun" | "moon";

const PATHS: Record<IconName, ReactNode> = {
  shield: <><path d="M12 1.5 3 6v6c0 5.8 3.84 11.21 9 12 5.16-.79 9-6.2 9-12V6l-9-4.5Z" /><path d="m9 12 2.25 2.25L15 9.75" /></>,
  check: <path d="m5 12 4 4L19 6" />,
  cross: <path d="m6 6 12 12M18 6 6 18" />,
  question: <><path d="M9.1 9a3 3 0 1 1 5.8 1c0 2-2.9 2.1-2.9 4" /><path d="M12 18h.01" /></>,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></>,
  search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></>,
  pen: <><path d="M12 20h9" /><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" /></>,
  link: <><path d="M10 13a5 5 0 0 0 7.07.07l2-2a5 5 0 0 0-7.07-7.07l-1.14 1.14" /><path d="M14 11a5 5 0 0 0-7.07-.07l-2 2A5 5 0 0 0 12 20l1.14-1.14" /></>,
  code: <path d="m8 7-5 5 5 5M16 7l5 5-5 5" />,
  chat: <path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12Z" />,
  bot: <><rect x="7" y="7" width="10" height="10" rx="1" /><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4" /></>,
  copy: <><rect x="9" y="9" width="10" height="10" rx="1" /><path d="M15 9V5H5v10h4" /></>,
  external: <><path d="M14 5h5v5M19 5l-8 8" /><path d="M19 14v5H5V5h5" /></>,
  chevron: <path d="m8 10 4 4 4-4" />,
  pause: <path d="M9 5v14M15 5v14" />,
  play: <path d="m9 5 10 7-10 7Z" />,
  menu: <path d="M4 6h16M4 12h16M4 18h16" />,
  close: <path d="m6 6 12 12M18 6 6 18" />,
  grid: <><rect x="4" y="4" width="6" height="6" /><rect x="14" y="4" width="6" height="6" /><rect x="4" y="14" width="6" height="6" /><rect x="14" y="14" width="6" height="6" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" /></>,
  moon: <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" />,
};

export default function Icon({ name, size = 20, className }: { name: IconName; size?: 16 | 20 | 24; className?: string }) {
  return <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={className}>{PATHS[name]}</svg>;
}

export function Mark({ size = 28, className }: { size?: number; className?: string }) {
  return <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={className}><path d="M12 1.5 3 6v6c0 5.8 3.84 11.21 9 12 5.16-.79 9-6.2 9-12V6l-9-4.5Z" fill="currentColor" /><path d="m9 12 2.25 2.25L15 9.75" className="text-onfill" /></svg>;
}
