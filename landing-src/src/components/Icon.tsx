import type { ReactNode } from "react";

export type IconName =
  | "check"
  | "copy"
  | "chevron"
  | "menu"
  | "close"
  | "sun"
  | "moon";

const PATHS: Record<IconName, ReactNode> = {
  check: (
    <path d="M13 24 4 15 5.414 13.586 13 21.171 26.586 7.586 28 9 13 24z" />
  ),
  copy: (
    <>
      <path d="M28,10V28H10V10H28m0-2H10a2,2,0,0,0-2,2V28a2,2,0,0,0,2,2H28a2,2,0,0,0,2-2V10a2,2,0,0,0-2-2Z" />
      <path d="M4,18H2V4A2,2,0,0,1,4,2H18V4H4Z" />
    </>
  ),
  chevron: <path d="M16 22 6 12 7.4 10.6 16 19.2 24.6 10.6 26 12z" />,
  menu: (
    <>
      <path d="M4 6H28V8H4z" />
      <path d="M4 24H28V26H4z" />
      <path d="M4 12H28V14H4z" />
      <path d="M4 18H28V20H4z" />
    </>
  ),
  close: (
    <path d="M17.4141 16 24 9.4141 22.5859 8 16 14.5859 9.4143 8 8 9.4141 14.5859 16 8 22.5859 9.4143 24 16 17.4141 22.5859 24 24 22.5859 17.4141 16z" />
  ),
  sun: (
    <g fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round">
      <circle cx="16" cy="16" r="8" />
      <path d="M16 2v2M16 28v2M2 16h2M28 16h2M6.1 6.1l1.4 1.4M24.5 24.5l1.4 1.4M6.1 25.9l1.4-1.4M24.5 7.5l1.4-1.4" />
    </g>
  ),
  moon: (
    <path
      d="M27 19.5A11.5 11.5 0 1 1 12.5 5a9 9 0 0 0 14.5 14.5z"
      fill="none"
      stroke="currentColor"
      strokeWidth="4"
      strokeLinejoin="round"
    />
  ),
};

export default function Icon({
  name,
  size = 20,
  className,
}: {
  name: IconName;
  size?: 16 | 20 | 24;
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 32 32"
      width={size}
      height={size}
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      {PATHS[name]}
    </svg>
  );
}
