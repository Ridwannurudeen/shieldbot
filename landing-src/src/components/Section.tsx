import type { ReactNode } from "react";

export default function Section({
  id,
  title,
  level = "h2",
  children,
}: {
  id: string;
  title: string;
  level?: "h1" | "h2";
  children: ReactNode;
}) {
  const Heading = level;
  const titleId = `${id}-title`;

  return (
    <section
      id={id}
      aria-labelledby={titleId}
      className={
        level === "h1"
          ? "pt-20 pb-12 md:pt-20 md:pb-11"
          : "py-16 md:py-24"
      }
    >
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <Heading
          id={titleId}
          className={
            level === "h1"
              ? "text-display-sm text-ink md:text-display"
              : "text-h2-sm text-ink md:text-h2"
          }
        >
          {title}
        </Heading>
        <div className={level === "h1" ? "mt-8 md:mt-6" : "mt-10 md:mt-12"}>
          {children}
        </div>
      </div>
    </section>
  );
}
