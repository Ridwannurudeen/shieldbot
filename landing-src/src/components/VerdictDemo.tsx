import { useEffect, useRef, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import Badge from "./Badge";
import Icon, { Mark, type IconName } from "./Icon";
import { DEMO_TIMING, SCENES, type RowState } from "./verdictScenes";

const rowIcons: Record<RowState, IconName> = {
  ok: "check",
  fail: "cross",
  unmeasured: "question",
  info: "info",
};

const rowTones: Record<RowState, string> = {
  ok: "bg-emerald text-white",
  fail: "bg-block-fg text-white",
  unmeasured: "bg-unknown-hatch text-unknown-fg border border-unknown-line",
  info: "bg-surface-3 text-muted",
};

const verdictTones = {
  block: "bg-block-tint border-block-line",
  safe: "bg-safe-tint border-safe-line",
  unknown: "bg-unknown-hatch border-unknown-line",
};

export default function VerdictDemo() {
  const [sceneIndex, setSceneIndex] = useState(0);
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [inView, setInView] = useState(false);
  const reduced = useReducedMotion();
  const ref = useRef<HTMLElement>(null);
  const scene = SCENES[sceneIndex];
  const completeStep = scene.rows.length + 1;
  const visibleStep = reduced ? completeStep : step;
  const verdictShown = visibleStep === completeStep;

  useEffect(() => {
    const element = ref.current;
    if (!element) return;

    const observer = new IntersectionObserver(
      ([entry]) => setInView(entry.intersectionRatio >= 0.4),
      { threshold: 0.4 },
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!playing || !inView || reduced) return;

    const delay =
      step === 0
        ? DEMO_TIMING.firstRow
        : step < scene.rows.length
          ? DEMO_TIMING.rowGap
          : step === scene.rows.length
            ? DEMO_TIMING.verdictGap
            : DEMO_TIMING.hold;
    const timer = window.setTimeout(() => {
      if (step === completeStep) {
        const nextIndex = (sceneIndex + 1) % SCENES.length;
        setSceneIndex(nextIndex);
        setStep(0);
        return;
      }
      setStep((currentStep) => currentStep + 1);
    }, delay);

    return () => window.clearTimeout(timer);
  }, [
    completeStep,
    inView,
    playing,
    reduced,
    scene.rows.length,
    sceneIndex,
    step,
  ]);

  function selectScene(index: number) {
    setSceneIndex(index);
    setStep(SCENES[index].rows.length + 1);
    setPlaying(false);
  }

  function renderFootnote(item: (typeof SCENES)[number]) {
    if (item.footnote.startsWith(item.source.label)) {
      return (
        <>
          <a
            className="text-emerald underline underline-offset-4 hover:text-emerald-deep"
            href={item.source.href}
            target="_blank"
            rel="noopener noreferrer"
          >
            {item.source.label}
          </a>
          {item.footnote.slice(item.source.label.length)}
        </>
      );
    }

    return (
      <>
        {item.footnote}
        <a
          className="text-emerald underline underline-offset-4 hover:text-emerald-deep"
          href={item.source.href}
          target="_blank"
          rel="noopener noreferrer"
        >
          {item.source.label}
        </a>
      </>
    );
  }

  return (
    <section
      ref={ref}
      aria-labelledby="demo-title"
      className="w-full max-w-[480px] rounded-3xl border border-line bg-surface p-6 shadow-lg min-h-[520px] md:min-h-[548px]"
    >
      <h2 id="demo-title" className="sr-only">
        Recorded verdict examples
      </h2>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Mark size={20} className="text-emerald" />
          <span className="text-[13px] font-semibold text-muted">
            Recorded examples, not live scans
          </span>
        </div>
        {!reduced && (
          <button
            type="button"
            aria-pressed={!playing}
            aria-label={playing ? "Pause the examples" : "Play the examples"}
            onClick={() => setPlaying((currentPlaying) => !currentPlaying)}
            className="h-9 w-9 shrink-0 inline-flex items-center justify-center rounded-lg text-muted hover:bg-surface-3 hover:text-ink"
          >
            <Icon name={playing ? "pause" : "play"} size={16} />
          </button>
        )}
      </div>

      <div className="mt-5 flex gap-2">
        {SCENES.map((item, index) => {
          const active = index === sceneIndex;
          return (
            <button
              key={item.id}
              type="button"
              aria-label={`Show example ${index + 1} of 3`}
              aria-current={active ? "true" : undefined}
              onClick={() => selectScene(index)}
              className={[
                "h-8 w-8 rounded-full text-[13px] font-semibold",
                active
                  ? "bg-emerald-tint text-ink"
                  : "text-muted hover:bg-surface-3",
              ].join(" ")}
            >
              {index + 1}
            </button>
          );
        })}
      </div>

      <div className="grid">
        {SCENES.map((item, sceneBodyIndex) => {
          const active = sceneBodyIndex === sceneIndex;
          const itemVisibleStep = active ? visibleStep : item.rows.length + 1;
          const itemVerdictShown = itemVisibleStep === item.rows.length + 1;

          return (
            <div
              key={item.id}
              className={["col-start-1 row-start-1 mt-6", active ? "" : "invisible"]
                .filter(Boolean)
                .join(" ")}
              aria-hidden={active ? undefined : true}
              inert={!active}
            >
              <p className="text-base font-semibold text-ink">{item.title}</p>
              <p className="mt-1 text-sm text-muted">{item.subtitle}</p>
              <div className="mt-3 flex flex-wrap items-center gap-2 font-mono text-[13px] text-body">
                {item.address && (
                  <span>
                    <span className="md:hidden lg:inline xl:hidden">{`${item.address.slice(0, 6)}\u2026${item.address.slice(-4)}`}</span>
                    <span className="hidden md:inline lg:hidden xl:inline break-all">{item.address}</span>
                  </span>
                )}
                <span className="rounded-md bg-surface-3 px-2 py-0.5 text-xs text-muted">
                  {item.chain}
                </span>
              </div>

              <div className="mt-6 space-y-4">
                {item.rows.map((row, index) => (
                  <motion.div
                    key={row.name}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{
                      opacity: index < itemVisibleStep ? 1 : 0,
                      y: index < itemVisibleStep ? 0 : 6,
                    }}
                    transition={{ duration: reduced ? 0 : 0.25, ease: [0.2, 0, 0, 1] }}
                    className={["flex gap-3", index >= itemVisibleStep ? "invisible" : ""]
                      .filter(Boolean)
                      .join(" ")}
                  >
                    <span
                      className={[
                        "h-5 w-5 rounded-full flex items-center justify-center shrink-0",
                        rowTones[row.state],
                      ].join(" ")}
                    >
                      <Icon name={rowIcons[row.state]} size={16} className="h-3 w-3" />
                    </span>
                    <div>
                      <p className="text-sm font-semibold text-ink">{row.name}</p>
                      <p className="text-[13px] text-muted">{row.note}</p>
                    </div>
                  </motion.div>
                ))}
              </div>

              <motion.div
                initial={{ opacity: 0, y: 6 }}
                animate={{
                  opacity: itemVerdictShown ? 1 : 0,
                  y: itemVerdictShown ? 0 : 6,
                }}
                transition={{ duration: reduced ? 0 : 0.25, ease: [0.2, 0, 0, 1] }}
                className={[
                  "mt-6 rounded-xl border p-4",
                  verdictTones[item.verdict.tone],
                  itemVerdictShown ? "" : "invisible",
                ]
                  .filter(Boolean)
                  .join(" ")}
              >
                <Badge verdict={item.verdict.tone} variant="solid" size="lg">
                  {item.verdict.label}
                </Badge>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  {item.verdict.chips.map((chip) => (
                    <span
                      key={chip}
                      className="font-mono text-xs text-body rounded-md bg-surface/80 px-2 py-0.5"
                    >
                      {chip}
                    </span>
                  ))}
                </div>
                <p className="mt-3 text-sm text-body">{item.explanation}</p>
              </motion.div>

              <p className="mt-4 text-[13px] leading-relaxed text-muted">{renderFootnote(item)}</p>
            </div>
          );
        })}
      </div>
      <p className="sr-only" aria-live="polite">
        {verdictShown ? scene.announcement : ""}
      </p>
    </section>
  );
}
