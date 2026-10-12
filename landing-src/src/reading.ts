import { useEffect, useRef, useState, useSyncExternalStore } from "react";

// A section that takes its reading when it comes into view (index.css, "The reading"): the element renders
// data-read="wait", which pauses its animations on their first frame, and this sets "go" once, the first time a
// sixth of it is on screen. Text is never hidden while it waits, only dimmed; with reduced motion no animation
// exists, so "wait" changes nothing.
export function useReading<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    const element = ref.current!;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        element.dataset.read = "go";
        observer.disconnect();
      },
      { threshold: 0.15, rootMargin: "0px 0px -10% 0px" },
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return ref;
}

// One pause for the whole page: any part's Pause button stops every part, and any Play button restarts them all.
let pausedNow = false;
const pauseListeners = new Set<() => void>();

function subscribePaused(listener: () => void) {
  pauseListeners.add(listener);
  return () => {
    pauseListeners.delete(listener);
  };
}

function setPaused(paused: boolean) {
  pausedNow = paused;
  pauseListeners.forEach((listener) => listener());
}

// A part of the page that keeps moving (the hero's replay, the strip's re-reading, the chain orbits): on while it is
// on screen, the tab is visible, motion is allowed and the visitor has not paused the page (any Pause button, WCAG
// 2.2.2). It sends no request; each part only replays what the page already has.
export function useAlive<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const paused = useSyncExternalStore(subscribePaused, () => pausedNow);
  const [on, setOn] = useState(false);
  useEffect(() => {
    if (paused || matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setOn(false);
      return;
    }
    let seen = false;
    const sync = () => setOn(seen && !document.hidden);
    const observer = new IntersectionObserver(([entry]) => {
      seen = entry.isIntersecting;
      sync();
    });
    observer.observe(ref.current!);
    document.addEventListener("visibilitychange", sync);
    return () => {
      observer.disconnect();
      document.removeEventListener("visibilitychange", sync);
    };
  }, [paused]);
  return { ref, on, paused, setPaused };
}
