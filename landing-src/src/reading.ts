import { useEffect, useRef } from "react";

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
