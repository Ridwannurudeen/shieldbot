import { useEffect, useState } from "react";
import Button from "./Button";
import Icon from "./Icon";
import ThemeToggle from "./ThemeToggle";

const links = [
  { label: "How it works", href: "#how-it-works" },
  { label: "Coverage", href: "#chains" },
  { label: "On-chain registry", href: "#on-chain" },
  { label: "Telegram", href: "#telegram" },
  { label: "Safety guide", href: "/safety.html" },
  { label: "Dashboard", href: "/dashboard" },
];

const chromeStoreUrl = "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk";

export default function Navbar() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
        document.querySelector<HTMLButtonElement>('button[aria-controls="mobile-menu"]')?.focus();
      }
    }

    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [open]);

  return (
    <nav aria-label="Main" className="fixed top-0 inset-x-0 z-50 bg-ground/90 backdrop-blur border-b border-hairline">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        <a href="#top" className="flex items-center gap-2 min-h-[44px]">
          <span className="mark-slot inline-block w-6 h-6 empty:hidden" aria-hidden="true" />
          <span className="text-[22px] leading-none font-medium tracking-[-0.03em] text-ink">ShieldBot</span>
        </a>

        <div className="flex items-center gap-1 lg:gap-6">
          <div className="hidden lg:flex items-center gap-6">
            {links.map((link) => (
              <a key={link.label} href={link.href} className="text-[15px] font-medium text-ink hover:text-accent transition-colors duration-150 ease-out">
                {link.label}
              </a>
            ))}
          </div>
          <ThemeToggle />
          <Button href={chromeStoreUrl} variant="secondary" size="sm" className="hidden lg:inline-flex">Add to Chrome</Button>
          <Button variant="ghost" size="sm" className="lg:hidden h-11 w-11 min-w-11 !px-0" onClick={() => setOpen(!open)} ariaLabel="Menu" ariaExpanded={open} ariaControls="mobile-menu">
            <Icon name={open ? "close" : "menu"} size={24} />
          </Button>
        </div>
      </div>

      <div id="mobile-menu" inert={!open} className={`lg:hidden grid transition-[grid-template-rows] duration-[250ms] ease-out ${open ? "grid-rows-[1fr] border-b border-hairline" : "grid-rows-[0fr]"}`}>
        <div className="overflow-hidden bg-ground">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-2 flex flex-col">
            {links.map((link) => (
              <a key={link.label} href={link.href} className="flex items-center min-h-12 text-[15px] font-medium text-ink hover:text-accent transition-colors duration-150 ease-out" onClick={() => setOpen(false)}>
                {link.label}
              </a>
            ))}
            <Button href={chromeStoreUrl} variant="secondary" className="w-full mt-2 mb-3" onClick={() => setOpen(false)}>Add to Chrome</Button>
          </div>
        </div>
      </div>
    </nav>
  );
}
