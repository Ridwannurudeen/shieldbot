import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import Button from "./Button";
import Icon, { Mark } from "./Icon";

const links = [
  { label: "How it works", href: "#how-it-works" },
  { label: "On-chain check", href: "#on-chain" },
  { label: "Coverage", href: "#chains" },
  { label: "For builders", href: "#agent-security" },
  { label: "FAQ", href: "#faq" },
];

const chromeStoreUrl = "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk";

export default function Navbar() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }

    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [open]);

  return (
    <nav aria-label="Main" className="fixed top-0 inset-x-0 z-50 bg-surface/90 backdrop-blur border-b border-line">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        <a href="#top" className="flex items-center gap-2 min-h-[44px]">
          <Mark size={28} className="text-emerald" />
          <span className="text-lg font-bold"><span className="text-ink">Shield</span><span className="text-emerald">Bot</span></span>
        </a>

        <div className="hidden lg:flex items-center gap-6">
          {links.map((link) => (
            <a key={link.label} href={link.href} className="text-sm font-medium text-muted hover:text-ink hover:underline underline-offset-[6px] transition-colors duration-150 ease-out">
              {link.label}
            </a>
          ))}
          <Button href={chromeStoreUrl} size="sm">Add to Chrome</Button>
        </div>

        <Button variant="ghost" size="sm" className="lg:hidden h-11 w-11 min-w-11 !px-0" onClick={() => setOpen(!open)} ariaLabel="Menu" ariaExpanded={open} ariaControls="mobile-menu">
          <Icon name={open ? "close" : "menu"} size={24} />
        </Button>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div id="mobile-menu" initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.25, ease: [0.2, 0, 0, 1] }} className="lg:hidden overflow-hidden bg-surface border-b border-line">
            <div className="max-w-6xl mx-auto px-4 sm:px-6 py-2 flex flex-col">
              {links.map((link) => (
                <a key={link.label} href={link.href} className="flex items-center min-h-12 text-sm font-medium text-muted hover:text-ink transition-colors duration-150 ease-out" onClick={() => setOpen(false)}>
                  {link.label}
                </a>
              ))}
              <Button href={chromeStoreUrl} className="w-full mt-2 mb-3" onClick={() => setOpen(false)}>Add to Chrome</Button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  );
}
