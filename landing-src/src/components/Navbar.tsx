import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

const links = [
  { label: "How it works", href: "#how-it-works" },
  { label: "Chains", href: "#chains" },
  { label: "Agents", href: "#agent-security" },
  { label: "Robinhood Chain", href: "#robinhood-chain" },
  { label: "Dashboard", href: "/dashboard" },
  { label: "Add to Chrome", href: "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk" },
];

export default function Navbar() {
  const [open, setOpen] = useState(false);

  return (
    <nav aria-label="Main" className="fixed top-0 left-0 right-0 z-50 bg-navy/85 backdrop-blur-xl border-b border-white/5">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        {/* Brand */}
        <a href="#" className="flex items-center gap-2 min-h-[44px]">
          <svg
            width="28"
            height="28"
            viewBox="0 0 32 32"
            fill="none"
            className="text-neon"
            aria-hidden="true"
          >
            <path
              d="M16 2L4 8v8c0 7.73 5.12 14.95 12 16 6.88-1.05 12-8.27 12-16V8L16 2z"
              stroke="currentColor"
              strokeWidth="2"
              fill="rgba(0,255,136,0.08)"
            />
            <path
              d="M12 16l3 3 5-6"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span className="text-lg font-bold">
            <span className="text-white">Shield</span>
            <span className="text-neon">Bot</span>
          </span>
        </a>

        {/* Desktop links */}
        <div className="hidden lg:flex items-center gap-8">
          {links.slice(0, -1).map((l) => (
            <a
              key={l.label}
              href={l.href}
              className="text-sm text-gray-400 hover:text-white transition-colors"
            >
              {l.label}
            </a>
          ))}
          <a
            href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm font-semibold bg-neon text-navy px-4 py-1.5 rounded-lg hover:shadow-neon transition-all"
          >
            Add to Chrome
          </a>
        </div>

        {/* Mobile hamburger */}
        <button
          className="lg:hidden w-11 h-11 -mr-2.5 flex items-center justify-center text-gray-400 hover:text-white"
          onClick={() => setOpen(!open)}
          aria-label="Menu"
          aria-expanded={open}
          aria-controls="mobile-menu"
        >
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            {open ? (
              <path d="M6 6l12 12M6 18L18 6" />
            ) : (
              <path d="M4 6h16M4 12h16M4 18h16" />
            )}
          </svg>
        </button>
      </div>

      {/* Mobile menu */}
      <AnimatePresence>
        {open && (
          <motion.div
            id="mobile-menu"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="lg:hidden overflow-hidden bg-navy-light border-b border-white/5"
          >
            <div className="px-6 py-2 flex flex-col">
              {links.slice(0, -1).map((l) => (
                <a
                  key={l.label}
                  href={l.href}
                  className="py-3 text-sm text-gray-300 hover:text-white transition-colors"
                  onClick={() => setOpen(false)}
                >
                  {l.label}
                </a>
              ))}
              <a
                href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk"
                target="_blank"
                rel="noopener noreferrer"
                className="py-3 text-sm font-semibold text-neon"
                onClick={() => setOpen(false)}
              >
                Add to Chrome — Free
              </a>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  );
}
