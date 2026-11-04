import { useEffect, useState } from "react";
import Button from "./Button";
import Icon from "./Icon";
import ThemeToggle from "./ThemeToggle";

const links = [
  { label: "How it works", href: "#how" },
  { label: "Registry", href: "#registry" },
  { label: "Coverage", href: "#coverage" },
  { label: "Safety", href: "/safety.html" },
  { label: "Docs", href: "https://api.shieldbotsecurity.online/docs" },
];

const chromeStoreUrl =
  "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk";

function NavLinks({ onClick }: { onClick?: () => void }) {
  return (
    <>
      {links.map((link) => (
        <a
          key={link.label}
          href={link.href}
          onClick={onClick}
          className="flex min-h-11 items-center text-sm font-medium text-ink transition-colors hover:text-accent"
          {...(link.href.startsWith("http")
            ? { target: "_blank", rel: "noopener noreferrer" }
            : {})}
        >
          {link.label}
        </a>
      ))}
    </>
  );
}

export default function Navbar() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      setOpen(false);
      document
        .querySelector<HTMLButtonElement>('button[aria-controls="mobile-menu"]')
        ?.focus();
    }

    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [open]);

  return (
    <nav
      aria-label="Main"
      className="fixed inset-x-0 top-0 z-50 border-b border-hairline bg-ground/95"
    >
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
        <a href="#top" className="flex min-h-11 items-center text-lg font-medium tracking-[-0.03em] text-ink">
          ShieldBot
        </a>

        <div className="hidden items-center gap-6 lg:flex">
          <NavLinks />
          <ThemeToggle />
          <Button href={chromeStoreUrl} variant="secondary" size="sm">
            Add to Chrome
          </Button>
        </div>

        <Button
          variant="ghost"
          size="sm"
          className="h-11 w-11 min-w-11 !px-0 lg:hidden"
          onClick={() => setOpen(!open)}
          ariaLabel={open ? "Close menu" : "Open menu"}
          ariaExpanded={open}
          ariaControls="mobile-menu"
        >
          <Icon name={open ? "close" : "menu"} size={20} />
        </Button>
      </div>

      <div
        id="mobile-menu"
        inert={!open}
        className={`grid transition-[grid-template-rows] duration-200 ease-out lg:hidden ${open ? "grid-rows-[1fr] border-t border-hairline" : "grid-rows-[0fr]"}`}
      >
        <div className="overflow-hidden">
          <div className="mx-auto flex max-w-6xl flex-col px-4 py-3 sm:px-6">
            <NavLinks onClick={() => setOpen(false)} />
            <div className="flex items-center justify-between gap-4 border-t border-hairline pt-3">
              <ThemeToggle />
              <Button
                href={chromeStoreUrl}
                variant="secondary"
                className="flex-1"
                onClick={() => setOpen(false)}
              >
                Add to Chrome
              </Button>
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
