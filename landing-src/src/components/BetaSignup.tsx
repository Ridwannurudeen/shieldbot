import { useState, type FormEvent } from "react";
import { motion } from "framer-motion";

export default function BetaSignup() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error" | "dup">("idle");
  const [message, setMessage] = useState("");

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = email.trim();
    if (!trimmed) return;

    setStatus("loading");
    setMessage("");

    try {
      const res = await fetch("https://api.shieldbotsecurity.online/api/beta-signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: trimmed }),
      });
      const data = await res.json();

      if (res.ok) {
        setStatus("success");
        setMessage(data.message || "You're on the list!");
        setEmail("");
      } else if (res.status === 409) {
        setStatus("dup");
        setMessage(data.detail || "Already signed up.");
      } else {
        setStatus("error");
        setMessage(data.detail || "Something went wrong.");
      }
    } catch {
      setStatus("error");
      setMessage("Network error. Please try again.");
    }
  }

  const msgColor =
    status === "success"
      ? "text-neon"
      : status === "error"
        ? "text-red-400"
        : status === "dup"
          ? "text-gray-400"
          : "";

  return (
    <section id="signup" className="py-24 bg-navy-light border-y border-white/5">
      <div className="max-w-6xl mx-auto px-6">
        <motion.div
          initial={{ y: 30, opacity: 0 }}
          whileInView={{ y: 0, opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
          className="max-w-md mx-auto text-center"
        >
          <h2 className="text-3xl md:text-4xl font-bold mb-4 tracking-tight">
            Start Protecting Your Wallet
          </h2>
          <p className="text-gray-400 mb-6">
            ShieldAI is live on the Chrome Web Store — free to install, no account required.
          </p>

          <a
            href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 bg-neon text-navy font-bold text-base px-8 py-3.5 rounded-lg hover:shadow-neon transition-all hover:-translate-y-0.5 mb-8"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <circle cx="12" cy="12" r="4"/>
              <path d="M12 2a10 10 0 0 1 8.66 5H12a5 5 0 0 0-4.58 3H3.34A10 10 0 0 1 12 2z" opacity=".6"/>
              <path d="M12 22A10 10 0 0 1 3.34 17H7.42A5 5 0 0 0 12 19.92V22z" opacity=".6"/>
              <path d="M22 12a10 10 0 0 1-5.34 8.9l-2.08-3.6A5 5 0 0 0 17 12h5z" opacity=".6"/>
            </svg>
            Add to Chrome — Free
          </a>

          <p className="text-gray-500 text-sm mb-4">Or enter your email to stay updated on new features:</p>

          <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
              className="flex-1 px-4 py-3 bg-navy border border-white/10 rounded-lg text-white
                         placeholder:text-gray-500 outline-none focus:border-neon/50 transition-colors"
            />
            <button
              type="submit"
              disabled={status === "loading"}
              className="bg-white/10 text-white font-bold px-6 py-3 rounded-lg hover:bg-white/20
                         transition-all disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
            >
              {status === "loading" ? "Submitting..." : "Stay Updated"}
            </button>
          </form>

          {message && (
            <p className={`mt-4 text-sm ${msgColor}`}>{message}</p>
          )}
        </motion.div>
      </div>
    </section>
  );
}
