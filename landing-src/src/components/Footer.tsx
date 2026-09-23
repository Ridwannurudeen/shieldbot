export default function Footer() {
  return (
    <footer className="py-16 border-t border-white/5">
      <div className="max-w-6xl mx-auto px-6">
        <div className="flex flex-col md:flex-row justify-between gap-10">
          {/* Brand */}
          <div>
            <div className="text-lg font-bold mb-2">
              <span className="text-white">Shield</span>
              <span className="text-neon">Bot</span>
            </div>
            <p className="text-sm text-gray-500">On-chain transaction firewall</p>
          </div>

          {/* Link columns */}
          <div className="flex gap-16 flex-wrap">
            <div>
              <h5 className="text-xs text-gray-500 uppercase tracking-widest mb-3">
                Product
              </h5>
              <div className="flex flex-col gap-2">
                <a href="/dashboard" className="text-sm text-gray-300 hover:text-neon transition-colors">
                  Threat Dashboard
                </a>
                <a
                  href="https://youtu.be/NN95rom10R8"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  Demo Video
                </a>
                <a
                  href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  Chrome Extension
                </a>
                <a href="/about.html" className="text-sm text-gray-300 hover:text-neon transition-colors">
                  How It Works
                </a>
                <a href="/privacy.html" className="text-sm text-gray-300 hover:text-neon transition-colors">
                  Privacy Policy
                </a>
              </div>
            </div>
            <div>
              <h5 className="text-xs text-gray-500 uppercase tracking-widest mb-3">
                Community
              </h5>
              <div className="flex flex-col gap-2">
                <a
                  href="https://github.com/Ridwannurudeen/shieldbot"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  GitHub
                </a>
                <a
                  href="https://t.me/shieldbot_bnb_bot"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  Telegram Bot
                </a>
                <a
                  href="https://x.com/shieldbot_"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  @shieldbot_
                </a>
                <a
                  href="mailto:support@shieldbotsecurity.online"
                  className="text-sm text-gray-300 hover:text-neon transition-colors"
                >
                  support@shieldbotsecurity.online
                </a>
              </div>
            </div>
          </div>
        </div>

        <div className="text-center text-xs text-gray-600 mt-12">
          &copy; 2026 ShieldBot. Transaction security for EVM chains, including BNB Chain and Robinhood Chain.
        </div>
      </div>
    </footer>
  );
}
