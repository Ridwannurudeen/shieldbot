import { useState } from "react";
import { motion } from "framer-motion";

export default function Screenshot() {
  const [playing, setPlaying] = useState(false);

  return (
    <section className="py-24">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 tracking-tight">
          See It In Action
        </h2>
        <p className="text-gray-400 text-center max-w-md mx-auto mb-14">
          The live dashboard shows what ShieldBot is flagging right now: high
          risk contracts, possible sandwich attacks and suspicious approvals.
        </p>

        <div className="grid md:grid-cols-2 gap-6 items-start">
          {/* Left — demo video */}
          <motion.div
            initial={{ y: 40, opacity: 0 }}
            whileInView={{ y: 0, opacity: 1 }}
            viewport={{ once: true, amount: 0.2 }}
            transition={{ duration: 0.6 }}
            className="relative rounded-2xl overflow-hidden border border-neon/20 shadow-[0_0_60px_rgba(0,255,136,0.07)]"
            style={{ aspectRatio: "16/9" }}
          >
            {playing ? (
              <iframe
                className="absolute inset-0 w-full h-full"
                src="https://www.youtube.com/embed/NN95rom10R8?autoplay=1"
                title="ShieldBot Demo"
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                allowFullScreen
              />
            ) : (
              <>
                {/* Background */}
                <div className="absolute inset-0 bg-[#060B18]" />

                {/* Animated grid */}
                <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,136,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,136,0.03)_1px,transparent_1px)] bg-[size:40px_40px]" />

                {/* Radial glow */}
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(0,255,136,0.06),transparent_70%)]" />

                {/* Fake extension popup preview */}
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="bg-[#0A0F1E] border border-red-500/40 rounded-xl p-4 w-56 shadow-2xl">
                    <div className="flex items-center gap-2 mb-3">
                      <span className="text-lg">🚫</span>
                      <span className="text-red-400 font-bold text-sm">Transaction Blocked</span>
                    </div>
                    <div className="text-xs text-gray-400 mb-3">Safety: <span className="text-red-400 font-bold">6/100</span></div>
                    <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-2 text-xs text-gray-300">
                      Honeypot detected — you cannot sell this token.
                    </div>
                  </div>
                </div>

                {/* Play button */}
                <button
                  onClick={() => setPlaying(true)}
                  className="absolute inset-0 flex flex-col items-center justify-end pb-8 bg-gradient-to-t from-black/60 to-transparent group w-full cursor-pointer"
                >
                  <div className="flex items-center gap-3 bg-white/10 backdrop-blur-sm border border-white/20 rounded-full px-5 py-2.5 group-hover:bg-neon/20 group-hover:border-neon/40 transition-all">
                    <div className="w-0 h-0 border-t-[6px] border-t-transparent border-b-[6px] border-b-transparent border-l-[10px] border-l-white" />
                    <span className="text-sm font-semibold text-white">Play Demo</span>
                  </div>
                </button>

                {/* Demo badge: this is a recorded video, not live data */}
                <div className="absolute top-4 right-4 flex items-center gap-1.5 bg-black/60 backdrop-blur-sm border border-white/10 rounded-full px-3 py-1">
                  <span className="text-xs font-semibold text-gray-300">DEMO</span>
                </div>
              </>
            )}
          </motion.div>

          {/* Right — dashboard screenshot */}
          <motion.div
            initial={{ y: 40, opacity: 0 }}
            whileInView={{ y: 0, opacity: 1 }}
            viewport={{ once: true, amount: 0.2 }}
            transition={{ duration: 0.6, delay: 0.15 }}
            className="relative rounded-2xl overflow-hidden border border-neon/20 shadow-[0_0_60px_rgba(0,255,136,0.07)]"
          >
            <div className="absolute top-4 left-4 z-10 flex items-center gap-1.5 bg-black/60 backdrop-blur-sm border border-white/10 rounded-full px-3 py-1">
              <span className="text-xs font-semibold text-gray-300">Threat Dashboard</span>
            </div>
            <img
              src="/dashboard-screenshot.png"
              alt="ShieldBot threat dashboard on 23 September 2026 with live platform statistics, detections per hour and threats by chain"
              className="w-full h-auto block"
            />
          </motion.div>
        </div>

        <div className="flex justify-center mt-8">
          <a
            href="https://api.shieldbotsecurity.online/dashboard"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 text-sm text-neon border border-neon/30 px-6 py-2.5 rounded-lg hover:bg-neon/10 transition-colors"
          >
            Open Live Dashboard →
          </a>
        </div>
      </div>
    </section>
  );
}
