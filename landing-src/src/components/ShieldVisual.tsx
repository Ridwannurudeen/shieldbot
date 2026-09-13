import { motion } from "framer-motion";

export default function ShieldVisual() {
  return (
    <motion.div
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: "spring", stiffness: 100, damping: 20, delay: 0.3 }}
      className="relative w-full max-w-md mx-auto"
    >
      <svg
        viewBox="0 0 400 460"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-auto shield-glow"
      >
        {/* Outer glow */}
        <defs>
          <radialGradient id="shieldGlow" cx="50%" cy="45%" r="50%">
            <stop offset="0%" stopColor="rgba(0,255,136,0.15)" />
            <stop offset="100%" stopColor="rgba(0,255,136,0)" />
          </radialGradient>
          <linearGradient id="shieldFill" x1="200" y1="40" x2="200" y2="420" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="rgba(0,255,136,0.12)" />
            <stop offset="100%" stopColor="rgba(0,255,136,0.02)" />
          </linearGradient>
        </defs>

        {/* Background glow */}
        <ellipse cx="200" cy="230" rx="180" ry="200" fill="url(#shieldGlow)" />

        {/* Shield body */}
        <path
          d="M200 40L60 110v120c0 90 56 174 140 190 84-16 140-100 140-190V110L200 40z"
          fill="url(#shieldFill)"
          stroke="#00FF88"
          strokeWidth="2"
        />

        {/* Inner shield outline */}
        <path
          d="M200 70L85 128v100c0 75 47 145 115 158 68-13 115-83 115-158V128L200 70z"
          fill="none"
          stroke="rgba(0,255,136,0.2)"
          strokeWidth="1"
        />

        {/* Circuit traces */}
        <line x1="200" y1="120" x2="200" y2="320" stroke="rgba(0,255,136,0.3)" strokeWidth="1" className="circuit-line" />
        <line x1="120" y1="160" x2="280" y2="160" stroke="rgba(0,255,136,0.3)" strokeWidth="1" className="circuit-line" />
        <line x1="130" y1="220" x2="270" y2="220" stroke="rgba(0,255,136,0.25)" strokeWidth="1" className="circuit-line-reverse" />
        <line x1="150" y1="280" x2="250" y2="280" stroke="rgba(0,255,136,0.2)" strokeWidth="1" className="circuit-line" />

        {/* Diagonal circuit traces */}
        <line x1="120" y1="140" x2="170" y2="190" stroke="rgba(0,255,136,0.2)" strokeWidth="1" className="circuit-line-reverse" />
        <line x1="280" y1="140" x2="230" y2="190" stroke="rgba(0,255,136,0.2)" strokeWidth="1" className="circuit-line" />
        <line x1="140" y1="260" x2="180" y2="300" stroke="rgba(0,255,136,0.15)" strokeWidth="1" className="circuit-line-reverse" />
        <line x1="260" y1="260" x2="220" y2="300" stroke="rgba(0,255,136,0.15)" strokeWidth="1" className="circuit-line" />

        {/* Circuit nodes */}
        {[
          [200, 120], [200, 220], [200, 320],
          [120, 160], [280, 160],
          [130, 220], [270, 220],
          [150, 280], [250, 280],
          [170, 190], [230, 190],
        ].map(([cx, cy], i) => (
          <circle
            key={i}
            cx={cx}
            cy={cy}
            r="3"
            fill="#00FF88"
            opacity={0.6 + (i % 3) * 0.13}
          />
        ))}

        {/* Checkmark */}
        <motion.path
          d="M165 215l25 25 45-55"
          stroke="#00FF88"
          strokeWidth="4"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 1, delay: 0.8, ease: "easeOut" }}
        />
      </svg>
    </motion.div>
  );
}
