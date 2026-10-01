import { MotionConfig } from "framer-motion";
import Navbar from "./components/Navbar";
import Hero from "./components/Hero";
import LiveStats from "./components/LiveStats";
import HowItWorks from "./components/HowItWorks";
import Chains from "./components/Chains";
import AgentSecurity from "./components/AgentSecurity";
import RobinhoodCensus from "./components/RobinhoodCensus";
import FAQ from "./components/FAQ";
import Footer from "./components/Footer";

export default function App() {
  return (
    <MotionConfig reducedMotion="user">
      <div id="top" className="min-h-screen">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-[60] focus:bg-emerald focus:text-white focus:font-semibold focus:px-4 focus:py-3 focus:rounded-lg"
        >
          Skip to content
        </a>
        <Navbar />
        <main id="main" tabIndex={-1} className="focus:outline-none">
          <Hero />
          <LiveStats />
          <HowItWorks />
          <Chains />
          <AgentSecurity />
          <RobinhoodCensus />
          <FAQ />
        </main>
        <Footer />
      </div>
    </MotionConfig>
  );
}
