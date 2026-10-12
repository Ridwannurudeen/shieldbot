import Navbar from "./components/Navbar";
import Hero from "./components/Hero";
import WhyShieldBot from "./components/WhyShieldBot";
import TryIt from "./components/TryIt";
import WhyUnknown from "./components/WhyUnknown";
import Mechanism from "./components/Mechanism";
import Chains from "./components/Chains";
import HowItWorks from "./components/HowItWorks";
import FeatureTabs from "./components/FeatureTabs";
import WorkedExample from "./components/WorkedExample";
import OnChain from "./components/OnChain";
import AgentSecurity from "./components/AgentSecurity";
import Telegram from "./components/Telegram";
import StaySafe from "./components/StaySafe";
import FAQ from "./components/FAQ";
import CtaCard from "./components/CtaCard";
import Footer from "./components/Footer";

export default function App() {
  return (
    <div id="top" className="min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-[60] focus:bg-accent-fill focus:text-on-accent focus:font-medium focus:px-4 focus:py-3 focus:rounded-lg"
      >
        Skip to content
      </a>
      <Navbar />
      <main id="main" tabIndex={-1} className="focus:outline-none">
        <Hero />
        <WhyShieldBot />
        <TryIt />
        <WhyUnknown />
        <Mechanism />
        <WorkedExample />
        <OnChain />
        <Chains />
        <HowItWorks />
        <FeatureTabs />
        <AgentSecurity />
        <Telegram />
        <StaySafe />
        <FAQ />
        <CtaCard />
      </main>
      <Footer />
    </div>
  );
}
