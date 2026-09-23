import Navbar from "./components/Navbar";
import Hero from "./components/Hero";
import LiveStats from "./components/LiveStats";
import HowItWorks from "./components/HowItWorks";
import Screenshot from "./components/Screenshot";
import Features from "./components/Features";
import AgentSecurity from "./components/AgentSecurity";
import AIThreatCard from "./components/AIThreatCard";
import Chains from "./components/Chains";
import RobinhoodCensus from "./components/RobinhoodCensus";
import Channels from "./components/Channels";
import Roadmap from "./components/Roadmap";
import Team from "./components/Team";
import BetaSignup from "./components/BetaSignup";
import FAQ from "./components/FAQ";
import Footer from "./components/Footer";

export default function App() {
  return (
    <div className="min-h-screen">
      <Navbar />
      <Hero />
      <LiveStats />
      <HowItWorks />
      <Screenshot />
      <Features />
      <AgentSecurity />
      <AIThreatCard />
      <Chains />
      <RobinhoodCensus />
      <Channels />
      <Roadmap />
      <Team />
      <BetaSignup />
      <FAQ />
      <Footer />
    </div>
  );
}
