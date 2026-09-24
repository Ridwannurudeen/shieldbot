import Navbar from "./components/Navbar";
import Hero from "./components/Hero";
import LiveStats from "./components/LiveStats";
import HowItWorks from "./components/HowItWorks";
import Chains from "./components/Chains";
import AgentSecurity from "./components/AgentSecurity";
import RobinhoodCensus from "./components/RobinhoodCensus";
import FAQ from "./components/FAQ";
import Team from "./components/Team";
import Footer from "./components/Footer";

export default function App() {
  return (
    <div className="min-h-screen">
      <Navbar />
      <Hero />
      <LiveStats />
      <HowItWorks />
      <Chains />
      <AgentSecurity />
      <RobinhoodCensus />
      <FAQ />
      <Team />
      <Footer />
    </div>
  );
}
