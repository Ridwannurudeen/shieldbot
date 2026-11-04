import Navbar from "./components/Navbar";
import Hero from "./components/Hero";
import HowItWorks from "./components/HowItWorks";
import TryIt from "./components/TryIt";
import Proof from "./components/Proof";
import Registry from "./components/Registry";
import Chains from "./components/Chains";
import FAQ from "./components/FAQ";
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
        <HowItWorks />
        <TryIt />
        <Proof />
        <Registry />
        <Chains />
        <FAQ />
      </main>
      <Footer />
    </div>
  );
}
