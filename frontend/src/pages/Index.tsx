import HeroSection from "@/components/HeroSection";
import Navbar from "@/components/Navbar";
import ThreatAnalyzer from "@/components/ThreatAnalyzer";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <HeroSection />
      <ThreatAnalyzer />
    </div>
  );
};

export default Index;
