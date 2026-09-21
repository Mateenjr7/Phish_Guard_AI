import { Shield, Zap, Brain, Link as LinkIcon, BarChart3 } from "lucide-react";
import { SignInButton } from "@clerk/clerk-react";
import GlowButton from "@/components/GlowButton";
import { InteractiveHoverButton } from "@/components/ui/interactive-hover-button";
import { FlipWords } from "@/components/ui/flip-words";
import FeatureCard from "@/components/FeatureCard";
import  GridBackground  from "@/components/GridBackground";
import RealWorldDetection from "@/components/RealWorldDetection";

const Landing = () => {
  const words = [
    "Phishing Detection",
    "Link Analysis",
    "Threat Detection",
    "Email Security",
  ];

  return (
    <div className="relative min-h-screen bg-[#0b0f1a] text-white overflow-hidden">
      
      {/* 🔹 Grid Background */}
      <GridBackground />

      {/* 🔹 Page Content */}
      <div className="relative z-10">

        {/* Navbar */}
        <nav className="flex justify-between items-center px-8 py-6 border-b border-[#1f2937]">
          <h1 className="text-2xl font-bold text-red-500 flex items-center gap-2">
            <Shield />
            PhishGuard AI
          </h1>

          <SignInButton mode="redirect" forceRedirectUrl="/app">
            <button className="bg-red-500 px-5 py-2 rounded-lg font-semibold hover:bg-red-600 transition">
              Sign In
            </button>
          </SignInButton>
        </nav>

        {/* Hero */}
        <section className="text-center py-24 px-6">
          <h1 className="text-6xl font-bold mb-6 leading-tight">
            AI Powered{" "}
            <FlipWords words={words} className="text-red-500" />
          </h1>

          <p className="text-gray-400 max-w-2xl mx-auto text-lg mb-10">
            PhishGuard analyzes suspicious links, domains, and emails using AI
            to protect users from phishing attacks and malicious websites in
            real-time.
          </p>

          <GlowButton />
        </section>

        {/* Features */}
        <section className="px-8 pb-24">
          <h2 className="text-4xl font-bold text-center mb-16">
            Powerful Security Features
          </h2>

          <div className="grid md:grid-cols-4 gap-8 max-w-6xl mx-auto">
            <FeatureCard
              icon={<Brain size={40} />}
              title="AI Detection"
              description="Advanced AI models analyze links and domains for phishing patterns."
            />
            <FeatureCard
              icon={<Zap size={40} />}
              title="Real-Time Analysis"
              description="Instantly scan URLs and detect threats within seconds."
            />
            <FeatureCard
              icon={<LinkIcon size={40} />}
              title="Link Intelligence"
              description="Detect suspicious domains and spoofed websites."
            />
            <FeatureCard
              icon={<BarChart3 size={40} />}
              title="Threat Reports"
              description="Get detailed security reports and risk scores."
            />
          </div>
        </section>
        <RealWorldDetection />

        {/* CTA */}
        <section className="text-center pb-24">
          <h2 className="text-4xl font-bold mb-6">
            Start Protecting Yourself Today
          </h2>

          <SignInButton mode="redirect" forceRedirectUrl="/app">
            <InteractiveHoverButton className="px-8 py-4 text-lg rounded-xl shadow-2xl">
              Launch Phish Guard
            </InteractiveHoverButton>
          </SignInButton>
        </section>

        {/* Footer */}
        <footer className="border-t border-[#1f2937] text-center py-6 text-gray-500">
          © 2026 PhishGuard AI — Protecting users from phishing attacks.
        </footer>

      </div>
    </div>
  );
};

export default Landing;