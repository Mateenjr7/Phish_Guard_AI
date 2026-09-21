"use client";

import { Shield } from "lucide-react";
import { useEffect, useState } from "react";
import LetterGlitch from "./LetterGlitch";

const CHARACTERS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()-+=[]{}|;:,.<>?";

// ---------- Decrypting Headline ----------
interface DecryptingTextProps {
  targetText: string;
  speed?: number;
  className?: string;
  onComplete?: () => void;
}

const DecryptingText: React.FC<DecryptingTextProps> = ({
  targetText,
  speed = 10,
  className,
  onComplete,
}) => {
  const [currentText, setCurrentText] = useState("");

  useEffect(() => {
    let iteration = 0;
    let isMounted = true;

    const revealNextChar = () => {
      if (!isMounted) return;

      const newText = targetText
        .split("")
        .map((char, index) => {
          if (index < iteration) return char;

          if (char === " ") return " ";

          return CHARACTERS[
            Math.floor(Math.random() * CHARACTERS.length)
          ];
        })
        .join("");

      setCurrentText(newText);

      if (iteration < targetText.length) {
        iteration++;
        setTimeout(revealNextChar, speed * 15);
      } else {
        setCurrentText(targetText);
        onComplete?.();
      }
    };

    revealNextChar();

    return () => {
      isMounted = false;
    };
  }, [targetText, speed, onComplete]);

  return <p className={className}>{currentText}</p>;
};

// ---------- Stats ----------
const stats = [
  {
    value: "27",
    label: "URL ML features",
  },
  {
    value: "12,167",
    label: "SMS TF-IDF features",
  },
  {
    value: "50,000",
    label: "Email TF-IDF features",
  },
  {
    value: "3",
    label: "ML detection models",
  },
];

// ---------- HeroSection ----------
const HeroSection = () => {
  const [subtitleVisible, setSubtitleVisible] = useState(false);

  return (
    <section className="relative min-h-screen pt-24 pb-12 px-4 overflow-hidden bg-black">

      {/* ===== Background Glitch ===== */}
      <div className="absolute inset-0 z-0 opacity-30">
        <LetterGlitch
          className="w-full h-full"
          glitchColors={["#2b4539", "#61dca3", "#61b3dc"]}
          smooth
          glitchSpeed={50}
        />
      </div>

      {/* ===== Hero Content ===== */}
      <div className="max-w-5xl mx-auto text-center relative z-10">

        {/* Badge */}
        <div className="inline-flex items-center gap-2 mb-8 px-4 py-2 rounded-full border border-primary/30 bg-primary/10 text-primary text-sm font-semibold tracking-wider uppercase">
          <Shield className="w-4 h-4" />
          PhishGuard
        </div>

        {/* Headline */}
        <DecryptingText
          targetText="Detect Threats Before They Strike"
          speed={5}
          className="text-5xl md:text-6xl lg:text-7xl font-black tracking-tight mb-6 text-gradient-primary drop-shadow-lg"
          onComplete={() => setSubtitleVisible(true)}
        />

        {/* Subtitle */}
        {subtitleVisible && (
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-12 opacity-100 transition-opacity duration-700">
            Machine-learning and rule-based threat analysis for phishing URLs
            and scam messages.
          </p>
        )}

        {/* ===== Project Stats ===== */}
        <div className="flex flex-wrap items-center justify-center gap-4 mb-12">

          {/* ML / Dataset Stats */}
          {stats.map((stat, i) => (
            <div
              key={stat.label}
              className="stat-card min-w-[160px] opacity-0 animate-fade-in"
              style={{
                animationDelay: `${i * 300}ms`,
              }}
            >
              <div className="text-2xl font-bold text-primary">
                {stat.value}
              </div>

              <div className="text-xs text-muted-foreground mt-1">
                {stat.label}
              </div>
            </div>
          ))}

          {/* Hybrid Analysis */}
          <div
            className="stat-card min-w-[160px] opacity-0 animate-fade-in"
            style={{
              animationDelay: `${stats.length * 300}ms`,
            }}
          >
            <div className="text-2xl font-bold text-primary">
              ML + Rules
            </div>

            <div className="text-xs text-muted-foreground mt-1">
              Hybrid threat analysis
            </div>
          </div>
        </div>
      </div>

      {/* ===== Fade-In Animation ===== */}
      <style>
        {`
          @keyframes fadeIn {
            0% {
              opacity: 0;
              transform: translateY(10px);
            }

            100% {
              opacity: 1;
              transform: translateY(0);
            }
          }

          .animate-fade-in {
            animation: fadeIn 0.7s forwards;
          }
        `}
      </style>
    </section>
  );
};

export default HeroSection;