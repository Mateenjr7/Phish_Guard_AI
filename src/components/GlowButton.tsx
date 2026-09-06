import { useState, useEffect } from "react";
import { SignInButton } from "@clerk/clerk-react";
import { InteractiveHoverButton } from "@/components/ui/interactive-hover-button";

const GlowButton = () => {
  const [cursor, setCursor] = useState({ x: 0, y: 0 });

  // 🌟 GLOBAL CURSOR GLOW
  useEffect(() => {
    const move = (e: MouseEvent) => {
      setCursor({ x: e.clientX, y: e.clientY });
    };

    window.addEventListener("mousemove", move);
    return () => window.removeEventListener("mousemove", move);
  }, []);

  return (
    <>
      {/* 🌟 CURSOR GLOW */}
      <div
        className="fixed pointer-events-none z-50"
        style={{
          top: cursor.y,
          left: cursor.x,
          transform: "translate(-50%, -50%)",
          width: "250px",
          height: "250px",
          background:
            "radial-gradient(circle, rgba(239,68,68,0.25), transparent 70%)",
          filter: "blur(60px)",
        }}
      />

      <SignInButton mode="redirect" forceRedirectUrl="/app">
        <div className="relative inline-block">
          
          {/* 🔥 OPTIONAL OUTER GLOW */}
          <div className="absolute inset-0 bg-red-500/20 blur-xl rounded-xl pointer-events-none"></div>

          {/* ✨ MAGIC HOVER BUTTON */}
          <InteractiveHoverButton className="px-10 py-4 text-lg rounded-xl">
            Get Started
          </InteractiveHoverButton>

        </div>
      </SignInButton>
    </>
  );
};

export default GlowButton;