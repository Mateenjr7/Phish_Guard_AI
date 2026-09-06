import { useState, useEffect, useRef } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Mail, MessageSquare, Link, Shield, CheckCircle, AlertTriangle, XCircle, Copy, Zap, Lock } from "lucide-react";
import ScoreGauge from "./ScoreGauge";
import ThreatReport from "./ThreatReport";
import { analyzeContent, type AnalysisResult } from "@/lib/threatAnalysis";

const ParticleBackground = ({ cursor }: { cursor: { x: number; y: number } }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const particles = useRef<{ x: number; y: number; vx: number; vy: number; r: number }[]>([]);
  const animationRef = useRef<number>();

  const initParticles = (width: number, height: number) => {
    particles.current = Array.from({ length: 80 }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      r: 1 + Math.random() * 2,
    }));
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      initParticles(rect.width, rect.height);
    };

    resize();
    window.addEventListener("resize", resize);

    const animate = () => {
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      ctx.clearRect(0, 0, rect.width, rect.height);

      particles.current.forEach((p) => {
        const dx = p.x - cursor.x;
        const dy = p.y - cursor.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 100) {
          const angle = Math.atan2(dy, dx);
          const force = (100 - dist) / 100;
          p.vx += Math.cos(angle) * force * 0.4;
          p.vy += Math.sin(angle) * force * 0.4;
        }

        p.x += p.vx;
        p.y += p.vy;

        p.vx *= 0.95;
        p.vy *= 0.95;

        if (p.x < 0) p.x = rect.width;
        if (p.x > rect.width) p.x = 0;
        if (p.y < 0) p.y = rect.height;
        if (p.y > rect.height) p.y = 0;

        ctx.fillStyle = "rgba(255,255,255,0.18)";
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      });

      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      window.removeEventListener("resize", resize);
      if (animationRef.current) cancelAnimationFrame(animationRef.current);
    };
  }, [cursor]);

  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" />;
};

const examples = {
  email: "We've noticed unusual activity on your account. Click here to verify your identity: https://bit.ly#suspectlogin. Thanks, The Security Team.",
  sms: "URGENT: Your bank account has been compromised! Verify now at http://secure-bank-verify.tk/login to prevent lockout.",
  url: "http://paypa1-secure.com/signin?redirect=account-verify&token=abc123",
};

const ThreatAnalyzer = () => {
  const [activeTab, setActiveTab] = useState("email");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [inputValue, setInputValue] = useState(examples.email);
  const [reportOpen, setReportOpen] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [copied, setCopied] = useState(false);
  const [cursor, setCursor] = useState({ x: 0, y: 0 });
  const [history, setHistory] = useState<{ text: string; result: AnalysisResult; date: string }[]>([]);

  // Cursor tracking for interactive glow
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      setCursor({ x: e.clientX, y: e.clientY });
    };
    window.addEventListener("mousemove", handleMouseMove);
    return () => window.removeEventListener("mousemove", handleMouseMove);
  }, []);

  const handleTabChange = (val: string) => {
    setActiveTab(val);
    setInputValue(examples[val as keyof typeof examples]);
    setResult(null);
  };

  const handleAnalyze = () => {
    setIsAnalyzing(true);
    // Simulate analysis delay for effect
    setTimeout(() => {
      const analysis = analyzeContent(inputValue, activeTab);
      setResult(analysis);
      setHistory([{ text: inputValue, result: analysis, date: new Date().toLocaleTimeString() }, ...history.slice(0, 4)]);
      setIsAnalyzing(false);
    }, 800);
  };

  const handleCopy = () => {
    const text = `${activeTab.toUpperCase()}: ${inputValue}\n\nRisk Score: ${result?.score}%\nVerdict: ${result?.verdict.toUpperCase()}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const detectedThreats = result?.indicators.filter(i => i.detected) || [];

  const threatIcon = (severity: string) => {
    if (severity === "critical") return XCircle;
    if (severity === "high") return AlertTriangle;
    return CheckCircle;
  };

  return (
    <section className="relative min-h-screen px-4 py-24 overflow-hidden">
      {/* Animated background gradient */}
      <div className="fixed inset-0 -z-10">
        <div className="absolute inset-0 bg-gradient-to-b from-black via-slate-900 to-black" />
        <ParticleBackground cursor={cursor} />
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-primary/20 rounded-full mix-blend-screen blur-3xl opacity-30 animate-pulse" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-accent/20 rounded-full mix-blend-screen blur-3xl opacity-30 animate-pulse" style={{ animationDelay: "1s" }} />
      </div>

      {/* Cursor glow effect */}
      <div
        className="fixed pointer-events-none z-50 transition-opacity duration-150"
        style={{
          top: cursor.y,
          left: cursor.x,
          transform: "translate(-50%, -50%)",
          width: "300px",
          height: "300px",
          background: "radial-gradient(circle, rgba(348, 83, 90, 0.15), transparent 70%)",
          filter: "blur(60px)",
        }}
      />

      <div className="max-w-5xl mx-auto space-y-8 relative z-10">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 mb-4 px-4 py-2 rounded-full border border-primary/30 bg-primary/10">
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-semibold text-primary">Advanced Threat Detection</span>
            <Zap className="w-4 h-4 text-primary" />
          </div>
          <h2 className="text-4xl md:text-5xl font-bold mb-3 text-gradient-primary">
            Threat Analyzer
          </h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Real-time phishing and scam detection with AI-powered analysis
          </p>
        </div>

        {/* Input Card */}
        <div className="group relative">
          <div className="absolute inset-0 bg-gradient-to-r from-primary/20 to-accent/20 rounded-2xl blur-xl opacity-0 group-hover:opacity-100 transition-all duration-500" />
          <div className="relative glass-card rounded-2xl p-8 border border-border/50 group-hover:border-primary/50 transition-all duration-300">
            <Tabs value={activeTab} onValueChange={handleTabChange}>
              <TabsList className="bg-secondary/50 border border-border/50 mb-6 w-full">
                <TabsTrigger value="email" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-2 flex-1">
                  <Mail className="w-4 h-4" /> EMAIL
                </TabsTrigger>
                <TabsTrigger value="sms" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-2 flex-1">
                  <MessageSquare className="w-4 h-4" /> SMS
                </TabsTrigger>
                <TabsTrigger value="url" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-2 flex-1">
                  <Link className="w-4 h-4" /> URL
                </TabsTrigger>
              </TabsList>

              {["email", "sms", "url"].map((tab) => (
                <TabsContent key={tab} value={tab} className="space-y-4">
                  <div className="relative group">
                    <textarea
                      className="w-full bg-secondary/30 border-2 border-border/50 group-focus-within:border-primary/50 rounded-xl p-4 text-sm text-foreground resize-none focus:outline-none focus:ring-0 min-h-[120px] transition-all duration-300 backdrop-blur-sm"
                      value={inputValue}
                      onChange={(e) => { setInputValue(e.target.value); setResult(null); }}
                      placeholder="Paste your email, SMS, or URL here..."
                    />
                    <div className="absolute top-3 right-3 text-xs text-muted-foreground">
                      {inputValue.length} characters
                    </div>
                  </div>
                </TabsContent>
              ))}
            </Tabs>

            <div className="flex gap-3 mt-6">
              <button
                onClick={handleAnalyze}
                disabled={isAnalyzing}
                className="flex-1 inline-flex items-center justify-center gap-2 bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary/70 disabled:opacity-50 disabled:cursor-not-allowed text-primary-foreground px-6 py-3 rounded-xl text-sm font-semibold transition-all duration-300 group"
              >
                <Shield className="w-4 h-4 group-hover:animate-spin" />
                {isAnalyzing ? "ANALYZING..." : "ANALYZE THREAT"}
              </button>
              {result && (
                <button
                  onClick={handleCopy}
                  className="inline-flex items-center justify-center gap-2 border border-border/50 hover:border-primary/50 text-foreground hover:bg-primary/10 px-6 py-3 rounded-xl text-sm font-semibold transition-all duration-300"
                >
                  <Copy className="w-4 h-4" />
                  {copied ? "COPIED!" : "COPY"}
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Result Card */}
        {result && (
          <div className="group relative animate-fade-in-up">
            <div className="absolute inset-0 bg-gradient-to-r from-alert-card via-transparent to-alert-card rounded-2xl blur-xl opacity-40 group-hover:opacity-60 transition-all duration-500" />
            <div className="relative alert-card p-8 rounded-2xl border-2 border-primary/30 group-hover:border-primary/50 transition-all duration-300">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${result.verdict === "safe" ? "bg-success/20" : "bg-danger/20"}`}>
                    <Shield className={`w-5 h-5 ${result.verdict === "safe" ? "text-success" : "text-danger"}`} />
                  </div>
                  <div>
                    <div className="text-xs font-bold tracking-widest uppercase text-muted-foreground">Threat Status</div>
                    <div className="flex items-center gap-2">
                      <span className={`text-lg font-bold ${result.verdict === "safe" ? "text-success" : "text-primary"}`}>
                        {result.verdict === "safe" ? "SAFE" : "PHISHING ALERT"}
                      </span>
                      {result.verdict !== "safe" && <span className="inline-block w-2 h-2 bg-primary rounded-full animate-pulse" />}
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid md:grid-cols-3 gap-6">
                <div className="md:col-span-2 space-y-6">
                  <div>
                    <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
                      {result.verdict === "safe" ? (
                        <CheckCircle className="w-5 h-5 text-success" />
                      ) : (
                        <AlertTriangle className="w-5 h-5 text-primary" />
                      )}
                      {result.verdict === "safe" ? "No Threats Detected" : "Detected Threats"}
                    </h3>
                    <ul className="space-y-3">
                      {detectedThreats.map((t) => {
                        const Icon = threatIcon(t.severity);
                        return (
                          <li key={t.id} className="flex items-center gap-3 p-3 bg-secondary/30 border border-border/30 rounded-lg hover:border-primary/50 transition-all duration-300">
                            <Icon className={`w-5 h-5 flex-shrink-0 ${t.severity === "critical" ? "text-danger" : t.severity === "high" ? "text-primary" : "text-success"}`} />
                            <span className="text-foreground/90 flex-1">{t.label}</span>
                            <span className={`text-xs font-bold uppercase tracking-wider px-2 py-1 rounded ${t.severity === "critical" ? "bg-danger/20 text-danger" : t.severity === "high" ? "bg-primary/20 text-primary" : "bg-warning/20 text-warning"}`}>
                              {t.severity}
                            </span>
                          </li>
                        );
                      })}
                      {detectedThreats.length === 0 && (
                        <li className="flex items-center gap-3 p-3 bg-success/10 border border-success/30 rounded-lg">
                          <CheckCircle className="w-5 h-5 text-success" />
                          <span className="text-success">All checks passed — no threats detected</span>
                        </li>
                      )}
                    </ul>
                  </div>

                  {result.score >= 20 && (
                    <div className={`p-4 rounded-lg border ${result.score >= 70 ? "bg-danger/10 border-danger/50" : "bg-warning/10 border-warning/50"}`}>
                      <div className="flex items-center gap-2 text-sm font-bold">
                        <AlertTriangle className={`w-4 h-4 ${result.score >= 70 ? "text-danger" : "text-warning"}`} />
                        <span className={result.score >= 70 ? "text-danger" : "text-warning"}>
                          {result.score >= 70 ? "⚠️ HIGH RISK PHISHING ATTEMPT!" : result.score >= 45 ? "⚠️ POSSIBLE PHISHING ATTEMPT!" : "🛡️ EXERCISE CAUTION"}
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                <div className="flex flex-col items-center justify-center gap-6">
                  <ScoreGauge score={result.score} size={180} label="Scam Risk" />

                  {result.score >= 20 && (
                    <div className="text-center">
                      <div className="flex items-center justify-center gap-2 mb-2">
                        <Lock className="w-4 h-4 text-danger" />
                        <span className="text-xs font-bold text-danger tracking-wider uppercase">
                          {result.verdict.toUpperCase()} LEVEL
                        </span>
                      </div>
                      <div className="w-full h-1 bg-secondary rounded-full overflow-hidden">
                        <div
                          className={`h-full transition-all ${result.score >= 70 ? "bg-danger" : result.score >= 45 ? "bg-warning" : "bg-primary"}`}
                          style={{ width: `${result.score}%` }}
                        />
                      </div>
                    </div>
                  )}

                  <button
                    onClick={() => setReportOpen(true)}
                    className="w-full border border-foreground/30 text-foreground hover:bg-foreground/10 hover:border-primary/50 px-6 py-3 rounded-lg text-sm font-semibold tracking-wider transition-all duration-300"
                  >
                    VIEW FULL REPORT
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* History */}
        {history.length > 0 && (
          <div className="mt-12">
            <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
              <Lock className="w-5 h-5 text-primary" />
              Recent Analyses
            </h3>
            <div className="grid gap-3 max-h-64 overflow-y-auto">
              {history.map((item, idx) => (
                <div
                  key={idx}
                  className="p-4 bg-secondary/30 border border-border/30 rounded-lg hover:border-primary/50 hover:bg-secondary/50 transition-all duration-300 cursor-pointer group"
                  onClick={() => {
                    setInputValue(item.text);
                    setResult(item.result);
                  }}
                >
                  <div className="flex items-start justify-between mb-2">
                    <span className={`text-xs font-bold px-2 py-1 rounded ${item.result.verdict === "safe" ? "bg-success/20 text-success" : "bg-danger/20 text-danger"}`}>
                      {item.result.verdict.toUpperCase()}
                    </span>
                    <span className="text-xs text-muted-foreground">{item.date}</span>
                  </div>
                  <p className="text-sm text-foreground/70 truncate group-hover:text-foreground/90 transition-colors">
                    {item.text.substring(0, 100)}...
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        <ThreatReport open={reportOpen} onOpenChange={setReportOpen} result={result} />
      </div>

      {/* Animations */}
      <style>{`
        @keyframes fadeInUp {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        .animate-fade-in-up {
          animation: fadeInUp 0.6s ease-out forwards;
        }
      `}</style>
    </section>
  );
};

export default ThreatAnalyzer;
