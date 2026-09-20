import { useState, useEffect, useRef } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Mail,
  MessageSquare,
  Link,
  Shield,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Copy,
  Zap,
  Lock,
} from "lucide-react";
import ScoreGauge from "./ScoreGauge";
import ThreatReport from "./ThreatReport";
import {
  analyzeContent,
  type AnalysisResult,
  type ThreatIndicator,
  type ThreatSeverity,
} from "@/lib/threatAnalysis";
import {
  analyzeEmailWithBackend,
  analyzeSMSWithBackend,
  analyzeURLWithBackend,
  type EmailAnalysisResponse,
  type SMSAnalysisResponse,
  type URLAnalysisResponse,
} from "@/lib/api";

// =========================================================
// Particle Background
// =========================================================

const ParticleBackground = ({
  cursor,
}: {
  cursor: { x: number; y: number };
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const particles = useRef<
    {
      x: number;
      y: number;
      vx: number;
      vy: number;
      r: number;
    }[]
  >([]);

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

      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [cursor]);

  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" />;
};

// =========================================================
// Examples
// =========================================================

const examples = {
  email: {
    subject: "Urgent: Your account has been compromised",
    body: "Your bank account has been compromised. Verify your account immediately by logging in at https://secure-account-verify.xyz/login. Failure to verify your password will result in account suspension.",
  },

  sms: "URGENT: Your bank account has been compromised! Verify now at http://secure-bank-verify.tk/login to prevent lockout.",

  url: "https://secure-account-verify.xyz/login",
};

// =========================================================
// Backend response types
// =========================================================

type BackendAnalysisResponse =
  | URLAnalysisResponse
  | SMSAnalysisResponse
  | EmailAnalysisResponse;

// =========================================================
// History
// =========================================================

type HistoryItem = {
  text: string;
  subject?: string;
  result: AnalysisResult;
  date: string;
  backendResult: BackendAnalysisResponse | null;
};

// =========================================================
// Backend → Frontend AnalysisResult
// =========================================================

const convertBackendToAnalysisResult = (
  response: BackendAnalysisResponse,
  inputType: "url" | "sms" | "email",
): AnalysisResult => {
  const risk = response.risk;

  const indicators: ThreatIndicator[] = risk.indicators.map(
    (indicator, index) => {
      const severity: ThreatSeverity =
        indicator.severity === "info" ? "low" : indicator.severity;

      return {
        id: `${indicator.type}-${index}`,
        label: indicator.message,
        description: indicator.message,
        severity,
        detected: true,
        weight: 0,
      };
    },
  );

  let verdict: AnalysisResult["verdict"];

  switch (risk.risk_level) {
    case "LOW":
      verdict = "safe";
      break;

    case "MEDIUM":
      verdict = "suspicious";
      break;

    case "HIGH":
      verdict = "dangerous";
      break;

    case "UNCERTAIN":
      verdict = "suspicious";
      break;

    default:
      verdict = "suspicious";
  }

  const contentType =
    inputType === "url" ? "URL" : inputType === "sms" ? "SMS" : "Email";

  let summary = "";

  if (risk.risk_level === "LOW") {
    summary = `The ${contentType} has a low overall risk score based on the machine-learning signal and rule-based security checks.`;
  } else if (risk.risk_level === "MEDIUM") {
    summary = `The ${contentType} contains some indicators that require caution. Review the detected signals before interacting with it.`;
  } else if (risk.risk_level === "HIGH") {
    summary = `The ${contentType} shows strong phishing or scam indicators based on the machine-learning model and rule-based analysis.`;
  } else {
    summary = `The analysis produced an uncertain result. Review the detected indicators carefully before interacting with this ${contentType.toLowerCase()}.`;
  }

  let recommendations: string[];

  if (inputType === "url") {
    recommendations = [
      "Do not enter passwords, payment details, or sensitive information unless the destination is independently verified.",
      "If the link came from an email or SMS, verify the sender through an official channel.",
      "When in doubt, navigate directly to the organization's official website instead of using the supplied link.",
    ];
  } else if (inputType === "sms") {
    recommendations = [
      "Do not reply with passwords, OTPs, payment details, or other sensitive information.",
      "Verify the sender through an official channel before taking any requested action.",
      "If the message contains a link, avoid opening it and navigate directly to the organization's official website or app.",
    ];
  } else {
    recommendations = [
      "Do not reply with passwords, OTPs, payment details, or other sensitive information.",
      "Verify the sender through an official channel before taking any requested action.",
      "Avoid opening suspicious links or attachments contained in the email.",
      "If the email claims to be from an organization, access the organization's official website directly rather than using links in the email.",
    ];
  }

  if (risk.risk_level === "HIGH") {
    if (inputType === "url") {
      recommendations.unshift(
        "Treat this URL as potentially malicious and avoid interacting with it.",
      );
    } else if (inputType === "sms") {
      recommendations.unshift(
        "Treat this SMS as potentially malicious and avoid following its instructions.",
      );
    } else {
      recommendations.unshift(
        "Treat this email as potentially malicious and avoid following its instructions or opening its links and attachments.",
      );
    }
  }

  return {
    score: Math.round(risk.risk_score),
    verdict,
    indicators,
    summary,
    recommendations,
    inputType,
    analyzedAt: new Date().toLocaleString(),
  };
};

// =========================================================
// Component
// =========================================================

const ThreatAnalyzer = () => {
  const [activeTab, setActiveTab] = useState("email");

  const [result, setResult] = useState<AnalysisResult | null>(null);

  // Email fields
  const [emailSubject, setEmailSubject] = useState(examples.email.subject);

  const [emailBody, setEmailBody] = useState(examples.email.body);

  // SMS / URL field
  const [inputValue, setInputValue] = useState("");

  const [reportOpen, setReportOpen] = useState(false);

  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const [copied, setCopied] = useState(false);

  const [analysisError, setAnalysisError] = useState<string | null>(null);

  const [backendResult, setBackendResult] =
    useState<BackendAnalysisResponse | null>(null);

  const [cursor, setCursor] = useState({
    x: 0,
    y: 0,
  });

  const [history, setHistory] = useState<HistoryItem[]>([]);

  // =======================================================
  // Cursor tracking
  // =======================================================

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      setCursor({
        x: e.clientX,
        y: e.clientY,
      });
    };

    window.addEventListener("mousemove", handleMouseMove);

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
    };
  }, []);

  // =======================================================
  // Helpers
  // =======================================================

  const clearCurrentResult = () => {
    setResult(null);
    setBackendResult(null);
    setAnalysisError(null);
  };

  const getCurrentText = () => {
    if (activeTab === "email") {
      return `${emailSubject}\n${emailBody}`.trim();
    }

    return inputValue;
  };

  // =======================================================
  // Tab change
  // =======================================================

  const handleTabChange = (val: string) => {
    setActiveTab(val);

    clearCurrentResult();

    if (val === "email") {
      setEmailSubject(examples.email.subject);

      setEmailBody(examples.email.body);

      setInputValue("");
    } else if (val === "sms") {
      setInputValue(examples.sms);

      setEmailSubject("");
      setEmailBody("");
    } else {
      setInputValue(examples.url);

      setEmailSubject("");
      setEmailBody("");
    }
  };

  // =======================================================
  // Analyze
  // =======================================================

  const handleAnalyze = async () => {
    if (activeTab === "email" && !emailSubject.trim() && !emailBody.trim()) {
      return;
    }

    if (activeTab !== "email" && !inputValue.trim()) {
      return;
    }

    setIsAnalyzing(true);
    setAnalysisError(null);
    setResult(null);
    setBackendResult(null);

    try {
      let analysis: AnalysisResult;

      let savedBackendResult: BackendAnalysisResponse | null = null;

      let historyText = "";

      // ===================================================
      // URL
      // ===================================================

      if (activeTab === "url") {
        const response = await analyzeURLWithBackend(inputValue.trim());

        savedBackendResult = response;

        setBackendResult(response);

        analysis = convertBackendToAnalysisResult(response, "url");

        historyText = inputValue.trim();
      }

      // ===================================================
      // SMS
      // ===================================================
      else if (activeTab === "sms") {
        const response = await analyzeSMSWithBackend(inputValue.trim());

        savedBackendResult = response;

        setBackendResult(response);

        analysis = convertBackendToAnalysisResult(response, "sms");

        historyText = inputValue.trim();
      }

      // ===================================================
      // EMAIL
      // ===================================================
      else if (activeTab === "email") {
        const subject = emailSubject.trim();

        const body = emailBody.trim();

        const response = await analyzeEmailWithBackend(subject, body);

        savedBackendResult = response;

        setBackendResult(response);

        analysis = convertBackendToAnalysisResult(response, "email");

        historyText = body
          ? `Subject: ${subject}\nBody: ${body}`
          : `Subject: ${subject}`;
      }

      // ===================================================
      // Fallback
      // ===================================================
      else {
        await new Promise((resolve) => setTimeout(resolve, 800));

        analysis = analyzeContent(
          inputValue,
          activeTab as "email" | "sms" | "url",
        );

        historyText = inputValue;
      }

      // ===================================================
      // Display result
      // ===================================================

      setResult(analysis);

      // ===================================================
      // Save history
      // ===================================================

      setHistory((prev) => [
        {
          text: historyText,
          subject: activeTab === "email" ? emailSubject : undefined,
          result: analysis,
          date: new Date().toLocaleTimeString(),
          backendResult: savedBackendResult,
        },
        ...prev.slice(0, 4),
      ]);
    } catch (error) {
      console.error("Threat analysis failed:", error);

      const message =
        error instanceof Error ? error.message : "Unable to analyze the input.";

      setAnalysisError(message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  // =======================================================
  // Copy
  // =======================================================

  const handleCopy = () => {
    const currentText = getCurrentText();

    const text = `${activeTab.toUpperCase()}: ${currentText}

Risk Score: ${result?.score}%
Verdict: ${result?.verdict.toUpperCase()}
${
  backendResult
    ? `ML Probability: ${Math.round(
        backendResult.prediction.ml_probability * 100,
      )}%`
    : ""
}
${
  backendResult
    ? `Rule Score: ${Math.round(backendResult.risk.rule_score)}`
    : ""
}
${backendResult ? `Final Risk: ${backendResult.risk.risk_level}` : ""}`;

    navigator.clipboard.writeText(text);

    setCopied(true);

    setTimeout(() => setCopied(false), 2000);
  };

  // =======================================================
  // Detected threats
  // =======================================================

  const detectedThreats = result?.indicators.filter((i) => i.detected) || [];

  // =======================================================
  // Threat icon
  // =======================================================

  const threatIcon = (severity: string) => {
    if (severity === "critical") return XCircle;

    if (severity === "high") return AlertTriangle;

    return CheckCircle;
  };

  // =======================================================
  // Render
  // =======================================================

  return (
    <section className="relative min-h-screen px-4 py-24 overflow-hidden">
      {/* Animated background */}

      <div className="fixed inset-0 -z-10">
        <div className="absolute inset-0 bg-gradient-to-b from-black via-slate-900 to-black" />

        <ParticleBackground cursor={cursor} />

        <div className="absolute top-0 left-1/4 w-96 h-96 bg-primary/20 rounded-full mix-blend-screen blur-3xl opacity-30 animate-pulse" />

        <div
          className="absolute bottom-0 right-1/4 w-96 h-96 bg-accent/20 rounded-full mix-blend-screen blur-3xl opacity-30 animate-pulse"
          style={{
            animationDelay: "1s",
          }}
        />
      </div>

      {/* Cursor glow */}

      <div
        className="fixed pointer-events-none z-50 transition-opacity duration-150"
        style={{
          top: cursor.y,
          left: cursor.x,
          transform: "translate(-50%, -50%)",
          width: "300px",
          height: "300px",
          background:
            "radial-gradient(circle, rgba(348, 83, 90, 0.15), transparent 70%)",
          filter: "blur(60px)",
        }}
      />

      <div className="max-w-5xl mx-auto space-y-8 relative z-10">
        {/* Header */}

        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 mb-4 px-4 py-2 rounded-full border border-primary/30 bg-primary/10">
            <Shield className="w-4 h-4 text-primary" />

            <span className="text-sm font-semibold text-primary">
              Advanced Threat Detection
            </span>

            <Zap className="w-4 h-4 text-primary" />
          </div>

          <h2 className="text-4xl md:text-5xl font-bold mb-3 text-gradient-primary">
            Threat Analyzer
          </h2>

          <p className="text-muted-foreground max-w-2xl mx-auto">
            Real-time phishing and scam detection using machine learning and
            rule-based security analysis
          </p>
        </div>

        {/* Input Card */}

        <div className="group relative">
          <div className="absolute inset-0 bg-gradient-to-r from-primary/20 to-accent/20 rounded-2xl blur-xl opacity-0 group-hover:opacity-100 transition-all duration-500" />

          <div className="relative glass-card rounded-2xl p-8 border border-border/50 group-hover:border-primary/50 transition-all duration-300">
            <Tabs value={activeTab} onValueChange={handleTabChange}>
              <TabsList className="bg-secondary/50 border border-border/50 mb-6 w-full">
                <TabsTrigger
                  value="email"
                  className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-2 flex-1"
                >
                  <Mail className="w-4 h-4" />
                  EMAIL
                </TabsTrigger>

                <TabsTrigger
                  value="sms"
                  className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-2 flex-1"
                >
                  <MessageSquare className="w-4 h-4" />
                  SMS
                </TabsTrigger>

                <TabsTrigger
                  value="url"
                  className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-2 flex-1"
                >
                  <Link className="w-4 h-4" />
                  URL
                </TabsTrigger>
              </TabsList>

              {/* =================================================
                  EMAIL
              ================================================= */}

              <TabsContent value="email" className="space-y-4">
                {/* Subject */}

                <div className="relative group">
                  <label className="block text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-2">
                    Subject
                  </label>

                  <input
                    type="text"
                    className="w-full bg-secondary/30 border-2 border-border/50 group-focus-within:border-primary/50 rounded-xl px-4 py-3 text-sm text-foreground focus:outline-none focus:ring-0 transition-all duration-300 backdrop-blur-sm"
                    value={emailSubject}
                    onChange={(e) => {
                      setEmailSubject(e.target.value);

                      clearCurrentResult();
                    }}
                    placeholder="Enter the email subject..."
                  />

                  <div className="absolute bottom-3 right-3 text-xs text-muted-foreground">
                    {emailSubject.length}
                  </div>
                </div>

                {/* Body */}

                <div className="relative group">
                  <label className="block text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-2">
                    Email Body
                  </label>

                  <textarea
                    className="w-full bg-secondary/30 border-2 border-border/50 group-focus-within:border-primary/50 rounded-xl p-4 text-sm text-foreground resize-none focus:outline-none focus:ring-0 min-h-[180px] transition-all duration-300 backdrop-blur-sm"
                    value={emailBody}
                    onChange={(e) => {
                      setEmailBody(e.target.value);

                      clearCurrentResult();
                    }}
                    placeholder="Paste the email body here..."
                  />

                  <div className="absolute bottom-3 right-3 text-xs text-muted-foreground">
                    {emailBody.length} characters
                  </div>
                </div>
              </TabsContent>

              {/* =================================================
                  SMS
              ================================================= */}

              <TabsContent value="sms" className="space-y-4">
                <div className="relative group">
                  <textarea
                    className="w-full bg-secondary/30 border-2 border-border/50 group-focus-within:border-primary/50 rounded-xl p-4 text-sm text-foreground resize-none focus:outline-none focus:ring-0 min-h-[180px] transition-all duration-300 backdrop-blur-sm"
                    value={inputValue}
                    onChange={(e) => {
                      setInputValue(e.target.value);

                      clearCurrentResult();
                    }}
                    placeholder="Paste the SMS message here..."
                  />

                  <div className="absolute top-3 right-3 text-xs text-muted-foreground">
                    {inputValue.length} characters
                  </div>
                </div>
              </TabsContent>

              {/* =================================================
                  URL
              ================================================= */}

              <TabsContent value="url" className="space-y-4">
                <div className="relative group">
                  <input
                    type="url"
                    className="w-full bg-secondary/30 border-2 border-border/50 group-focus-within:border-primary/50 rounded-xl px-4 py-4 text-sm text-foreground focus:outline-none focus:ring-0 transition-all duration-300 backdrop-blur-sm"
                    value={inputValue}
                    onChange={(e) => {
                      setInputValue(e.target.value);

                      clearCurrentResult();
                    }}
                    placeholder="Paste the URL here..."
                  />

                  <div className="absolute top-1/2 -translate-y-1/2 right-3 text-xs text-muted-foreground">
                    {inputValue.length} characters
                  </div>
                </div>
              </TabsContent>
            </Tabs>

            {/* Error */}

            {analysisError && (
              <div className="mt-4 p-4 rounded-lg border border-danger/50 bg-danger/10 text-danger text-sm">
                <div className="flex items-center gap-2 font-semibold mb-1">
                  <XCircle className="w-4 h-4" />
                  Analysis Failed
                </div>

                <p>{analysisError}</p>

                <p className="mt-2 text-xs opacity-80">
                  Make sure the FastAPI backend is running at
                  http://127.0.0.1:8000
                </p>
              </div>
            )}

            {/* Analyze button */}

            <div className="flex gap-3 mt-6">
              <button
                onClick={handleAnalyze}
                disabled={
                  isAnalyzing ||
                  (activeTab === "email" &&
                    !emailSubject.trim() &&
                    !emailBody.trim()) ||
                  (activeTab !== "email" && !inputValue.trim())
                }
                className="flex-1 inline-flex items-center justify-center gap-2 bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary/70 disabled:opacity-50 disabled:cursor-not-allowed text-primary-foreground px-6 py-3 rounded-xl text-sm font-semibold transition-all duration-300 group"
              >
                <Shield className="w-4 h-4 group-hover:animate-spin" />

                {isAnalyzing
                  ? "ANALYZING..."
                  : activeTab === "email"
                    ? "ANALYZE EMAIL"
                    : "ANALYZE THREAT"}
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

        {/* =================================================
            Backend ML Summary
        ================================================= */}

        {backendResult && (
          <div className="grid md:grid-cols-3 gap-4 animate-fade-in-up">
            {/* ML Probability */}

            <div className="glass-card rounded-xl p-5 border border-border/50">
              <div className="text-xs uppercase tracking-widest text-muted-foreground mb-2">
                ML Probability
              </div>

              <div className="text-3xl font-bold text-primary">
                {Math.round(backendResult.prediction.ml_probability * 100)}%
              </div>

              <div className="text-xs text-muted-foreground mt-1">
                {activeTab === "url"
                  ? "Random Forest phishing probability"
                  : "TF-IDF + Logistic Regression probability"}
              </div>
            </div>

            {/* Rule Score */}

            <div className="glass-card rounded-xl p-5 border border-border/50">
              <div className="text-xs uppercase tracking-widest text-muted-foreground mb-2">
                Rule Score
              </div>

              <div className="text-3xl font-bold text-primary">
                {Math.round(backendResult.risk.rule_score)}
              </div>

              <div className="text-xs text-muted-foreground mt-1">
                Security indicator score
              </div>
            </div>

            {/* Final Risk */}

            <div className="glass-card rounded-xl p-5 border border-border/50">
              <div className="text-xs uppercase tracking-widest text-muted-foreground mb-2">
                Final Risk
              </div>

              <div className="text-3xl font-bold text-primary">
                {backendResult.risk.risk_level}
              </div>

              <div className="text-xs text-muted-foreground mt-1">
                Combined risk engine result
              </div>
            </div>
          </div>
        )}

        {/* =================================================
            Result Card
        ================================================= */}

        {result && (
          <div className="group relative animate-fade-in-up">
            <div className="absolute inset-0 bg-gradient-to-r from-alert-card via-transparent to-alert-card rounded-2xl blur-xl opacity-40 group-hover:opacity-60 transition-all duration-500" />

            <div className="relative alert-card p-8 rounded-2xl border-2 border-primary/30 group-hover:border-primary/50 transition-all duration-300">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div
                    className={`p-2 rounded-lg ${
                      result.verdict === "safe"
                        ? "bg-success/20"
                        : "bg-danger/20"
                    }`}
                  >
                    <Shield
                      className={`w-5 h-5 ${
                        result.verdict === "safe"
                          ? "text-success"
                          : "text-danger"
                      }`}
                    />
                  </div>

                  <div>
                    <div className="text-xs font-bold tracking-widest uppercase text-muted-foreground">
                      Threat Status
                    </div>

                    <div className="flex items-center gap-2">
                      <span
                        className={`text-lg font-bold ${
                          result.verdict === "safe"
                            ? "text-success"
                            : "text-primary"
                        }`}
                      >
                        {result.verdict === "safe" ? "SAFE" : "PHISHING ALERT"}
                      </span>

                      {result.verdict !== "safe" && (
                        <span className="inline-block w-2 h-2 bg-primary rounded-full animate-pulse" />
                      )}
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

                      {result.verdict === "safe"
                        ? "No Threats Detected"
                        : "Detected Threats"}
                    </h3>

                    <ul className="space-y-3">
                      {detectedThreats.map((t) => {
                        const Icon = threatIcon(t.severity);

                        return (
                          <li
                            key={t.id}
                            className="flex items-center gap-3 p-3 bg-secondary/30 border border-border/30 rounded-lg hover:border-primary/50 transition-all duration-300"
                          >
                            <Icon
                              className={`w-5 h-5 flex-shrink-0 ${
                                t.severity === "critical"
                                  ? "text-danger"
                                  : t.severity === "high"
                                    ? "text-primary"
                                    : "text-success"
                              }`}
                            />

                            <span className="text-foreground/90 flex-1">
                              {t.label}
                            </span>

                            <span
                              className={`text-xs font-bold uppercase tracking-wider px-2 py-1 rounded ${
                                t.severity === "critical"
                                  ? "bg-danger/20 text-danger"
                                  : t.severity === "high"
                                    ? "bg-primary/20 text-primary"
                                    : "bg-warning/20 text-warning"
                              }`}
                            >
                              {t.severity}
                            </span>
                          </li>
                        );
                      })}

                      {detectedThreats.length === 0 && (
                        <li className="flex items-center gap-3 p-3 bg-success/10 border border-success/30 rounded-lg">
                          <CheckCircle className="w-5 h-5 text-success" />

                          <span className="text-success">
                            All checks passed — no threats detected
                          </span>
                        </li>
                      )}
                    </ul>
                  </div>

                  {/* Risk warning */}

                  {result.score >= 20 && (
                    <div
                      className={`p-4 rounded-lg border ${
                        result.score >= 70
                          ? "bg-danger/10 border-danger/50"
                          : "bg-warning/10 border-warning/50"
                      }`}
                    >
                      <div className="flex items-center gap-2 text-sm font-bold">
                        <AlertTriangle
                          className={`w-4 h-4 ${
                            result.score >= 70 ? "text-danger" : "text-warning"
                          }`}
                        />

                        <span
                          className={
                            result.score >= 70 ? "text-danger" : "text-warning"
                          }
                        >
                          {result.score >= 70
                            ? "⚠️ HIGH RISK PHISHING ATTEMPT!"
                            : result.score >= 45
                              ? "⚠️ POSSIBLE PHISHING ATTEMPT!"
                              : "🛡️ EXERCISE CAUTION"}
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Gauge */}

                <div className="flex flex-col items-center justify-center gap-6">
                  <ScoreGauge
                    score={result.score}
                    size={180}
                    label="Scam Risk"
                  />

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
                          className={`h-full transition-all ${
                            result.score >= 70
                              ? "bg-danger"
                              : result.score >= 45
                                ? "bg-warning"
                                : "bg-primary"
                          }`}
                          style={{
                            width: `${result.score}%`,
                          }}
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

        {/* =================================================
            History
        ================================================= */}

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
                    setResult(item.result);

                    setBackendResult(item.backendResult);

                    setAnalysisError(null);

                    setActiveTab(item.result.inputType);

                    if (item.result.inputType === "email") {
                      setEmailSubject(item.subject || "");

                      const storedText = item.text;

                      if (storedText.startsWith("Subject:")) {
                        const parts = storedText.split("\nBody: ");

                        setEmailSubject(
                          parts[0].replace("Subject:", "").trim(),
                        );

                        setEmailBody(parts[1] || "");
                      } else {
                        setEmailBody(storedText);
                      }

                      setInputValue("");
                    } else {
                      setInputValue(item.text);

                      setEmailSubject("");

                      setEmailBody("");
                    }
                  }}
                >
                  <div className="flex items-start justify-between mb-2">
                    <span
                      className={`text-xs font-bold px-2 py-1 rounded ${
                        item.result.verdict === "safe"
                          ? "bg-success/20 text-success"
                          : "bg-danger/20 text-danger"
                      }`}
                    >
                      {item.result.verdict.toUpperCase()}
                    </span>

                    <span className="text-xs text-muted-foreground">
                      {item.date}
                    </span>
                  </div>

                  <p className="text-sm text-foreground/70 whitespace-pre-line line-clamp-2 group-hover:text-foreground/90 transition-colors">
                    {item.text.substring(0, 160)}
                    ...
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Threat Report */}

        <ThreatReport
          open={reportOpen}
          onOpenChange={setReportOpen}
          result={result}
          backendResult={backendResult}
        />
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
