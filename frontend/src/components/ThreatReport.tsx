import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";

import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  FileText,
  Brain,
  Activity,
  Lock,
} from "lucide-react";

import type { AnalysisResult } from "@/lib/threatAnalysis";
import type { URLAnalysisDetails } from "@/lib/api";

interface BackendIndicator {
  type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  message: string;
}

interface BackendRisk {
  risk_score: number;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "UNCERTAIN";
  ml_probability: number;
  rule_score: number;
  indicators: BackendIndicator[];
}

interface BackendPrediction {
  ml_probability: number;
  ml_label: "phishing" | "phishing/spam" | "legitimate";
}

interface BackendResult {
  prediction: BackendPrediction;
  risk: BackendRisk;
  url_analysis?: URLAnalysisDetails;
}

interface ThreatReportProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  result: AnalysisResult | null;
  backendResult?: BackendResult | null;
}

const severityColors: Record<string, string> = {
  info: "text-muted-foreground",
  low: "text-muted-foreground",
  medium: "text-warning",
  high: "text-primary",
  critical: "text-danger",
};

const severityBg: Record<string, string> = {
  info: "bg-muted/30",
  low: "bg-muted/30",
  medium: "bg-warning/10",
  high: "bg-primary/10",
  critical: "bg-danger/10",
};

const verdictConfig = {
  safe: {
    label: "SAFE",
    color: "text-success",
    bg: "bg-success/10",
    icon: CheckCircle,
  },

  suspicious: {
    label: "SUSPICIOUS",
    color: "text-warning",
    bg: "bg-warning/10",
    icon: AlertTriangle,
  },

  dangerous: {
    label: "DANGEROUS",
    color: "text-primary",
    bg: "bg-primary/10",
    icon: AlertTriangle,
  },

  critical: {
    label: "CRITICAL THREAT",
    color: "text-danger",
    bg: "bg-danger/10",
    icon: XCircle,
  },
};

const ThreatReport = ({
  open,
  onOpenChange,
  result,
  backendResult,
}: ThreatReportProps) => {
  if (!result) return null;

  const verdict = verdictConfig[result.verdict];
  const VerdictIcon = verdict.icon;

  const detected = result.indicators.filter(
    (i) => i.detected,
  );

  const clean = result.indicators.filter(
    (i) => !i.detected,
  );

  const mlProbability =
    backendResult?.prediction.ml_probability ?? null;

  const ruleScore =
    backendResult?.risk.rule_score ?? null;

  const finalRisk =
    backendResult?.risk.risk_score ?? result.score;

  const riskLevel =
    backendResult?.risk.risk_level ?? null;

  const urlAnalysis = backendResult?.url_analysis;

  const urlStructureFields: Array<[
    string,
    string | number,
  ]> = urlAnalysis
    ? [
        ["Protocol", urlAnalysis.protocol.toUpperCase()],
        ["Hostname", urlAnalysis.hostname || "-"],
        ["Root Domain", urlAnalysis.registrable_domain || "-"],
        ["TLD", urlAnalysis.tld || "-"],
        ["Subdomains", urlAnalysis.subdomain_count],
        ["IP Address", urlAnalysis.is_ip_address ? "Yes" : "No"],
        ["URL Length", urlAnalysis.url_length],
        ["Domain Length", urlAnalysis.domain_length],
        ["Path Depth", urlAnalysis.path_depth],
        ["Query Parameters", urlAnalysis.query_parameter_count],
        ["Port", urlAnalysis.port ?? "-"],
      ]
    : [];

  const urlSecuritySignals: Array<[string, boolean]> = urlAnalysis
    ? [
        ["HTTPS", urlAnalysis.protocol === "https"],
        ["Percent Encoding", urlAnalysis.has_percent_encoding],
        ["@ Symbol", urlAnalysis.has_at_symbol],
        ["URL Shortener", urlAnalysis.is_shortened],
        ["Suspicious TLD", urlAnalysis.is_suspicious_tld],
      ]
    : [];

  /*
   * Removes a severity accidentally appended to the
   * frontend indicator label, e.g.
   *
   * "urgentmedium"
   * "account, bankmedium"
   *
   * while preserving legitimate words such as
   * "medium" when they are actually part of the message.
   */
  const cleanIndicatorLabel = (
    label: string,
    severity: string,
  ) => {
    const normalizedSeverity = severity.toLowerCase();

    const suffix = new RegExp(
      `${normalizedSeverity}$`,
      "i",
    );

    return label.replace(suffix, "").trim();
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
    >
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto bg-card border-border/50">

        {/* =================================================
            Header
        ================================================= */}

        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-foreground">
            <FileText className="w-5 h-5 text-primary" />

            Threat Analysis Report
          </DialogTitle>

          <DialogDescription className="flex items-center gap-2 text-xs text-muted-foreground">
            <Clock className="w-3 h-3" />

            {result.analyzedAt}

            <span>•</span>

            {result.inputType} Analysis
          </DialogDescription>
        </DialogHeader>

        {/* =================================================
            Verdict Banner
        ================================================= */}

        <div
          className={`rounded-lg p-4 ${verdict.bg} border border-border/30`}
        >
          <div className="flex items-center gap-3">

            <VerdictIcon
              className={`w-8 h-8 ${verdict.color}`}
            />

            <div>
              <p
                className={`text-lg font-bold tracking-wider ${verdict.color}`}
              >
                {verdict.label}
              </p>

              <p className="text-sm text-muted-foreground mt-1">
                {result.summary}
              </p>
            </div>

            <div className="ml-auto text-right">
              <p className="text-3xl font-bold text-foreground">
                {Math.round(finalRisk)}%
              </p>

              <p className="text-xs text-muted-foreground">
                Final Risk
              </p>
            </div>

          </div>
        </div>

        {/* =================================================
            ML + Rules Summary
        ================================================= */}

        {backendResult && (
          <div className="grid md:grid-cols-3 gap-3">

            {/* ML */}

            <div className="rounded-xl p-4 bg-secondary/20 border border-border/30">

              <div className="flex items-center gap-2 mb-2">
                <Brain className="w-4 h-4 text-primary" />

                <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  Machine Learning
                </span>
              </div>

              <div className="text-2xl font-bold text-primary">
                {Math.round(
                  (mlProbability ?? 0) * 100,
                )}
                %
              </div>

              <p className="text-xs text-muted-foreground mt-1">
                Phishing probability
              </p>

              <div className="mt-3 h-1.5 bg-secondary rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all"
                  style={{
                    width: `${Math.min(
                      (mlProbability ?? 0) * 100,
                      100,
                    )}%`,
                  }}
                />
              </div>

            </div>

            {/* Rules */}

            <div className="rounded-xl p-4 bg-secondary/20 border border-border/30">

              <div className="flex items-center gap-2 mb-2">
                <Activity className="w-4 h-4 text-warning" />

                <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  Rule Engine
                </span>
              </div>

              <div className="text-2xl font-bold text-warning">
                {Math.round(ruleScore ?? 0)}
              </div>

              <p className="text-xs text-muted-foreground mt-1">
                Security indicator score
              </p>

              <div className="mt-3 h-1.5 bg-secondary rounded-full overflow-hidden">
                <div
                  className="h-full bg-warning transition-all"
                  style={{
                    width: `${Math.min(
                      ruleScore ?? 0,
                      100,
                    )}%`,
                  }}
                />
              </div>

            </div>

            {/* Final */}

            <div className="rounded-xl p-4 bg-secondary/20 border border-border/30">

              <div className="flex items-center gap-2 mb-2">
                <Shield className="w-4 h-4 text-success" />

                <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  Risk Engine
                </span>
              </div>

              <div className="text-2xl font-bold text-foreground">
                {Math.round(finalRisk)}%
              </div>

              <p className="text-xs text-muted-foreground mt-1">
                Final combined risk
              </p>

              <div className="mt-2">
                <span
                  className={`text-xs font-bold tracking-wider ${
                    riskLevel === "HIGH"
                      ? "text-danger"
                      : riskLevel === "MEDIUM"
                        ? "text-warning"
                        : "text-success"
                  }`}
                >
                  {riskLevel ??
                    result.verdict.toUpperCase()}
                </span>
              </div>

            </div>

          </div>
        )}

        {/* =================================================
            Detection Method
        ================================================= */}

        {backendResult && (
          <div className="rounded-lg border border-border/30 bg-secondary/10 p-4">

            <div className="flex items-center gap-2 mb-2">
              <Lock className="w-4 h-4 text-primary" />

              <h3 className="text-sm font-bold text-foreground">
                DETECTION METHOD
              </h3>
            </div>

            <p className="text-xs text-muted-foreground">
              This result combines a machine-learning
              probability with deterministic security
              indicators from the PhishGuard rule engine.
            </p>

            <div className="grid sm:grid-cols-2 gap-2 mt-3">

              <div className="rounded-md bg-secondary/30 px-3 py-2">
                <span className="text-xs text-muted-foreground">
                  ML Model
                </span>

                <p className="text-sm font-semibold text-foreground">
                  {result.inputType === "url"
                    ? "Random Forest"
                    : "TF-IDF + Logistic Regression"}
                </p>
              </div>

              <div className="rounded-md bg-secondary/30 px-3 py-2">
                <span className="text-xs text-muted-foreground">
                  Analysis Type
                </span>

                <p className="text-sm font-semibold text-foreground">
                  {result.inputType}
                </p>
              </div>

            </div>

          </div>
        )}

        {result.inputType === "url" && urlAnalysis && (
            <div className="rounded-lg border border-border/30 bg-secondary/10 p-4">
              <h3 className="text-sm font-bold text-foreground mb-3">
                URL ANALYSIS
              </h3>

              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <p className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2">
                    URL Structure
                  </p>

                  <div className="grid grid-cols-2 gap-2">
                    {urlStructureFields.map(([label, value]) => (
                      <div
                        key={label}
                        className="rounded-md bg-secondary/30 px-3 py-2"
                      >
                        <span className="text-xs text-muted-foreground">
                          {label}
                        </span>
                        <p className="text-sm font-semibold text-foreground break-words">
                          {value}
                        </p>
                      </div>
                    ))}
                  </div>

                  <div className="rounded-md bg-secondary/30 px-3 py-2 mt-2">
                    <span className="text-xs text-muted-foreground">
                      Path
                    </span>
                    <p className="text-sm font-semibold text-foreground break-all">
                      {urlAnalysis.path || "/"}
                    </p>
                  </div>
                </div>

                <div>
                  <p className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2">
                    Security Signals
                  </p>

                  <div className="grid gap-2">
                    {urlSecuritySignals.map(([label, detected]) => (
                      <div
                        key={label}
                        className="flex items-center justify-between rounded-md bg-secondary/30 px-3 py-2"
                      >
                        <span className="text-sm text-foreground">
                          {label}
                        </span>
                        <span
                          className={`text-xs font-bold uppercase ${detected ? "text-warning" : "text-success"}`}
                        >
                          {detected ? "Detected" : "Not detected"}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

        {/* =================================================
            Detected Threats
        ================================================= */}

        {detected.length > 0 && (
          <div>

            <h3 className="text-sm font-bold text-foreground mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />

              THREATS DETECTED ({detected.length})
            </h3>

            <div className="space-y-2">

              {detected.map((ind) => {

                const cleanLabel =
                  cleanIndicatorLabel(
                    ind.label,
                    ind.severity,
                  );

                return (
                  <div
                    key={ind.id}
                    className={`rounded-lg p-3 ${
                      severityBg[ind.severity]
                    } border border-border/20`}
                  >

                    <div className="flex items-center justify-between mb-1">

                      <span className="text-sm font-semibold text-foreground">
                        {cleanLabel}
                      </span>

                      <span
                        className={`text-xs font-bold uppercase tracking-wider ${
                          severityColors[ind.severity]
                        }`}
                      >
                        {ind.severity.toUpperCase()}
                      </span>

                    </div>

                    <p className="text-xs text-muted-foreground">
                      {ind.description}
                    </p>

                  </div>
                );

              })}

            </div>
          </div>
        )}

        {/* =================================================
            Clean Checks
        ================================================= */}

        {clean.length > 0 && (
          <div>

            <h3 className="text-sm font-bold text-foreground mb-3 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-success" />

              PASSED CHECKS ({clean.length})
            </h3>

            <div className="grid grid-cols-2 gap-2">

              {clean.map((ind) => (
                <div
                  key={ind.id}
                  className="flex items-center gap-2 text-xs text-muted-foreground bg-secondary/20 rounded-md px-3 py-2"
                >

                  <CheckCircle className="w-3 h-3 text-success flex-shrink-0" />

                  {ind.label}

                </div>
              ))}

            </div>
          </div>
        )}

        {/* =================================================
            Recommendations
        ================================================= */}

        <div>

          <h3 className="text-sm font-bold text-foreground mb-3">
            RECOMMENDATIONS
          </h3>

          <ul className="space-y-2">

            {result.recommendations.map(
              (rec, i) => (
                <li
                  key={i}
                  className="flex items-start gap-2 text-sm text-muted-foreground"
                >

                  <span className="text-primary font-bold mt-0.5">
                    ›
                  </span>

                  {rec}

                </li>
              ),
            )}

          </ul>

        </div>

      </DialogContent>
    </Dialog>
  );
};

export default ThreatReport;