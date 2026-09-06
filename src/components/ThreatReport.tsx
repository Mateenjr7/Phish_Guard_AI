import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Shield, AlertTriangle, CheckCircle, XCircle, Clock, FileText } from "lucide-react";
import type { AnalysisResult } from "@/lib/threatAnalysis";

interface ThreatReportProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  result: AnalysisResult | null;
}

const severityColors: Record<string, string> = {
  low: "text-muted-foreground",
  medium: "text-warning",
  high: "text-primary",
  critical: "text-danger",
};

const severityBg: Record<string, string> = {
  low: "bg-muted/30",
  medium: "bg-warning/10",
  high: "bg-primary/10",
  critical: "bg-danger/10",
};

const verdictConfig = {
  safe: { label: "SAFE", color: "text-success", bg: "bg-success/10", icon: CheckCircle },
  suspicious: { label: "SUSPICIOUS", color: "text-warning", bg: "bg-warning/10", icon: AlertTriangle },
  dangerous: { label: "DANGEROUS", color: "text-primary", bg: "bg-primary/10", icon: AlertTriangle },
  critical: { label: "CRITICAL THREAT", color: "text-danger", bg: "bg-danger/10", icon: XCircle },
};

const ThreatReport = ({ open, onOpenChange, result }: ThreatReportProps) => {
  if (!result) return null;

  const verdict = verdictConfig[result.verdict];
  const VerdictIcon = verdict.icon;
  const detected = result.indicators.filter(i => i.detected);
  const clean = result.indicators.filter(i => !i.detected);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto bg-card border-border/50">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-foreground">
            <FileText className="w-5 h-5 text-primary" />
            Threat Analysis Report
          </DialogTitle>
          <DialogDescription className="flex items-center gap-2 text-xs text-muted-foreground">
            <Clock className="w-3 h-3" />
            {result.analyzedAt} • {result.inputType} Analysis
          </DialogDescription>
        </DialogHeader>

        {/* Verdict Banner */}
        <div className={`rounded-lg p-4 ${verdict.bg} border border-border/30`}>
          <div className="flex items-center gap-3">
            <VerdictIcon className={`w-8 h-8 ${verdict.color}`} />
            <div>
              <p className={`text-lg font-bold tracking-wider ${verdict.color}`}>{verdict.label}</p>
              <p className="text-sm text-muted-foreground mt-1">{result.summary}</p>
            </div>
            <div className="ml-auto text-right">
              <p className="text-3xl font-bold text-foreground">{result.score}%</p>
              <p className="text-xs text-muted-foreground">Risk Score</p>
            </div>
          </div>
        </div>

        {/* Detected Threats */}
        {detected.length > 0 && (
          <div>
            <h3 className="text-sm font-bold text-foreground mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />
              THREATS DETECTED ({detected.length})
            </h3>
            <div className="space-y-2">
              {detected.map((ind) => (
                <div key={ind.id} className={`rounded-lg p-3 ${severityBg[ind.severity]} border border-border/20`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-semibold text-foreground">{ind.label}</span>
                    <span className={`text-xs font-bold uppercase tracking-wider ${severityColors[ind.severity]}`}>
                      {ind.severity}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground">{ind.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Clean Checks */}
        {clean.length > 0 && (
          <div>
            <h3 className="text-sm font-bold text-foreground mb-3 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-success" />
              PASSED CHECKS ({clean.length})
            </h3>
            <div className="grid grid-cols-2 gap-2">
              {clean.map((ind) => (
                <div key={ind.id} className="flex items-center gap-2 text-xs text-muted-foreground bg-secondary/20 rounded-md px-3 py-2">
                  <CheckCircle className="w-3 h-3 text-success flex-shrink-0" />
                  {ind.label}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommendations */}
        <div>
          <h3 className="text-sm font-bold text-foreground mb-3">RECOMMENDATIONS</h3>
          <ul className="space-y-2">
            {result.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                <span className="text-primary font-bold mt-0.5">›</span>
                {rec}
              </li>
            ))}
          </ul>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default ThreatReport;
