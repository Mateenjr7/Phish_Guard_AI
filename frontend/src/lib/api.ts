const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

// =========================================================
// Shared backend indicator
// =========================================================

export interface BackendIndicator {
  type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  message: string;
}

// =========================================================
// URL analysis
// =========================================================

export interface URLAnalysisResponse {
  url: string;

  url_analysis?: URLAnalysisDetails;

  prediction: {
    ml_probability: number;
    ml_label: "phishing" | "legitimate";
  };

  risk: {
    risk_score: number;
    risk_level: "LOW" | "MEDIUM" | "HIGH" | "UNCERTAIN";
    ml_probability: number;
    rule_score: number;
    indicators: BackendIndicator[];
  };
}

export interface URLAnalysisDetails {
  protocol: string;
  hostname: string;
  registrable_domain: string;
  tld: string;
  subdomain_count: number;
  is_ip_address: boolean;
  url_length: number;
  domain_length: number;
  path: string;
  path_depth: number;
  query_parameter_count: number;
  query: string;
  fragment: string;
  port: number | null;
  has_percent_encoding: boolean;
  has_at_symbol: boolean;
  is_shortened: boolean;
  is_suspicious_tld: boolean;
}

// =========================================================
// SMS analysis
// =========================================================

export interface SMSAnalysisResponse {
  text: string;

  prediction: {
    ml_probability: number;
    ml_label: "phishing/spam" | "legitimate";
  };

  risk: {
    risk_score: number;
    risk_level: "LOW" | "MEDIUM" | "HIGH" | "UNCERTAIN";
    ml_probability: number;
    rule_score: number;
    indicators: BackendIndicator[];
  };
}

// =========================================================
// Email analysis
// =========================================================

export interface EmailAnalysisResponse {
  subject: string;
  body: string;

  prediction: {
    ml_probability: number;
    ml_label: "phishing/spam" | "legitimate";
  };

  risk: {
    risk_score: number;
    risk_level: "LOW" | "MEDIUM" | "HIGH" | "UNCERTAIN";
    ml_probability: number;
    rule_score: number;
    indicators: BackendIndicator[];
  };
}

export type UnifiedAnalysisRequest =
  | { input_type: "url"; url: string }
  | { input_type: "sms"; text: string }
  | { input_type: "email"; subject?: string; body?: string };

export type UnifiedAnalysisResponse =
  | (URLAnalysisResponse & { input_type: "url" })
  | (SMSAnalysisResponse & { input_type: "sms" })
  | (EmailAnalysisResponse & { input_type: "email" });

// =========================================================
// URL API
// =========================================================

export async function analyzeURLWithBackend(
  url: string,
): Promise<URLAnalysisResponse> {
  const response = await fetch(
    `${API_BASE_URL}/api/analyze/url`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    },
  );

  if (!response.ok) {
    let message = "Failed to analyze URL.";

    try {
      const error = await response.json();

      if (error?.detail) {
        message = error.detail;
      }
    } catch {
      // Keep default error message.
    }

    throw new Error(message);
  }

  return response.json();
}

// =========================================================
// SMS API
// =========================================================

export async function analyzeSMSWithBackend(
  text: string,
): Promise<SMSAnalysisResponse> {
  const response = await fetch(
    `${API_BASE_URL}/api/analyze/sms`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ text }),
    },
  );

  if (!response.ok) {
    let message = "Failed to analyze SMS.";

    try {
      const error = await response.json();

      if (error?.detail) {
        message = error.detail;
      }
    } catch {
      // Ignore JSON parsing errors.
    }

    throw new Error(message);
  }

  return response.json();
}

// =========================================================
// Email API
// =========================================================

export async function analyzeEmailWithBackend(
  subject: string,
  body: string,
): Promise<EmailAnalysisResponse> {
  const response = await fetch(
    `${API_BASE_URL}/api/analyze/email`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        subject,
        body,
      }),
    },
  );

  if (!response.ok) {
    let message = "Failed to analyze email.";

    try {
      const error = await response.json();

      if (error?.detail) {
        message = error.detail;
      }
    } catch {
      // Ignore JSON parsing errors.
    }

    throw new Error(message);
  }

  return response.json();
}

// =========================================================
// Unified analysis API
// =========================================================

export async function analyzeUnifiedWithBackend(
  request: UnifiedAnalysisRequest,
): Promise<UnifiedAnalysisResponse> {
  const response = await fetch(
    `${API_BASE_URL}/api/analyze`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    },
  );

  if (!response.ok) {
    let message = "Failed to analyze input.";

    try {
      const error = await response.json();

      if (error?.detail) {
        message = error.detail;
      }
    } catch {
      // Ignore JSON parsing errors.
    }

    throw new Error(message);
  }

  return response.json();
}