const API_BASE_URL = "http://127.0.0.1:8000";

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