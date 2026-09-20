export type ThreatSeverity = "low" | "medium" | "high" | "critical";

export type AnalysisVerdict =
  | "safe"
  | "suspicious"
  | "dangerous"
  | "critical";

export type InputType = "email" | "sms" | "url";

export interface ThreatIndicator {
  id: string;
  label: string;
  description: string;
  severity: ThreatSeverity;
  detected: boolean;
  weight: number;
}

export interface AnalysisResult {
  score: number;
  verdict: AnalysisVerdict;
  indicators: ThreatIndicator[];
  summary: string;
  recommendations: string[];
  inputType: InputType;
  analyzedAt: string;
}

const suspiciousTerms = {
  email: [
    "verify",
    "urgent",
    "secure",
    "login",
    "account",
    "password",
    "bank",
    "warning",
    "suspended",
    "confirm",
    "update",
    "immediately",
  ],

  sms: [
    "urgent",
    "verify",
    "bank",
    "account",
    "secure",
    "login",
    "password",
    "lockout",
    "suspended",
    "confirm",
    "immediately",
  ],

  url: [
    "verify",
    "login",
    "secure",
    "account",
    "signin",
    "bank",
    "password",
    "update",
    "confirm",
    "auth",
    "pay",
    "wallet",
  ],
};

const suspiciousTlds = [
  ".xyz",
  ".top",
  ".click",
  ".link",
  ".tk",
  ".ga",
  ".cf",
  ".ml",
];

const shortenDomains = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "shorturl.at",
];

const addIndicator = (
  list: ThreatIndicator[],
  id: string,
  label: string,
  description: string,
  severity: ThreatSeverity,
  detected: boolean,
  weight: number,
): void => {
  list.push({
    id,
    label,
    description,
    severity,
    detected,
    weight,
  });
};

const getVerdict = (score: number): AnalysisVerdict => {
  if (score >= 75) return "critical";
  if (score >= 50) return "dangerous";
  if (score >= 25) return "suspicious";
  return "safe";
};

export function analyzeContent(
  input: string,
  inputType: InputType,
): AnalysisResult {
  const text = input.trim();
  const normalized = text.toLowerCase();

  const indicators: ThreatIndicator[] = [];

  const signalCount = (words: string[]) =>
    words.filter((word) => normalized.includes(word)).length;

  const threatWeight = (matches: number, base: number) =>
    matches * base;

  let score = 0;

  if (!text) {
    return {
      score: 0,
      verdict: "safe",
      indicators: [],
      summary:
        "The input is empty, so there are no phishing indicators to flag.",
      recommendations: [
        "Enter a URL, SMS, or email sample to analyze.",
      ],
      inputType,
      analyzedAt: new Date().toLocaleString(),
    };
  }

  const matches = signalCount(suspiciousTerms[inputType]);

  if (matches > 0) {
    const weight = threatWeight(matches, 12);
    score += weight;

    addIndicator(
      indicators,
      "suspicious-terms",
      "Urgency / credential language",
      "Suspicious wording such as verify, login, password, or urgent action was detected.",
      matches >= 3 ? "high" : "medium",
      true,
      weight,
    );
  }

  if (/(https?:\/\/|www\.)/i.test(text)) {
    score += 10;

    addIndicator(
      indicators,
      "link-present",
      "External link detected",
      "The message includes an external link, which is common in phishing attempts.",
      "medium",
      true,
      10,
    );
  }

  const suspiciousDomainMatch = suspiciousTlds.some((tld) =>
    normalized.includes(tld),
  );

  if (suspiciousDomainMatch) {
    score += 18;

    addIndicator(
      indicators,
      "suspicious-domain",
      "Suspicious top-level domain",
      "The domain ends in a known phishing-style TLD such as .xyz or .tk.",
      "high",
      true,
      18,
    );
  }

  if (
    shortenDomains.some((domain) =>
      normalized.includes(domain),
    )
  ) {
    score += 20;

    addIndicator(
      indicators,
      "shortened-link",
      "Shortened or obfuscated link",
      "A URL shortener or obfuscated link was detected, which is commonly used to hide phishing destinations.",
      "high",
      true,
      20,
    );
  }

  if (
    /\b(?:urgent|immediately|action required|confirm now|verify now)\b/i.test(
      text,
    )
  ) {
    score += 14;

    addIndicator(
      indicators,
      "urgency-pressure",
      "Urgency pressure",
      "The message tries to create urgency so the user acts before thinking.",
      "medium",
      true,
      14,
    );
  }

  if (/\d{4,}/.test(text)) {
    score += 8;

    addIndicator(
      indicators,
      "numeric-code",
      "Numeric token / code pattern",
      "The message includes a long numeric identifier or code, which can signal account or verification campaigns.",
      "low",
      true,
      8,
    );
  }

  if (/[A-Z]{8,}/.test(text)) {
    score += 6;

    addIndicator(
      indicators,
      "all-caps",
      "Heavy capitalization",
      "The content uses large blocks of uppercase text to amplify urgency or alarm.",
      "low",
      true,
      6,
    );
  }

  const safetyChecks = [
    "The message is free of known credential-harvesting language.",
    "The content does not include suspicious shortened links or risky domains.",
    "The message does not strongly pressure the user into immediate action.",
  ];

  const cleanIndicators: ThreatIndicator[] =
    safetyChecks.map((item, index) => ({
      id: `safe-check-${index}`,
      label: item,
      description: item,
      severity: "low",
      detected: false,
      weight: 0,
    }));

  const verdict = getVerdict(score);

  const summary =
    score === 0
      ? "No phishing indicators were found in this content."
      : verdict === "safe"
        ? "This content looks mostly normal, though a few benign risk signs are present."
        : verdict === "suspicious"
          ? "This content contains several signs commonly associated with phishing attempts."
          : verdict === "dangerous"
            ? "This content shows strong phishing indicators and should be treated with caution."
            : "This content is highly consistent with a phishing or scam attempt.";

  const recommendations = [
    "Do not click or open links from untrusted sources without verification.",
    "Confirm the sender or website through an official channel before taking action.",
    "Avoid entering login credentials or payment information unless you independently validated the destination.",
  ];

  if (score >= 50) {
    recommendations.unshift(
      "Treat this message as potentially malicious and do not interact with the included link.",
    );
  }

  return {
    score: Math.min(score, 100),
    verdict,
    indicators:
      indicators.length > 0
        ? indicators
        : cleanIndicators,
    summary,
    recommendations,
    inputType,
    analyzedAt: new Date().toLocaleString(),
  };
}