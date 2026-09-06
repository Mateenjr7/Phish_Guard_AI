export interface ThreatIndicator {
  id: string;
  label: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  detected: boolean;
  weight: number;
}

export interface AnalysisResult {
  score: number;
  verdict: "safe" | "suspicious" | "dangerous" | "critical";
  indicators: ThreatIndicator[];
  summary: string;
  recommendations: string[];
  inputType: string;
  analyzedAt: string;
}

const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click", ".link", ".info"];
const SHORTENED_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rb.gy"];
const URGENT_WORDS = ["urgent", "immediately", "verify now", "act now", "suspended", "compromised", "lockout", "expire", "limited time", "account will be"];
const SENSITIVE_REQUESTS = ["password", "credit card", "ssn", "social security", "bank account", "verify your identity", "confirm your", "update your payment", "login credentials"];
const KNOWN_PHISHING_PATTERNS = ["paypa1", "amaz0n", "g00gle", "micr0soft", "app1e", "faceb00k", "netfl1x", "secure-", "-verify", "-login", "-account"];

function extractUrls(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  return text.match(urlRegex) || [];
}

function checkIndicator(id: string, label: string, desc: string, severity: ThreatIndicator["severity"], detected: boolean, weight: number): ThreatIndicator {
  return { id, label, description: desc, severity, detected, weight };
}

export function analyzeContent(input: string, type: string): AnalysisResult {
  const lower = input.toLowerCase();
  const urls = extractUrls(input);
  const indicators: ThreatIndicator[] = [];

  // 1. Suspicious/shortened URLs
  const hasShortenedUrl = urls.some(u => SHORTENED_DOMAINS.some(d => u.toLowerCase().includes(d)));
  indicators.push(checkIndicator("shortened-url", "Shortened URL detected", "URL shorteners hide the true destination, commonly used in phishing.", "medium", hasShortenedUrl, 12));

  // 2. Suspicious TLDs
  const hasSuspiciousTld = urls.some(u => SUSPICIOUS_TLDS.some(tld => u.toLowerCase().includes(tld)));
  indicators.push(checkIndicator("suspicious-tld", "Suspicious domain TLD", "The URL uses a top-level domain frequently associated with phishing campaigns.", "high", hasSuspiciousTld, 15));

  // 3. Urgent language
  const urgentCount = URGENT_WORDS.filter(w => lower.includes(w)).length;
  const hasUrgency = urgentCount > 0;
  indicators.push(checkIndicator("urgency", "Urgent/pressure language", `Found ${urgentCount} urgency indicator(s) designed to pressure quick action.`, "medium", hasUrgency, Math.min(urgentCount * 8, 20)));

  // 4. Sensitive info requests
  const sensitiveCount = SENSITIVE_REQUESTS.filter(w => lower.includes(w)).length;
  const hasSensitive = sensitiveCount > 0;
  indicators.push(checkIndicator("sensitive-request", "Requests sensitive information", `Message asks for ${sensitiveCount} type(s) of sensitive personal data.`, "high", hasSensitive, Math.min(sensitiveCount * 10, 20)));

  // 5. Known phishing patterns (typosquatting)
  const phishingPatterns = KNOWN_PHISHING_PATTERNS.filter(p => lower.includes(p));
  const hasPhishingDomain = phishingPatterns.length > 0;
  indicators.push(checkIndicator("phishing-domain", "Known phishing pattern", `Domain mimics a legitimate brand using character substitution: ${phishingPatterns.join(", ") || "none"}.`, "critical", hasPhishingDomain, 25));

  // 6. Mismatched or suspicious protocol
  const hasHttpOnly = urls.some(u => u.startsWith("http://") && !u.startsWith("https://"));
  indicators.push(checkIndicator("no-https", "Insecure HTTP connection", "Links use HTTP instead of HTTPS, indicating no encryption.", "medium", hasHttpOnly, 10));

  // 7. IP address in URL
  const hasIpUrl = urls.some(u => /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u));
  indicators.push(checkIndicator("ip-url", "IP address used instead of domain", "Legitimate services use domain names, not raw IP addresses.", "high", hasIpUrl, 18));

  // 8. Suspicious URL fragments (hash tricks)
  const hasHashTrick = urls.some(u => u.includes("#") && u.indexOf("#") < u.length - 1);
  indicators.push(checkIndicator("hash-trick", "URL fragment manipulation", "URL contains fragment identifiers that may hide the true destination.", "medium", hasHashTrick, 8));

  // 9. Generic greeting
  const hasGenericGreeting = /dear (customer|user|member|sir|madam|valued)/i.test(input) || /hello (customer|user)/i.test(input);
  indicators.push(checkIndicator("generic-greeting", "Generic greeting used", "Legitimate services typically address you by name.", "low", hasGenericGreeting, 5));

  // 10. Spelling/grammar anomalies (simple check)
  const hasSpellingIssues = /\b(recieve|verifiy|updaet|acount|pasword|securty)\b/i.test(input);
  indicators.push(checkIndicator("spelling", "Spelling anomalies", "Contains misspellings commonly used to evade email filters.", "low", hasSpellingIssues, 5));

  // Calculate score
  const detectedIndicators = indicators.filter(i => i.detected);
  const rawScore = detectedIndicators.reduce((sum, i) => sum + i.weight, 0);
  const score = Math.min(Math.round(rawScore), 100);

  // Determine verdict
  let verdict: AnalysisResult["verdict"] = "safe";
  if (score >= 70) verdict = "critical";
  else if (score >= 45) verdict = "dangerous";
  else if (score >= 20) verdict = "suspicious";

  // Generate recommendations
  const recommendations: string[] = [];
  if (score >= 20) recommendations.push("Do not click any links in this message.");
  if (hasSensitive) recommendations.push("Never share sensitive personal information via email or SMS.");
  if (hasPhishingDomain) recommendations.push("Verify the sender by visiting the official website directly.");
  if (hasUrgency) recommendations.push("Be wary of urgency tactics — legitimate services rarely pressure you.");
  if (hasShortenedUrl) recommendations.push("Avoid clicking shortened URLs from unknown sources.");
  if (score < 20) recommendations.push("This content appears relatively safe, but always stay cautious.");

  const summary = score >= 70
    ? "This content shows strong indicators of a phishing attempt. Multiple red flags were detected."
    : score >= 45
    ? "This content contains several suspicious elements consistent with phishing or scam tactics."
    : score >= 20
    ? "Some minor suspicious elements were detected. Exercise caution."
    : "No significant threats detected. The content appears relatively safe.";

  return {
    score,
    verdict,
    indicators,
    summary,
    recommendations,
    inputType: type.toUpperCase(),
    analyzedAt: new Date().toLocaleString(),
  };
}
