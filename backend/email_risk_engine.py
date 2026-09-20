import re

from backend.risk_engine import analyze_rules


URGENCY_TERMS = {
    "urgent",
    "immediately",
    "act now",
    "action required",
    "final notice",
    "expires today",
    "last chance",
    "as soon as possible",
}

ACCOUNT_TERMS = {
    "account",
    "account suspended",
    "account locked",
    "bank account",
    "profile",
}

VERIFICATION_TERMS = {
    "verify",
    "verification",
    "confirm",
    "confirmation",
    "validate",
    "authenticate",
}

CREDENTIAL_TERMS = {
    "password",
    "username",
    "login",
    "log in",
    "credentials",
    "passcode",
    "otp",
    "one-time password",
}

FINANCIAL_TERMS = {
    "bank",
    "payment",
    "invoice",
    "transaction",
    "credit card",
    "debit card",
    "refund",
    "billing",
    "wire transfer",
}

REWARD_TERMS = {
    "winner",
    "winning",
    "prize",
    "reward",
    "lottery",
    "congratulations",
    "free gift",
}

THREAT_TERMS = {
    "suspended",
    "blocked",
    "closed",
    "legal action",
    "penalty",
    "unauthorized",
    "compromised",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".jar",
    ".msi",
    ".zip",
}

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    flags=re.IGNORECASE,
)

HTML_SCRIPT_PATTERN = re.compile(
    r"<\s*(script|iframe|object|embed)\b|"
    r"\bjavascript\s*:|\bon(?:error|load|click)\s*=",
    flags=re.IGNORECASE,
)


def find_terms(text: str, terms: set[str]) -> list[str]:
    text_lower = text.lower()

    return [
        term
        for term in sorted(terms)
        if re.search(
            rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])",
            text_lower,
        )
    ]


def extract_urls(text: str) -> list[str]:
    urls = []

    for match in URL_PATTERN.findall(text):
        cleaned = match.rstrip(".,!?;:)]}")

        if cleaned and cleaned not in urls:
            urls.append(cleaned)

    return urls


def deduplicate_indicators(indicators: list[dict]) -> list[dict]:
    unique = []
    seen = set()

    for indicator in indicators:
        key = (
            indicator.get("type"),
            indicator.get("severity"),
            indicator.get("message"),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(indicator)

    return unique


def analyze_email_rules(
    subject: str,
    body: str,
) -> dict:

    subject = subject or ""
    body = body or ""

    text = f"{subject}\n{body}"
    text_lower = text.lower()

    score = 0
    indicators = []

    # --------------------------------------------------------
    # Urgency
    # --------------------------------------------------------

    urgency = find_terms(
        text,
        URGENCY_TERMS,
    )

    if urgency:
        score += 10

        indicators.append({
            "type": "urgency",
            "severity": "medium",
            "message": (
                "Urgency or pressure language detected: "
                + ", ".join(urgency[:5])
            ),
        })

    # --------------------------------------------------------
    # Account
    # --------------------------------------------------------

    account = find_terms(
        text,
        ACCOUNT_TERMS,
    )

    if account:
        score += 8

        indicators.append({
            "type": "account",
            "severity": "medium",
            "message": (
                "Account-related language detected: "
                + ", ".join(account[:5])
            ),
        })

    # --------------------------------------------------------
    # Verification
    # --------------------------------------------------------

    verification = find_terms(
        text,
        VERIFICATION_TERMS,
    )

    if verification:
        score += 12

        indicators.append({
            "type": "verification",
            "severity": "medium",
            "message": (
                "Verification-related language detected: "
                + ", ".join(verification[:5])
            ),
        })

    # --------------------------------------------------------
    # Credentials
    # --------------------------------------------------------

    credentials = find_terms(
        text,
        CREDENTIAL_TERMS,
    )

    if credentials:
        score += 15

        indicators.append({
            "type": "credentials",
            "severity": "high",
            "message": (
                "Credential or authentication terms detected: "
                + ", ".join(credentials[:5])
            ),
        })

    # --------------------------------------------------------
    # Financial
    # --------------------------------------------------------

    financial = find_terms(
        text,
        FINANCIAL_TERMS,
    )

    if financial:
        score += 8

        indicators.append({
            "type": "financial",
            "severity": "medium",
            "message": (
                "Financial or payment-related terms detected: "
                + ", ".join(financial[:5])
            ),
        })

    # --------------------------------------------------------
    # Rewards
    # --------------------------------------------------------

    rewards = find_terms(
        text,
        REWARD_TERMS,
    )

    if rewards:
        score += 15

        indicators.append({
            "type": "reward",
            "severity": "high",
            "message": (
                "Prize or reward language detected: "
                + ", ".join(rewards[:5])
            ),
        })

    # --------------------------------------------------------
    # Threats
    # --------------------------------------------------------

    threats = find_terms(
        text,
        THREAT_TERMS,
    )

    if threats:
        score += 15

        indicators.append({
            "type": "threat",
            "severity": "high",
            "message": (
                "Threat or account-consequence language detected: "
                + ", ".join(threats[:5])
            ),
        })

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = extract_urls(text)

    if urls:
        score += min(len(urls) * 5, 15)

        indicators.append({
            "type": "links",
            "severity": "medium",
            "message": (
                f"{len(urls)} web link(s) detected in the email."
            ),
        })

        url_rule_score = 0

        for url in urls:
            url_result = analyze_rules(url)
            url_rule_score += url_result["rule_score"]

            for url_indicator in url_result["indicators"]:
                indicator_type = url_indicator["type"]

                if indicator_type not in {
                    "url_shortener",
                    "ip_address",
                    "suspicious_tld",
                    "brand_impersonation",
                    "brand_action_combination",
                    "at_symbol",
                    "encoded_url",
                }:
                    continue

                indicators.append({
                    "type": f"email_{indicator_type}",
                    "severity": url_indicator["severity"],
                    "message": (
                        f"Suspicious URL detected ({url}): "
                        f"{url_indicator['message']}"
                    ),
                })

        if url_rule_score:
            score += min(url_rule_score, 40)

            indicators.append({
                "type": "suspicious_url",
                "severity": "high" if url_rule_score >= 25 else "medium",
                "message": (
                    f"Suspicious URL evidence detected in "
                    f"{len(urls)} email link(s)."
                ),
            })

    # --------------------------------------------------------
    # Attachments / executable files
    # --------------------------------------------------------

    suspicious_files = []

    for extension in SUSPICIOUS_EXTENSIONS:
        if extension in text_lower:
            suspicious_files.append(extension)

    if suspicious_files:
        score += 25

        indicators.append({
            "type": "attachment",
            "severity": "critical",
            "message": (
                "Potentially dangerous file type referenced: "
                + ", ".join(suspicious_files)
            ),
        })

    # --------------------------------------------------------
    # High-risk combinations
    # --------------------------------------------------------

    if account and verification:
        score += 15

        indicators.append({
            "type": "account_verification",
            "severity": "high",
            "message": (
                "Account-related and verification language "
                "appear together."
            ),
        })

    if credentials and urls:
        score += 20

        indicators.append({
            "type": "credential_link",
            "severity": "critical",
            "message": (
                "Credential-related language appears together "
                "with a web link."
            ),
        })

    if financial and urgency:
        score += 15

        indicators.append({
            "type": "financial_urgency",
            "severity": "high",
            "message": (
                "Financial language appears together with "
                "urgent pressure."
            ),
        })

    if rewards and (urls or urgency):
        score += 15

        indicators.append({
            "type": "reward_link",
            "severity": "high",
            "message": (
                "Reward/prize language appears with a link "
                "or urgency."
            ),
        })

    if HTML_SCRIPT_PATTERN.search(text):
        score += 20

        indicators.append({
            "type": "html_script_content",
            "severity": "high",
            "message": (
                "Script-like or active HTML content was detected."
            ),
        })

    score = min(score, 100)

    indicators = deduplicate_indicators(indicators)

    return {
        "rule_score": score,
        "indicators": indicators,
    }