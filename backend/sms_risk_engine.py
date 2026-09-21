import re

from backend.risk_engine import analyze_rules


URGENT_TERMS = {
    "urgent",
    "immediately",
    "urgent action",
    "act now",
    "limited time",
    "expires",
    "last chance",
}

ACCOUNT_TERMS = {
    "account",
    "bank",
    "wallet",
    "card",
    "payment",
    "billing",
    "transaction",
}

VERIFICATION_TERMS = {
    "verify",
    "verification",
    "confirm",
    "validate",
    "authenticate",
    "security check",
}

CREDENTIAL_TERMS = {
    "password",
    "otp",
    "pin",
    "cvv",
    "login",
    "username",
    "credentials",
}

FINANCIAL_TERMS = {
    "payment",
    "invoice",
    "transaction",
    "credit card",
    "debit card",
    "billing",
    "wire transfer",
}

REWARD_TERMS = {
    "winner",
    "won",
    "prize",
    "reward",
    "gift",
    "bonus",
    "lottery",
    "cashback",
}

THREAT_TERMS = {
    "suspended",
    "blocked",
    "locked",
    "closed",
    "deactivated",
    "terminated",
    "unauthorized",
}

LINK_PATTERN = re.compile(
    r"(https?://|www\.)",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(
    r"\+?\d[\d\s().-]{7,}\d"
)

MONEY_PATTERN = re.compile(
    r"(₹|\$|€|£|\b(?:usd|inr|dollars?|rupees?)\b)",
    re.IGNORECASE,
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)

LINK_ACTION_TERMS = {
    "click",
    "open",
    "visit",
    "tap",
    "follow",
}


def _find_terms(text: str, terms: set[str]) -> list[str]:
    found = []

    lower_text = text.lower()

    for term in terms:
        if term in lower_text:
            found.append(term)

    return sorted(found)


def _extract_urls(text: str) -> list[str]:
    urls = []

    for match in URL_PATTERN.findall(text):
        cleaned = match.rstrip(".,!?;:)]}")

        if cleaned and cleaned not in urls:
            urls.append(cleaned)

    return urls


def _deduplicate_indicators(indicators: list[dict]) -> list[dict]:
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


def analyze_sms_rules(text: str) -> dict:
    text = text.strip()

    if not text:
        raise ValueError("SMS text cannot be empty.")

    indicators = []
    rule_score = 0

    urgent = _find_terms(text, URGENT_TERMS)
    account = _find_terms(text, ACCOUNT_TERMS)
    verification = _find_terms(text, VERIFICATION_TERMS)
    credentials = _find_terms(text, CREDENTIAL_TERMS)
    financial = _find_terms(text, FINANCIAL_TERMS)
    rewards = _find_terms(text, REWARD_TERMS)
    threats = _find_terms(text, THREAT_TERMS)

    urls = _extract_urls(text)
    has_link = bool(urls) or bool(LINK_PATTERN.search(text))
    text_without_urls = URL_PATTERN.sub("", text)
    has_phone = bool(PHONE_PATTERN.search(text_without_urls))
    has_money = bool(MONEY_PATTERN.search(text))
    link_actions = _find_terms(text, LINK_ACTION_TERMS)

    if urgent:
        rule_score += 10

        indicators.append({
            "type": "urgency",
            "severity": "medium",
            "message": (
                "Urgency or pressure language detected: "
                + ", ".join(urgent)
            ),
        })

    if account:
        rule_score += 8

        indicators.append({
            "type": "account_terms",
            "severity": "medium",
            "message": (
                "Financial or account-related terms detected: "
                + ", ".join(account)
            ),
        })

    if verification:
        rule_score += 12

        indicators.append({
            "type": "verification",
            "severity": "medium",
            "message": (
                "Verification-related language detected: "
                + ", ".join(verification)
            ),
        })

    if credentials:
        rule_score += 15

        indicators.append({
            "type": "credentials",
            "severity": "high",
            "message": (
                "Credential or authentication terms detected: "
                + ", ".join(credentials)
            ),
        })

    if financial:
        rule_score += 8

        indicators.append({
            "type": "financial_request",
            "severity": "medium",
            "message": (
                "Financial or payment-related terms detected: "
                + ", ".join(financial)
            ),
        })

    if rewards:
        rule_score += 15

        indicators.append({
            "type": "reward_scam",
            "severity": "high",
            "message": (
                "Prize, reward, or lottery-related language detected: "
                + ", ".join(rewards)
            ),
        })

    if threats:
        rule_score += 15

        indicators.append({
            "type": "threat_language",
            "severity": "high",
            "message": (
                "Account-threat language detected: "
                + ", ".join(threats)
            ),
        })

    if has_link:
        rule_score += 10

        indicators.append({
            "type": "link",
            "severity": "medium",
            "message": "A web link was detected in the message.",
        })

    if link_actions and has_link:
        rule_score += 5

        indicators.append({
            "type": "link_action",
            "severity": "medium",
            "message": (
                "A request to open or follow a web link was detected: "
                + ", ".join(link_actions)
            ),
        })

    if urls:
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
                    "type": f"sms_{indicator_type}",
                    "severity": url_indicator["severity"],
                    "message": (
                        f"Suspicious URL detected ({url}): "
                        f"{url_indicator['message']}"
                    ),
                })

        if url_rule_score:
            rule_score += min(url_rule_score, 40)

            indicators.append({
                "type": "suspicious_url",
                "severity": "high" if url_rule_score >= 25 else "medium",
                "message": (
                    f"Suspicious URL evidence detected in "
                    f"{len(urls)} SMS link(s)."
                ),
            })

    if has_phone:
        rule_score += 5

        indicators.append({
            "type": "phone_number",
            "severity": "low",
            "message": "A phone number was detected in the message.",
        })

    if has_money:
        rule_score += 5

        indicators.append({
            "type": "money",
            "severity": "low",
            "message": "Money or currency-related language was detected.",
        })

    # Strong combinations
    if account and verification:
        rule_score += 15

        indicators.append({
            "type": "account_verification_combination",
            "severity": "high",
            "message": (
                "Account-related and verification language "
                "appear together."
            ),
        })

    if rewards and (has_link or has_phone):
        rule_score += 15

        indicators.append({
            "type": "reward_contact_combination",
            "severity": "critical",
            "message": (
                "A reward/prize message includes a link or "
                "contact request."
            ),
        })

    if threats and verification:
        rule_score += 15

        indicators.append({
            "type": "threat_verification_combination",
            "severity": "critical",
            "message": (
                "Threatening account language is combined "
                "with a verification request."
            ),
        })

    rule_score = min(rule_score, 100)
    indicators = _deduplicate_indicators(indicators)

    return {
        "rule_score": rule_score,
        "indicators": indicators,
    }