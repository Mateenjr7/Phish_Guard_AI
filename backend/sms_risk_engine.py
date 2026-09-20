import re


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


def _find_terms(text: str, terms: set[str]) -> list[str]:
    found = []

    lower_text = text.lower()

    for term in terms:
        if term in lower_text:
            found.append(term)

    return sorted(found)


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
    rewards = _find_terms(text, REWARD_TERMS)
    threats = _find_terms(text, THREAT_TERMS)

    has_link = bool(LINK_PATTERN.search(text))
    has_phone = bool(PHONE_PATTERN.search(text))
    has_money = bool(MONEY_PATTERN.search(text))

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

    return {
        "rule_score": rule_score,
        "indicators": indicators,
    }