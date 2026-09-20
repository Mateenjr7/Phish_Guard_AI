from urllib.parse import urlparse
import re

from backend.threat_intelligence import ThreatIntelEvidence


MAX_THREAT_INTEL_SCORE = 30
THREAT_INTEL_SEVERITY_SCORES = {
    "info": 5,
    "low": 5,
    "medium": 10,
    "high": 20,
    "critical": 30,
}


def _indicator_key(indicator: dict) -> tuple:
    return (
        indicator.get("type"),
        indicator.get("severity"),
        indicator.get("message"),
    )


def _deduplicate_indicators(
    indicators: list[dict],
) -> list[dict]:
    unique_indicators = []
    seen = set()

    for indicator in indicators:
        key = _indicator_key(indicator)

        if key in seen:
            continue

        seen.add(key)
        unique_indicators.append(indicator)

    return unique_indicators


def _threat_intel_score(
    threat_intel: ThreatIntelEvidence,
) -> tuple[int, str | None]:
    adjustment = 0
    highest_severity = None
    severity_order = {
        "info": 0,
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }

    for indicator in threat_intel.indicators:
        severity = indicator.get("severity", "info").lower()
        adjustment += THREAT_INTEL_SEVERITY_SCORES.get(
            severity,
            0,
        )

        if (
            highest_severity is None
            or severity_order.get(severity, 0)
            > severity_order.get(highest_severity, 0)
        ):
            highest_severity = severity

    return min(adjustment, MAX_THREAT_INTEL_SCORE), highest_severity


# =========================================================
# Configuration
# =========================================================

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".link",
    ".work",
    ".zip",
    ".review",
    ".country",
    ".kim",
    ".party",
    ".gq",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
}


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "tiny.cc",
}


SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "credential",
    "authentication",
    "wallet",
    "payment",
    "billing",
    "bank",
    "unlock",
    "suspended",
    "confirm",
}


SENSITIVE_ACTIONS = {
    "login",
    "signin",
    "verify",
    "update",
    "confirm",
    "authentication",
    "password",
    "payment",
    "billing",
}


BRANDS = {
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "google",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "dropbox",
    "github",
}


# Official registrable domains for brands we explicitly recognize.
#
# This is deliberately small and conservative. A production
# version can use a maintained threat-intelligence/domain
# database instead.
LEGITIMATE_BRAND_DOMAINS = {
    "paypal": {
        "paypal.com",
    },
    "microsoft": {
        "microsoft.com",
        "live.com",
        "office.com",
        "outlook.com",
    },
    "apple": {
        "apple.com",
        "icloud.com",
    },
    "amazon": {
        "amazon.com",
        "amazon.in",
    },
    "google": {
        "google.com",
    },
    "facebook": {
        "facebook.com",
        "fb.com",
    },
    "instagram": {
        "instagram.com",
    },
    "linkedin": {
        "linkedin.com",
    },
    "netflix": {
        "netflix.com",
    },
    "dropbox": {
        "dropbox.com",
    },
    "github": {
        "github.com",
    },
}


# =========================================================
# Helpers
# =========================================================

def normalize_url(url: str) -> str:

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def tokenize(text: str) -> set[str]:

    return {
        token.lower()
        for token in re.split(
            r"[^a-zA-Z0-9]+",
            text,
        )
        if token
    }


def get_registrable_domain(hostname: str) -> str:

    """
    Lightweight registrable-domain approximation.

    Example:
        www.github.com -> github.com
        secure.github.com -> github.com
        example.co.uk -> example.co.uk

    This intentionally avoids pretending to be a complete
    Public Suffix List implementation.
    """

    hostname = hostname.lower().strip(".")

    parts = hostname.split(".")

    if len(parts) <= 2:
        return hostname

    # Handle common two-level country-code suffixes.
    common_second_level = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "com.br",
        "co.jp",
        "co.in",
    }

    suffix = ".".join(parts[-2:])

    if suffix in common_second_level and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def brand_is_on_legitimate_domain(
    brand: str,
    registrable_domain: str,
) -> bool:

    return registrable_domain in (
        LEGITIMATE_BRAND_DOMAINS.get(
            brand,
            set(),
        )
    )


# =========================================================
# Rule analysis
# =========================================================

def analyze_rules(url: str) -> dict:

    normalized = normalize_url(url)

    parsed = urlparse(normalized)

    domain = (parsed.hostname or "").lower()

    registrable_domain = get_registrable_domain(
        domain
    )

    full_text = normalized.lower()

    indicators = []

    rule_score = 0


    # -----------------------------------------------------
    # HTTP
    # -----------------------------------------------------

    if parsed.scheme == "http":

        indicators.append({
            "type": "insecure_protocol",
            "severity": "medium",
            "message": "URL uses HTTP instead of HTTPS.",
        })

        rule_score += 10


    # -----------------------------------------------------
    # IP address
    # -----------------------------------------------------

    ip_pattern = re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if ip_pattern.match(domain):

        indicators.append({
            "type": "ip_address",
            "severity": "high",
            "message": "URL uses an IP address instead of a domain.",
        })

        rule_score += 30


    # -----------------------------------------------------
    # Suspicious TLD
    # -----------------------------------------------------

    if any(
        domain.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    ):

        indicators.append({
            "type": "suspicious_tld",
            "severity": "high",
            "message": "Domain uses a commonly abused TLD.",
        })

        rule_score += 25


    # -----------------------------------------------------
    # URL shortener
    # -----------------------------------------------------

    if domain in SHORTENERS:

        indicators.append({
            "type": "url_shortener",
            "severity": "medium",
            "message": "URL uses a URL-shortening service.",
        })

        rule_score += 20


    # -----------------------------------------------------
    # @ symbol
    # -----------------------------------------------------

    if "@" in normalized:

        indicators.append({
            "type": "at_symbol",
            "severity": "high",
            "message": "URL contains an @ symbol.",
        })

        rule_score += 30


    # -----------------------------------------------------
    # Percent encoding
    # -----------------------------------------------------

    if "%" in normalized:

        indicators.append({
            "type": "encoded_url",
            "severity": "medium",
            "message": "URL contains percent-encoded characters.",
        })

        rule_score += 10


    tokens = tokenize(full_text)


    # -----------------------------------------------------
    # Suspicious keywords
    # -----------------------------------------------------

    suspicious_found = sorted(
        tokens.intersection(
            SUSPICIOUS_WORDS
        )
    )

    if suspicious_found:

        indicators.append({
            "type": "suspicious_keywords",
            "severity": "medium",
            "message": (
                "Suspicious security-related terms found: "
                + ", ".join(suspicious_found)
            ),
        })

        rule_score += min(
            len(suspicious_found) * 7,
            25,
        )


    # -----------------------------------------------------
    # Sensitive actions
    # -----------------------------------------------------

    actions_found = sorted(
        tokens.intersection(
            SENSITIVE_ACTIONS
        )
    )

    if actions_found:

        indicators.append({
            "type": "sensitive_actions",
            "severity": "medium",
            "message": (
                "Sensitive account/action terms found: "
                + ", ".join(actions_found)
            ),
        })

        rule_score += min(
            len(actions_found) * 5,
            20,
        )


    # -----------------------------------------------------
    # Brand detection
    # -----------------------------------------------------

    brand_found = sorted(
        tokens.intersection(BRANDS)
    )

    legitimate_brands = []
    impersonated_brands = []


    for brand in brand_found:

        if brand_is_on_legitimate_domain(
            brand,
            registrable_domain,
        ):
            legitimate_brands.append(brand)

        else:
            impersonated_brands.append(brand)


    # -----------------------------------------------------
    # Legitimate brand
    # -----------------------------------------------------

    for brand in legitimate_brands:

        indicators.append({
            "type": "recognized_brand_domain",
            "severity": "info",
            "message": (
                f"{brand} appears on its recognized "
                "official domain."
            ),
        })

        # IMPORTANT:
        # No risk points are added.


    # -----------------------------------------------------
    # Brand on unrelated domain
    # -----------------------------------------------------

    if impersonated_brands:

        indicators.append({
            "type": "brand_impersonation",
            "severity": "high",
            "message": (
                "Brand reference appears on an unrelated "
                "domain: "
                + ", ".join(impersonated_brands)
            ),
        })

        rule_score += min(
            len(impersonated_brands) * 20,
            40,
        )


    # -----------------------------------------------------
    # Brand + sensitive action
    # -----------------------------------------------------

    if (
        impersonated_brands
        and actions_found
    ):

        indicators.append({
            "type": "brand_action_combination",
            "severity": "critical",
            "message": (
                "A known brand appears on an unrelated "
                "domain together with sensitive account "
                "or security actions."
            ),
        })

        rule_score += 30


    return {
        "rule_score": min(rule_score, 100),
        "indicators": indicators,
    }


# =========================================================
# Combined risk engine
# =========================================================

def calculate_risk(
    ml_probability: float,
    rule_result: dict,
    threat_intel: ThreatIntelEvidence | None = None,
) -> dict:

    rule_score = rule_result["rule_score"]

    indicators = _deduplicate_indicators(
        list(rule_result.get("indicators", []))
    )

    confirmed_threat_intel = bool(
        threat_intel and threat_intel.matched
    )


    # -----------------------------------------------------
    # Strong rule evidence
    # -----------------------------------------------------

    has_critical = any(
        indicator["severity"] == "critical"
        for indicator in indicators
    )

    has_high = any(
        indicator["severity"] == "high"
        for indicator in indicators
    )


    # -----------------------------------------------------
    # ML confidence
    # -----------------------------------------------------

    ml_score = ml_probability * 100


    # -----------------------------------------------------
    # Base combined score
    #
    # The structural ML model is intentionally limited
    # because external testing showed false positives on
    # legitimate URLs with complex paths.
    # -----------------------------------------------------

    combined_score = (
        ml_score * 0.30
        +
        rule_score * 0.70
    )


    # -----------------------------------------------------
    # Strong evidence overrides
    # -----------------------------------------------------

    if has_critical:

        combined_score = max(
            combined_score,
            80,
        )

    elif (
        has_high
        and rule_score >= 50
    ):

        combined_score = max(
            combined_score,
            70,
        )


    combined_score = round(
        min(
            max(combined_score, 0),
            100,
        ),
        2,
    )


    # -----------------------------------------------------
    # Uncertainty
    # -----------------------------------------------------

    if (
        0.40 <= ml_probability <= 0.60
        and
        20 <= rule_score <= 60
    ):

        risk_level = "UNCERTAIN"

    elif combined_score >= 70:

        risk_level = "HIGH"

    elif combined_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # -----------------------------------------------------
    # Important safety correction:
    #
    # A high ML probability with ZERO rule evidence
    # should not automatically become MEDIUM/HIGH.
    #
    # This addresses legitimate complex URLs such as:
    # docs.python.org/.../urllib.parse.html
    # -----------------------------------------------------

    if (
        not confirmed_threat_intel
        and
        ml_probability >= 0.90
        and
        rule_score == 0
    ):

        risk_level = "LOW"

        combined_score = round(
            min(
                combined_score,
                25,
            ),
            2,
        )


    if confirmed_threat_intel:
        threat_intel_adjustment, highest_ti_severity = (
            _threat_intel_score(threat_intel)
        )

        combined_score = round(
            min(
                combined_score + threat_intel_adjustment,
                100,
            ),
            2,
        )

        if highest_ti_severity == "critical":
            combined_score = max(combined_score, 80)
            risk_level = "HIGH"

        elif highest_ti_severity == "high":
            combined_score = max(combined_score, 70)
            risk_level = "HIGH"

        elif combined_score >= 70:
            risk_level = "HIGH"

        elif combined_score >= 40:
            risk_level = "MEDIUM"

        indicators = _deduplicate_indicators(
            indicators + threat_intel.indicators
        )

    risk_result = {
        "risk_score": combined_score,
        "risk_level": risk_level,
        "ml_probability": round(
            ml_probability,
            4,
        ),
        "rule_score": rule_score,
        "indicators": indicators,
    }

    return risk_result