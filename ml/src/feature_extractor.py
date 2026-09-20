import math
import re
from urllib.parse import urlparse


# ==========================================
# SUSPICIOUS WORDS
# ==========================================

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "authenticate",
    "authentication",
    "wallet",
    "payment",
    "billing",
    "bank",
    "paypal",
    "unlock",
    "suspended",
    "restricted",
]


# ==========================================
# SHORTENED URL SERVICES
# ==========================================

SHORTENED_DOMAINS = [
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
]


# ==========================================
# SUSPICIOUS TLDs
# ==========================================

SUSPICIOUS_TLDS = [
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
]


# ==========================================
# ENTROPY
# ==========================================

def calculate_entropy(text):
    """
    Calculate Shannon entropy of a string.
    """

    if not text:
        return 0.0

    probabilities = [
        text.count(char) / len(text)
        for char in set(text)
    ]

    return -sum(
        p * math.log2(p)
        for p in probabilities
        if p > 0
    )


# ==========================================
# URL FEATURE EXTRACTION
# ==========================================

def extract_features(url):
    """
    Extract numerical features from a raw URL.

    IMPORTANT:
    This function is used during both
    training and inference.
    """

    url = str(url).strip()

    # --------------------------------------
    # Add scheme if missing
    # --------------------------------------

    parse_url = url

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parse_url):
        parse_url = "http://" + parse_url

    parsed = urlparse(parse_url)

    # --------------------------------------
    # Basic URL components
    # --------------------------------------

    domain = parsed.netloc.lower()

    # Remove username/password if present
    if "@" in domain:
        domain = domain.split("@")[-1]

    # Remove port
    domain = domain.split(":")[0]

    path = parsed.path or ""
    query = parsed.query or ""

    # --------------------------------------
    # Character counts
    # --------------------------------------

    digit_count = sum(char.isdigit() for char in url)

    letter_count = sum(char.isalpha() for char in url)

    special_char_count = sum(
        not char.isalnum()
        for char in url
    )

    dot_count = url.count(".")

    hyphen_count = url.count("-")

    underscore_count = url.count("_")

    slash_count = url.count("/")

    question_count = url.count("?")

    equal_count = url.count("=")

    at_count = url.count("@")

    ampersand_count = url.count("&")

    percent_count = url.count("%")

    # --------------------------------------
    # Domain statistics
    # --------------------------------------

    domain_digit_count = sum(
        char.isdigit()
        for char in domain
    )

    domain_has_hyphen = int(
        "-" in domain
    )

    # --------------------------------------
    # Path statistics
    # --------------------------------------

    path_digit_count = sum(
        char.isdigit()
        for char in path
    )

    # --------------------------------------
    # Subdomain count
    # --------------------------------------

    domain_parts = [
        part
        for part in domain.split(".")
        if part
    ]

    if len(domain_parts) >= 2:
        subdomain_count = max(
            0,
            len(domain_parts) - 2
        )
    else:
        subdomain_count = 0

    # --------------------------------------
    # IP address detection
    # --------------------------------------

    is_domain_ip = int(
        bool(
            re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                domain
            )
        )
    )

    # --------------------------------------
    # HTTPS
    # --------------------------------------

    is_https = int(
        parsed.scheme.lower() == "https"
    )

    # --------------------------------------
    # Suspicious words
    # --------------------------------------

    url_lower = url.lower()

    suspicious_word_count = sum(
        1
        for word in SUSPICIOUS_WORDS
        if word in url_lower
    )

    # --------------------------------------
    # Specific keyword indicators
    # --------------------------------------

    has_login_keyword = int(
        any(
            word in url_lower
            for word in [
                "login",
                "signin",
                "sign-in",
            ]
        )
    )

    has_verify_keyword = int(
        any(
            word in url_lower
            for word in [
                "verify",
                "verification",
                "confirm",
                "confirmation",
            ]
        )
    )

    has_account_keyword = int(
        "account" in url_lower
    )

    has_secure_keyword = int(
        "secure" in url_lower
    )

    has_update_keyword = int(
        "update" in url_lower
    )

    has_auth_keyword = int(
        any(
            word in url_lower
            for word in [
                "auth",
                "authenticate",
                "authentication",
            ]
        )
    )

    has_password_keyword = int(
        any(
            word in url_lower
            for word in [
                "password",
                "credential",
            ]
        )
    )

    # --------------------------------------
    # Shortened URL detection
    # --------------------------------------

    is_shortened = int(
        any(
            domain == short_domain
            or domain.endswith("." + short_domain)
            for short_domain in SHORTENED_DOMAINS
        )
    )

    # --------------------------------------
    # Suspicious TLD detection
    # --------------------------------------

    is_suspicious_tld = int(
        any(
            domain.endswith(tld)
            for tld in SUSPICIOUS_TLDS
        )
    )

    # --------------------------------------
    # Percent encoding
    # --------------------------------------

    has_percent_encoding = int(
        bool(
            re.search(
                r"%[0-9a-fA-F]{2}",
                url
            )
        )
    )

    # --------------------------------------
    # URL fragment
    # --------------------------------------

    has_fragment = int(
        bool(parsed.fragment)
    )

    # --------------------------------------
    # Query parameter count
    # --------------------------------------

    if query:
        query_parameter_count = len(
            query.split("&")
        )
    else:
        query_parameter_count = 0

    # --------------------------------------
    # URL entropy
    # --------------------------------------

    url_entropy = calculate_entropy(url)

    # ======================================
    # RETURN FEATURES
    # ======================================

    return {

        "URLLength": len(url),

        "DomainLength": len(domain),

        "PathLength": len(path),

        "QueryLength": len(query),

        "DigitCount": digit_count,

        "LetterCount": letter_count,

        "SpecialCharCount": special_char_count,

        "DotCount": dot_count,

        "HyphenCount": hyphen_count,

        "UnderscoreCount": underscore_count,

        "SlashCount": slash_count,

        "QuestionCount": question_count,

        "EqualCount": equal_count,

        "AtCount": at_count,

        "AmpersandCount": ampersand_count,

        "PercentCount": percent_count,

        "SubdomainCount": subdomain_count,

        "IsDomainIP": is_domain_ip,

        "IsHTTPS": is_https,

        "SuspiciousWordCount": suspicious_word_count,

        "IsShortened": is_shortened,

        "IsSuspiciousTLD": is_suspicious_tld,

        "HasPercentEncoding": has_percent_encoding,

        "HasFragment": has_fragment,

        "URLEntropy": url_entropy,

        "DomainHasHyphen": domain_has_hyphen,

        "DomainDigitCount": domain_digit_count,

        "PathDigitCount": path_digit_count,

        "QueryParameterCount": query_parameter_count,

        "HasLoginKeyword": has_login_keyword,

        "HasVerifyKeyword": has_verify_keyword,

        "HasAccountKeyword": has_account_keyword,

        "HasSecureKeyword": has_secure_keyword,

        "HasUpdateKeyword": has_update_keyword,

        "HasAuthKeyword": has_auth_keyword,

        "HasPasswordKeyword": has_password_keyword,
    }