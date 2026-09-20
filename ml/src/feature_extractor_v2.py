import math
import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "credential",
    "authentication",
    "auth",
    "wallet",
    "payment",
    "billing",
    "bank",
    "unlock",
    "suspended",
    "confirm",
    "confirmation",
    "recover",
    "recovery",
}

SHORTENED_DOMAINS = {
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


def shannon_entropy(text):
    """Calculate Shannon entropy of a string."""
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


def safe_ratio(numerator, denominator):
    """Return a ratio without division-by-zero errors."""
    if denominator == 0:
        return 0.0

    return numerator / denominator


def extract_features(url):
    """
    Extract lexical and structural features from a raw URL.

    Returns a dictionary of numerical features.
    """

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    # Add scheme when missing.
    parse_url = url

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parse_url):
        parse_url = "http://" + parse_url

    parsed = urlparse(parse_url)

    domain = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    url_lower = url.lower()
    domain_lower = domain.lower()
    path_lower = path.lower()
    query_lower = query.lower()

    # ---------------------------------------------------------
    # Basic lengths
    # ---------------------------------------------------------

    url_length = len(url)
    domain_length = len(domain)
    path_length = len(path)
    query_length = len(query)

    # ---------------------------------------------------------
    # Character counts
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # Ratios
    # ---------------------------------------------------------

    digit_ratio = safe_ratio(
        digit_count,
        url_length,
    )

    letter_ratio = safe_ratio(
        letter_count,
        url_length,
    )

    special_char_ratio = safe_ratio(
        special_char_count,
        url_length,
    )

    # ---------------------------------------------------------
    # Domain structure
    # ---------------------------------------------------------

    domain_parts = [
        part
        for part in domain_lower.split(".")
        if part
    ]

    # www.example.com -> 1 subdomain
    subdomain_count = max(
        len(domain_parts) - 2,
        0,
    )

    domain_digit_count = sum(
        char.isdigit()
        for char in domain
    )

    domain_digit_ratio = safe_ratio(
        domain_digit_count,
        domain_length,
    )

    domain_hyphen_count = domain.count("-")

    domain_hyphen_ratio = safe_ratio(
        domain_hyphen_count,
        domain_length,
    )

    domain_entropy = shannon_entropy(domain)

    # ---------------------------------------------------------
    # Path structure
    # ---------------------------------------------------------

    path_parts = [
        part
        for part in path.split("/")
        if part
    ]

    path_depth = len(path_parts)

    path_digit_count = sum(
        char.isdigit()
        for char in path
    )

    path_letter_count = sum(
        char.isalpha()
        for char in path
    )

    path_entropy = shannon_entropy(path)

    # ---------------------------------------------------------
    # Query structure
    # ---------------------------------------------------------

    query_parameters = [
        item
        for item in query.split("&")
        if item
    ]

    query_parameter_count = len(query_parameters)

    query_digit_count = sum(
        char.isdigit()
        for char in query
    )

    query_entropy = shannon_entropy(query)

    # ---------------------------------------------------------
    # Suspicious words
    # ---------------------------------------------------------

    suspicious_word_count = sum(
        1
        for word in SUSPICIOUS_WORDS
        if word in url_lower
    )

    has_login_keyword = int(
        any(
            word in url_lower
            for word in {
                "login",
                "signin",
                "sign-in",
            }
        )
    )

    has_verify_keyword = int(
        any(
            word in url_lower
            for word in {
                "verify",
                "verification",
                "confirm",
                "confirmation",
            }
        )
    )

    has_account_keyword = int(
        "account" in url_lower
    )

    has_secure_keyword = int(
        any(
            word in url_lower
            for word in {
                "secure",
                "security",
            }
        )
    )

    has_update_keyword = int(
        "update" in url_lower
    )

    has_auth_keyword = int(
        any(
            word in url_lower
            for word in {
                "auth",
                "authentication",
            }
        )
    )

    has_password_keyword = int(
        any(
            word in url_lower
            for word in {
                "password",
                "passwd",
                "pwd",
            }
        )
    )

    # ---------------------------------------------------------
    # Suspicious domain properties
    # ---------------------------------------------------------

    is_domain_ip = int(
        bool(
            re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                domain,
            )
        )
    )

    is_shortened = int(
        domain_lower in SHORTENED_DOMAINS
    )

    is_suspicious_tld = int(
        any(
            domain_lower.endswith(tld)
            for tld in SUSPICIOUS_TLDS
        )
    )

    # ---------------------------------------------------------
    # Encoding / obfuscation
    # ---------------------------------------------------------

    has_percent_encoding = int(
        bool(
            re.search(
                r"%[0-9a-fA-F]{2}",
                url,
            )
        )
    )

    encoded_char_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url,
        )
    )

    # ---------------------------------------------------------
    # Fragment
    # ---------------------------------------------------------

    has_fragment = int(
        bool(fragment)
    )

    # ---------------------------------------------------------
    # Repetition / randomness
    # ---------------------------------------------------------

    repeated_character_count = len(
        re.findall(
            r"(.)\1{2,}",
            url_lower,
        )
    )

    # ---------------------------------------------------------
    # File / resource indicators
    # ---------------------------------------------------------

    suspicious_file_extension = int(
        bool(
            re.search(
                r"\.(php|asp|aspx|jsp|cgi|exe|scr|zip|rar)(?:$|[?#])",
                path_lower,
            )
        )
    )

    # ---------------------------------------------------------
    # Brand / sensitive combination
    # ---------------------------------------------------------

    sensitive_keyword_count = sum(
        1
        for word in {
            "bank",
            "paypal",
            "apple",
            "microsoft",
            "google",
            "amazon",
            "facebook",
            "instagram",
            "linkedin",
            "netflix",
            "wallet",
            "payment",
        }
        if word in url_lower
    )

    has_sensitive_action = int(
        any(
            word in url_lower
            for word in {
                "login",
                "signin",
                "verify",
                "verification",
                "confirm",
                "update",
                "secure",
                "password",
                "authentication",
            }
        )
    )

    brand_action_combination = int(
        sensitive_keyword_count > 0
        and has_sensitive_action
    )

    # ---------------------------------------------------------
    # Return feature vector
    # ---------------------------------------------------------

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "PathLength": path_length,
        "QueryLength": query_length,

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

        "DigitRatio": digit_ratio,
        "LetterRatio": letter_ratio,
        "SpecialCharRatio": special_char_ratio,

        "SubdomainCount": subdomain_count,
        "IsDomainIP": is_domain_ip,

        "SuspiciousWordCount": suspicious_word_count,

        "IsShortened": is_shortened,
        "IsSuspiciousTLD": is_suspicious_tld,

        "HasPercentEncoding": has_percent_encoding,
        "EncodedCharCount": encoded_char_count,

        "HasFragment": has_fragment,

        "URLEntropy": shannon_entropy(url),
        "DomainEntropy": domain_entropy,
        "PathEntropy": path_entropy,
        "QueryEntropy": query_entropy,

        "DomainHasHyphen": int(domain_hyphen_count > 0),
        "DomainDigitCount": domain_digit_count,
        "DomainDigitRatio": domain_digit_ratio,
        "DomainHyphenRatio": domain_hyphen_ratio,

        "PathDepth": path_depth,
        "PathDigitCount": path_digit_count,
        "PathLetterCount": path_letter_count,

        "QueryParameterCount": query_parameter_count,
        "QueryDigitCount": query_digit_count,

        "HasLoginKeyword": has_login_keyword,
        "HasVerifyKeyword": has_verify_keyword,
        "HasAccountKeyword": has_account_keyword,
        "HasSecureKeyword": has_secure_keyword,
        "HasUpdateKeyword": has_update_keyword,
        "HasAuthKeyword": has_auth_keyword,
        "HasPasswordKeyword": has_password_keyword,

        "RepeatedCharacterCount": repeated_character_count,

        "SuspiciousFileExtension": suspicious_file_extension,

        "SensitiveKeywordCount": sensitive_keyword_count,
        "HasSensitiveAction": has_sensitive_action,
        "BrandActionCombination": brand_action_combination,
    }