import math
import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "passwd",
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
    if denominator == 0:
        return 0.0

    return numerator / denominator


def contains_token(text, token):
    """
    Match a word/token instead of arbitrary substrings.

    Example:
        login.example.com      -> True
        secure-login.example   -> True
        myloginportal.com      -> False
    """

    pattern = rf"(?<![a-zA-Z0-9]){re.escape(token)}(?![a-zA-Z0-9])"

    return bool(
        re.search(
            pattern,
            text.lower(),
        )
    )


def extract_features(url):
    """
    Extract cleaner lexical and structural phishing features.

    This extractor intentionally avoids several features that
    behaved like dataset-specific label shortcuts.
    """

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    parse_url = url

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        parse_url,
    ):
        parse_url = "http://" + parse_url

    parsed = urlparse(parse_url)

    domain = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    domain_lower = domain.lower()
    url_lower = url.lower()

    # ---------------------------------------------------------
    # Domain composition
    # ---------------------------------------------------------

    domain_length = len(domain)

    domain_parts = [
        part
        for part in domain_lower.split(".")
        if part
    ]

    subdomain_count = max(
        len(domain_parts) - 2,
        0,
    )

    domain_digit_count = sum(
        char.isdigit()
        for char in domain
    )

    domain_letter_count = sum(
        char.isalpha()
        for char in domain
    )

    domain_special_count = sum(
        not char.isalnum()
        for char in domain
    )

    domain_hyphen_count = domain.count("-")

    domain_dot_count = domain.count(".")

    domain_digit_ratio = safe_ratio(
        domain_digit_count,
        domain_length,
    )

    domain_letter_ratio = safe_ratio(
        domain_letter_count,
        domain_length,
    )

    domain_entropy = shannon_entropy(domain)

    # ---------------------------------------------------------
    # URL character composition
    # ---------------------------------------------------------

    url_length = len(url)

    digit_count = sum(
        char.isdigit()
        for char in url
    )

    letter_count = sum(
        char.isalpha()
        for char in url
    )

    special_char_count = sum(
        not char.isalnum()
        for char in url
    )

    digit_ratio = safe_ratio(
        digit_count,
        url_length,
    )

    special_char_ratio = safe_ratio(
        special_char_count,
        url_length,
    )

    # ---------------------------------------------------------
    # Separators
    # ---------------------------------------------------------

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
    # Path / query structure
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

    path_special_count = sum(
        not char.isalnum()
        for char in path
    )

    query_parameters = [
        item
        for item in query.split("&")
        if item
    ]

    query_parameter_count = len(
        query_parameters
    )

    query_digit_count = sum(
        char.isdigit()
        for char in query
    )

    # ---------------------------------------------------------
    # Entropy
    # ---------------------------------------------------------

    url_entropy = shannon_entropy(url)

    path_entropy = shannon_entropy(path)

    query_entropy = shannon_entropy(query)

    # ---------------------------------------------------------
    # IP address
    # ---------------------------------------------------------

    is_domain_ip = int(
        bool(
            re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                domain,
            )
        )
    )

    # ---------------------------------------------------------
    # TLD
    # ---------------------------------------------------------

    is_suspicious_tld = int(
        any(
            domain_lower.endswith(tld)
            for tld in SUSPICIOUS_TLDS
        )
    )

    # ---------------------------------------------------------
    # URL shortener
    # ---------------------------------------------------------

    is_shortened = int(
        domain_lower in SHORTENED_DOMAINS
    )

    # ---------------------------------------------------------
    # Obfuscation
    # ---------------------------------------------------------

    encoded_char_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url,
        )
    )

    double_slash_count = url.count("//")

    has_at_symbol = int(
        at_count > 0
    )

    # ---------------------------------------------------------
    # Suspicious lexical tokens
    # ---------------------------------------------------------

    suspicious_token_count = sum(
        contains_token(
            url_lower,
            word,
        )
        for word in SUSPICIOUS_WORDS
    )

    has_login_keyword = int(
        contains_token(url_lower, "login")
        or contains_token(url_lower, "signin")
        or contains_token(url_lower, "sign-in")
    )

    has_verify_keyword = int(
        contains_token(url_lower, "verify")
        or contains_token(url_lower, "verification")
        or contains_token(url_lower, "confirm")
        or contains_token(url_lower, "confirmation")
    )

    has_account_keyword = int(
        contains_token(url_lower, "account")
    )

    has_secure_keyword = int(
        contains_token(url_lower, "secure")
        or contains_token(url_lower, "security")
    )

    has_update_keyword = int(
        contains_token(url_lower, "update")
    )

    has_auth_keyword = int(
        contains_token(url_lower, "auth")
        or contains_token(url_lower, "authentication")
    )

    has_password_keyword = int(
        contains_token(url_lower, "password")
        or contains_token(url_lower, "passwd")
    )

    # ---------------------------------------------------------
    # Sensitive actions
    # ---------------------------------------------------------

    sensitive_action_count = sum(
        [
            has_login_keyword,
            has_verify_keyword,
            has_account_keyword,
            has_secure_keyword,
            has_update_keyword,
            has_auth_keyword,
            has_password_keyword,
        ]
    )

    # ---------------------------------------------------------
    # Brand tokens
    # ---------------------------------------------------------

    brand_tokens = {
        "paypal",
        "apple",
        "microsoft",
        "google",
        "amazon",
        "facebook",
        "instagram",
        "linkedin",
        "netflix",
    }

    brand_token_count = sum(
        contains_token(
            url_lower,
            brand,
        )
        for brand in brand_tokens
    )

    brand_sensitive_combination = int(
        brand_token_count > 0
        and sensitive_action_count > 0
    )

    # ---------------------------------------------------------
    # Repetition
    # ---------------------------------------------------------

    repeated_character_count = len(
        re.findall(
            r"(.)\1{2,}",
            url_lower,
        )
    )

    # ---------------------------------------------------------
    # Suspicious file extension
    # ---------------------------------------------------------

    suspicious_file_extension = int(
        bool(
            re.search(
                r"\.(php|asp|aspx|jsp|cgi|exe|scr)(?:$|[?#])",
                path.lower(),
            )
        )
    )

    # ---------------------------------------------------------
    # Return clean feature vector
    # ---------------------------------------------------------

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "DomainDigitCount": domain_digit_count,
        "DomainDigitRatio": domain_digit_ratio,
        "DomainLetterRatio": domain_letter_ratio,
        "DomainSpecialCount": domain_special_count,
        "DomainHyphenCount": domain_hyphen_count,
        "DomainDotCount": domain_dot_count,
        "DomainHasHyphen": int(domain_hyphen_count > 0),
        "DomainEntropy": domain_entropy,
        "SubdomainCount": subdomain_count,

        "DigitCount": digit_count,
        "DigitRatio": digit_ratio,
        "LetterCount": letter_count,
        "SpecialCharCount": special_char_count,
        "SpecialCharRatio": special_char_ratio,

        "DotCount": dot_count,
        "HyphenCount": hyphen_count,
        "UnderscoreCount": underscore_count,
        "SlashCount": slash_count,
        "QuestionCount": question_count,
        "EqualCount": equal_count,
        "AtCount": at_count,
        "AmpersandCount": ampersand_count,
        "PercentCount": percent_count,

        "IsDomainIP": is_domain_ip,
        "IsSuspiciousTLD": is_suspicious_tld,
        "IsShortened": is_shortened,

        "EncodedCharCount": encoded_char_count,
        "DoubleSlashCount": double_slash_count,
        "HasAtSymbol": has_at_symbol,

        "URLEntropy": url_entropy,
        "PathEntropy": path_entropy,
        "QueryEntropy": query_entropy,

        "PathDepth": path_depth,
        "PathDigitCount": path_digit_count,
        "PathSpecialCount": path_special_count,

        "QueryParameterCount": query_parameter_count,
        "QueryDigitCount": query_digit_count,

        "SuspiciousTokenCount": suspicious_token_count,

        "HasLoginKeyword": has_login_keyword,
        "HasVerifyKeyword": has_verify_keyword,
        "HasAccountKeyword": has_account_keyword,
        "HasSecureKeyword": has_secure_keyword,
        "HasUpdateKeyword": has_update_keyword,
        "HasAuthKeyword": has_auth_keyword,
        "HasPasswordKeyword": has_password_keyword,

        "SensitiveActionCount": sensitive_action_count,

        "BrandTokenCount": brand_token_count,
        "BrandSensitiveCombination": brand_sensitive_combination,

        "RepeatedCharacterCount": repeated_character_count,
        "SuspiciousFileExtension": suspicious_file_extension,
    }