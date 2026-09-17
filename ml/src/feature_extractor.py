from urllib.parse import urlparse
import re
import math


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


def extract_features(url):
    """
    Extract numerical features from a raw URL.

    Returns a dictionary of URL characteristics.
    """

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.split("@")[-1].split(":")[0]
    path = parsed.path
    query = parsed.query

    full_url = url

    # Basic URL features
    url_length = len(full_url)
    domain_length = len(domain)
    path_length = len(path)
    query_length = len(query)

    # Character features
    digit_count = sum(char.isdigit() for char in full_url)
    letter_count = sum(char.isalpha() for char in full_url)
    special_char_count = sum(
        not char.isalnum()
        for char in full_url
    )

    # Specific characters
    dot_count = full_url.count(".")
    hyphen_count = full_url.count("-")
    underscore_count = full_url.count("_")
    slash_count = full_url.count("/")
    question_count = full_url.count("?")
    equal_count = full_url.count("=")
    at_count = full_url.count("@")
    ampersand_count = full_url.count("&")
    percent_count = full_url.count("%")

    # Subdomain count
    subdomain_count = max(
        domain.count(".") - 1,
        0
    )

    # IP address detection
    is_domain_ip = int(
        bool(
            re.match(
                r"^(?:\d{1,3}\.){3}\d{1,3}$",
                domain
            )
        )
    )

    # HTTPS
    is_https = int(parsed.scheme == "https")

    # Suspicious URL patterns
    suspicious_words = [
        "login",
        "verify",
        "account",
        "secure",
        "update",
        "password",
        "bank",
        "signin",
        "confirm",
        "security",
        "payment"
    ]

    suspicious_word_count = sum(
        word in full_url.lower()
        for word in suspicious_words
    )

    # URL shortening services
    shortened_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rb.gy"
    ]

    is_shortened = int(
        any(
            domain.lower().endswith(short_domain)
            for short_domain in shortened_domains
        )
    )

    # Suspicious TLDs
    suspicious_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".xyz",
        ".top",
        ".buzz",
        ".click",
        ".link",
        ".info"
    ]

    is_suspicious_tld = int(
        any(
            domain.lower().endswith(tld)
            for tld in suspicious_tlds
        )
    )

    # Encoded characters
    has_percent_encoding = int("%" in full_url)

    # Fragment
    has_fragment = int(bool(parsed.fragment))

    # Entropy
    url_entropy = shannon_entropy(full_url)

    # Feature dictionary
    features = {
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
        "SubdomainCount": subdomain_count,
        "IsDomainIP": is_domain_ip,
        "IsHTTPS": is_https,
        "SuspiciousWordCount": suspicious_word_count,
        "IsShortened": is_shortened,
        "IsSuspiciousTLD": is_suspicious_tld,
        "HasPercentEncoding": has_percent_encoding,
        "HasFragment": has_fragment,
        "URLEntropy": url_entropy
    }

    return features


if __name__ == "__main__":

    test_urls = [
        "https://example.com",
        "https://example.com/login",
        "http://192.168.1.1/login",
        "https://secure-account-verify.xyz/login",
        "https://bit.ly/example"
    ]

    for url in test_urls:

        print("\n" + "=" * 60)
        print(f"URL: {url}")
        print("=" * 60)

        features = extract_features(url)

        for name, value in features.items():
            print(f"{name}: {value}")