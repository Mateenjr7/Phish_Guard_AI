import pytest

from backend.url_analysis import analyze_url_structure


def test_github_url_structure():
    result = analyze_url_structure("https://github.com")

    assert result["protocol"] == "https"
    assert result["hostname"] == "github.com"
    assert result["registrable_domain"] == "github.com"
    assert result["tld"] == ".com"
    assert result["subdomain_count"] == 0
    assert result["is_ip_address"] is False
    assert result["path"] == ""
    assert result["port"] is None


def test_http_url_structure():
    result = analyze_url_structure("http://example.com")

    assert result["protocol"] == "http"
    assert result["hostname"] == "example.com"
    assert result["is_suspicious_tld"] is False


def test_subdomain_count():
    assert analyze_url_structure(
        "https://www.example.com"
    )["subdomain_count"] == 1
    assert analyze_url_structure(
        "https://login.secure.example.com"
    )["subdomain_count"] == 2


def test_ipv4_and_ipv6_detection():
    ipv4 = analyze_url_structure(
        "https://192.168.1.1/login"
    )
    ipv6 = analyze_url_structure(
        "https://[2001:db8::1]:8443/login"
    )

    assert ipv4["is_ip_address"] is True
    assert ipv4["registrable_domain"] == "192.168.1.1"
    assert ipv6["is_ip_address"] is True
    assert ipv6["hostname"] == "2001:db8::1"
    assert ipv6["port"] == 8443


def test_path_query_and_fragment_details():
    result = analyze_url_structure(
        "https://example.com/a/b/c?a=1&b=2#section"
    )

    assert result["path"] == "/a/b/c"
    assert result["path_depth"] == 3
    assert result["query"] == "a=1&b=2"
    assert result["query_parameter_count"] == 2
    assert result["fragment"] == "section"


def test_query_parameter_edge_cases():
    assert analyze_url_structure(
        "https://example.com?a=1"
    )["query_parameter_count"] == 1
    assert analyze_url_structure(
        "https://example.com?"
    )["query_parameter_count"] == 0
    assert analyze_url_structure(
        "https://example.com?a=1&b="
    )["query_parameter_count"] == 2


def test_explicit_port_is_preserved():
    result = analyze_url_structure(
        "https://example.com:8443/login"
    )

    assert result["port"] == 8443


def test_percent_encoding_and_at_symbol():
    result = analyze_url_structure(
        "https://user@example.com/%6cogin"
    )

    assert result["has_percent_encoding"] is True
    assert result["has_at_symbol"] is True


def test_shortener_and_suspicious_tld_detection():
    shortener = analyze_url_structure("https://bit.ly/example")
    suspicious = analyze_url_structure(
        "https://secure-account-verify.xyz/login"
    )

    assert shortener["is_shortened"] is True
    assert suspicious["is_suspicious_tld"] is True
    assert suspicious["tld"] == ".xyz"


def test_url_without_scheme_is_only_normalized_for_parsing():
    result = analyze_url_structure("example.com/login")

    assert result["protocol"] == "http"
    assert result["hostname"] == "example.com"
    assert result["path"] == "/login"
    assert result["url_length"] == len("example.com/login")


def test_malformed_port_does_not_crash():
    result = analyze_url_structure("https://example.com:not-a-port/path")

    assert result["hostname"] == "example.com"
    assert result["port"] is None


def test_empty_url_is_rejected():
    with pytest.raises(ValueError, match="URL cannot be empty"):
        analyze_url_structure("  ")


def test_combined_url_properties():
    result = analyze_url_structure(
        "http://login.secure.example.xyz:8080/a/b?token=1#frag"
    )

    assert result == {
        "protocol": "http",
        "hostname": "login.secure.example.xyz",
        "registrable_domain": "example.xyz",
        "tld": ".xyz",
        "subdomain_count": 2,
        "is_ip_address": False,
        "url_length": 53,
        "domain_length": 24,
        "path": "/a/b",
        "path_depth": 2,
        "query_parameter_count": 1,
        "query": "token=1",
        "fragment": "frag",
        "port": 8080,
        "has_percent_encoding": False,
        "has_at_symbol": False,
        "is_shortened": False,
        "is_suspicious_tld": True,
    }
