import ipaddress
import re
from urllib.parse import parse_qsl, urlparse

from backend.risk_engine import (
    SHORTENERS,
    SUSPICIOUS_TLDS,
    get_registrable_domain,
)


_PERCENT_ENCODING_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


def _normalized_url(url: str) -> str:
    stripped = url.strip()

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        stripped,
    ):
        return "http://" + stripped

    return stripped


def _safe_hostname(parsed) -> str:
    try:
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _safe_port(parsed) -> int | None:
    try:
        return parsed.port
    except ValueError:
        return None


def _path_depth(path: str) -> int:
    return len(
        [segment for segment in path.split("/") if segment]
    )


def analyze_url_structure(url: str) -> dict:
    """Return observable URL metadata without assigning a risk verdict."""
    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    original_url = url.strip()

    if not original_url:
        raise ValueError("URL cannot be empty.")

    parsed = urlparse(_normalized_url(original_url))
    hostname = _safe_hostname(parsed)
    is_ip_address = _is_ip_address(hostname)

    if hostname and not is_ip_address:
        registrable_domain = get_registrable_domain(hostname)
        domain_parts = [
            part for part in hostname.split(".") if part
        ]
        root_parts = [
            part
            for part in registrable_domain.split(".")
            if part
        ]
        subdomain_count = max(
            len(domain_parts) - len(root_parts),
            0,
        )
        tld = (
            "." + hostname.rsplit(".", 1)[-1]
            if "." in hostname
            else ""
        )
    else:
        registrable_domain = hostname
        subdomain_count = 0
        tld = ""

    query = parsed.query or ""
    path = parsed.path or ""

    return {
        "protocol": parsed.scheme.lower(),
        "hostname": hostname,
        "registrable_domain": registrable_domain,
        "tld": tld,
        "subdomain_count": subdomain_count,
        "is_ip_address": is_ip_address,
        "url_length": len(original_url),
        "domain_length": len(hostname),
        "path": path,
        "path_depth": _path_depth(path),
        "query_parameter_count": len(
            parse_qsl(query, keep_blank_values=True)
        ),
        "query": query,
        "fragment": parsed.fragment or "",
        "port": _safe_port(parsed),
        "has_percent_encoding": bool(
            _PERCENT_ENCODING_PATTERN.search(original_url)
        ),
        "has_at_symbol": "@" in original_url,
        "is_shortened": hostname in SHORTENERS,
        "is_suspicious_tld": any(
            hostname.endswith(tld_value)
            for tld_value in SUSPICIOUS_TLDS
        ),
    }
