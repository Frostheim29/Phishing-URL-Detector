"""Small, standard-library URL structural analysis helpers.

This module deliberately does not assign a phishing score or make a prediction.
It only describes the parts and simple characteristics of a URL for a future
risk engine to use.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit


SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "password", "banking", "bank", "payment", "wallet",
    "confirm", "authentication", "recover", "unlock",
}

# This is intentionally a small, editable heuristic list rather than a claim
# that every URL using one of these TLDs is malicious.
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "zip", "mov"}


def normalize_url(url: Any) -> tuple[str, bool]:
    """Return a trimmed URL and whether a missing scheme was added.

    Browsers accept ``example.com`` without a protocol.  ``urlsplit`` treats
    that as a path, so an ``http://`` prefix is added for useful analysis.
    """
    if not isinstance(url, str):
        return "", False

    cleaned = url.strip()
    if not cleaned:
        return "", False

    # ``//example.com`` already has a network location, only no scheme.
    if cleaned.startswith("//"):
        return "http:" + cleaned, True

    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", cleaned):
        return "http://" + cleaned, True

    return cleaned, False


def _domain_from_host(host: str, is_ip_address: bool) -> str:
    """Return a simple base domain (not a public-suffix-aware registration)."""
    if not host or is_ip_address:
        return host
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_local_or_private(host: str, is_ip_address: bool) -> bool:
    if host.lower() == "localhost":
        return True
    if not is_ip_address:
        return False
    address = ipaddress.ip_address(host)
    return address.is_private or address.is_loopback or address.is_link_local


def _find_suspicious_keywords(text: str) -> list[str]:
    """Find keyword matches as whole-ish URL tokens, without duplicates."""
    words = set(re.findall(r"[a-z]+", text.lower()))
    return sorted(SUSPICIOUS_KEYWORDS.intersection(words))


def analyze_url(url: str) -> dict:
    """Analyze *url* structurally and return a dictionary of simple signals.

    Invalid or unusual user input is returned with ``valid: False`` and an
    ``error`` message instead of raising an exception.
    """
    original_url = url if isinstance(url, str) else str(url)
    normalized_url, scheme_added = normalize_url(url)
    result = {
        "original_url": original_url,
        "normalized_url": normalized_url,
        "valid": False,
        "error": None,
        "scheme_added": scheme_added,
    }

    if not isinstance(url, str):
        result["error"] = "URL must be a string."
        return result
    if not normalized_url:
        result["error"] = "URL is empty."
        return result

    try:
        parsed = urlsplit(normalized_url)
        # Accessing .port can itself raise for values such as ':not-a-port'.
        port = parsed.port
        host = (parsed.hostname or "").lower().rstrip(".")
    except (ValueError, TypeError) as exc:
        result["error"] = "Could not parse URL: " + str(exc)
        return result

    if not parsed.scheme or not host:
        result["error"] = "URL must include a host name."
        return result

    is_ip_address = _is_ip_address(host)
    domain = _domain_from_host(host, is_ip_address)
    host_labels = host.split(".") if host and not is_ip_address else []
    subdomain_count = max(0, len(host_labels) - 2)
    path_segments = [segment for segment in parsed.path.split("/") if segment]
    query_parameters = parse_qsl(parsed.query, keep_blank_values=True)
    tld = "" if is_ip_address or "." not in host else host.rsplit(".", 1)[-1]
    keywords = _find_suspicious_keywords(normalized_url)
    hyphen_count = host.count("-")

    # Rebuild from parsed components to keep a clear, consistently structured URL.
    clean_url = urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, parsed.fragment))
    result.update({
        "normalized_url": clean_url,
        "valid": True,
        "scheme": parsed.scheme.lower(),
        "protocol": parsed.scheme.lower(),
        "is_https": parsed.scheme.lower() == "https",
        "host": host,
        "domain": domain,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "port": port,
        "is_ip_address": is_ip_address,
        "is_localhost_or_private_ip": _is_local_or_private(host, is_ip_address),
        "url_length": len(clean_url),
        "domain_length": len(domain),
        "subdomain_count": subdomain_count,
        "path_segment_count": len(path_segments),
        "query_parameter_count": len(query_parameters),
        "has_at_symbol": "@" in normalized_url,
        "hyphen_count": hyphen_count,
        "has_excessive_hyphens": hyphen_count >= 3,
        "has_encoded_characters": bool(re.search(r"%[0-9A-Fa-f]{2}", normalized_url)),
        "suspicious_keywords": keywords,
        "has_suspicious_keywords": bool(keywords),
        "tld": tld,
        "has_suspicious_tld": tld in SUSPICIOUS_TLDS,
        "has_non_standard_port": port is not None and port not in {80, 443},
        "is_punycode_or_idn": "xn--" in host or any(ord(character) > 127 for character in host),
    })
    return result
