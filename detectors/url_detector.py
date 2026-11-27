"""Explainable checks for suspicious URL patterns. URLs are never fetched here."""

import ipaddress
import re
from urllib.parse import parse_qsl, urlparse

from detectors.brand_detector import detect_brand_impersonation

SUSPICIOUS_EXTENSIONS = {".xyz", ".top", ".click", ".work", ".zip", ".country", ".gq", ".tk"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "shorturl.at"}
URL_KEYWORDS = {"login", "verify", "update", "secure", "account", "signin", "confirm", "password", "wallet", "recover"}


def normalize_url(value):
    """Add a scheme when omitted and trim surrounding whitespace."""
    value = (value or "").strip()
    if value and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    return value


def analyze_url(value):
    """Return parsed URL details and unique, explainable warning findings."""
    url = normalize_url(value)
    parsed = urlparse(url)
    if not url or not parsed.hostname or parsed.scheme not in {"http", "https"} or any(char.isspace() for char in parsed.hostname):
        return {"valid": False, "url": url, "details": {}, "findings": [], "error": "Enter a complete web URL with a domain name."}

    host = parsed.hostname.lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        return {"valid": False, "url": url, "details": {}, "findings": [], "error": "The URL contains an invalid port number."}
    findings = []

    def add(key, indicator, points, severity, explanation):
        findings.append({"key": key, "indicator": indicator, "points": points, "severity": severity, "explanation": explanation})

    if parsed.scheme.lower() == "http":
        add("http", "Unencrypted connection", 5, "Low", "This URL uses HTTP, so the connection does not provide HTTPS transport encryption. HTTPS alone would not prove a site is legitimate.")

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        add("ip_address", "IP address used as host", 20, "High", "The link uses a raw IP address instead of a familiar domain. This can make the destination harder to verify.")

    labels = host.split(".")
    if not is_ip and len(labels) >= 2:
        suffix = "." + labels[-1]
        if suffix in SUSPICIOUS_EXTENSIONS:
            add("suspicious_extension", "Uncommon domain ending", 15, "Medium", "This domain ending is often inexpensive or abused. A domain ending by itself is not proof of phishing.")
    if not is_ip and len(labels) > 4:
        add("many_subdomains", "Many subdomains", 10, "Medium", "Several subdomain levels can obscure the actual registered domain. Check the domain immediately before the ending.")
    if len(url) > 100:
        add("long_url", "Unusually long URL", 10, "Medium", "Long links can hide destinations or carry tracking and redirection data.")
    if host in SHORTENERS:
        add("shortened_url", "Shortened URL", 10, "Medium", "A link shortener hides the final destination until expanded. Do not follow it unless you trust its source.")
    keyword_matches = sorted(word for word in URL_KEYWORDS if word in (host + parsed.path + parsed.query).lower())
    if keyword_matches:
        add("url_keyword", "Sensitive action wording", 5, "Low", "The URL contains wording often used in account prompts: " + ", ".join(keyword_matches) + ". Legitimate services may also use these words.")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        add("misleading_at", "Potentially misleading URL structure", 15, "High", "User information or an @ character appears before the host. Some links use this to make a different destination look familiar.")
    if re.search(r"%[0-9a-fA-F]{2}|-{2,}|_{2,}", host):
        add("unusual_host_chars", "Unusual characters in host", 10, "Medium", "Encoded or repeated punctuation in the host can be used to imitate a trusted domain.")

    brand_finding = detect_brand_impersonation(host)
    if brand_finding:
        findings.append(brand_finding)

    details = {
        "full_url": url,
        "protocol": parsed.scheme.lower(),
        "hostname": host,
        "domain": host,
        "path": parsed.path or "/",
        "query_parameters": parse_qsl(parsed.query, keep_blank_values=True),
        "port": port,
    }
    return {"valid": True, "url": url, "details": details, "findings": findings, "error": None}
