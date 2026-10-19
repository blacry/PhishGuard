"""
url_scanner.py — Analyzes a URL for phishing indicators.

This module looks at the STRUCTURE of a URL (not its content) to find
red flags. It never opens or visits the URL — that would be unsafe.

Each function checks ONE specific indicator and returns a dictionary
with the result. This makes the code easy to test and explain.

Python concepts used:
    - String methods (startswith, count, len, split)
    - Regular expressions (re module) for pattern matching
    - Functions that return dictionaries
    - Boolean logic (True/False)
"""


import re
import os
import csv
from urllib.parse import urlparse


# Default keywords to use if keywords.csv is missing or unreachable
DEFAULT_SUSPICIOUS_URL_WORDS = [
    "login", "verify", "secure", "account",
    "update", "confirm", "banking", "signin", "password"
]


def _load_url_keywords():
    """
    Helper function to load 'suspicious_url_words' from data/keywords.csv.
    If the file cannot be opened, returns DEFAULT_SUSPICIOUS_URL_WORDS.
    """
    # Look for keywords.csv in the ../data directory relative to this file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    keywords_path = os.path.join(current_dir, "..", "data", "keywords.csv")

    keywords = []
    if os.path.exists(keywords_path):
        try:
            with open(keywords_path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("category", "").strip() == "suspicious_url_words":
                        word = row.get("keyword", "").strip().lower()
                        if word:
                            keywords.append(word)
        except Exception:
            # If reading fails, fall back to defaults
            keywords = DEFAULT_SUSPICIOUS_URL_WORDS
    else:
        keywords = DEFAULT_SUSPICIOUS_URL_WORDS

    return keywords if keywords else DEFAULT_SUSPICIOUS_URL_WORDS


def check_https(url):
    """
    Check whether the URL uses HTTPS (secure) or HTTP (insecure).

    Takes:   url (str) - the URL to check, e.g. "http://example.com"
    Returns: dict - {"indicator": "https_check",
                      "triggered": True/False,
                      "detail": "...why this matters..."}

    Why this matters:
        HTTP transmits data in plain text without encryption.
        However, modern phishers also use HTTPS, so this is weighted as
        a low/moderate clue (weight: 10), not definitive proof.
    """
    is_https = url.strip().lower().startswith("https://")

    if not is_https:
        return {
            "indicator": "https_check",
            "triggered": True,
            "detail": "URL does not use HTTPS encryption (uses unencrypted HTTP)."
        }
    else:
        return {
            "indicator": "https_check",
            "triggered": False,
            "detail": "URL uses HTTPS encryption."
        }


def check_ip_address(url):
    """
    Check if the URL uses a raw IP address instead of a domain name.

    Takes:   url (str) - e.g. "http://192.168.1.1/login"
    Returns: dict - {"indicator": "ip_address",
                      "triggered": True/False,
                      "detail": "...explanation..."}

    Why this matters:
        Legitimate organizations almost always use branded domain names (e.g. google.com).
        Attackers use raw IP addresses to bypass domain reputation filters and hide identity.
    """
    # Prepend scheme if missing so urlparse extracts netloc correctly
    to_parse = url if "://" in url else "http://" + url
    parsed = urlparse(to_parse)

    # Extract hostname, ignoring any trailing port (e.g. 192.168.1.1:8080 -> 192.168.1.1)
    hostname = parsed.netloc.split(":")[0].strip()

    # IPv4 regex pattern: 4 numbers separated by dots (e.g. 192.168.1.1)
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    is_ip = bool(re.match(ip_pattern, hostname))

    if is_ip:
        return {
            "indicator": "ip_address",
            "triggered": True,
            "detail": f"URL host '{hostname}' is a raw IP address instead of a registered domain."
        }
    else:
        return {
            "indicator": "ip_address",
            "triggered": False,
            "detail": "URL uses a standard domain name."
        }


def check_url_length(url):
    """
    Check if the URL is unusually long (> 75 characters).

    Takes:   url (str)
    Returns: dict - {"indicator": "url_length",
                      "triggered": True/False,
                      "detail": "...explanation..."}

    Why this matters:
        Phishing URLs frequently append fake parameters, extra paths,
        or embedded URLs to conceal the true destination.
    """
    length = len(url.strip())
    max_threshold = 75

    if length > max_threshold:
        return {
            "indicator": "url_length",
            "triggered": True,
            "detail": f"URL length is {length} characters, exceeding the safe threshold of {max_threshold}."
        }
    else:
        return {
            "indicator": "url_length",
            "triggered": False,
            "detail": f"URL length is {length} characters (within standard limits)."
        }


def check_subdomains(url):
    """
    Check if the URL has an excessive number of subdomains (3 or more).

    Takes:   url (str) - e.g. "http://secure.login.bank.example.com"
    Returns: dict - {"indicator": "excessive_subdomains",
                      "triggered": True/False,
                      "detail": "...explanation..."}

    Why this matters:
        Attackers stack subdomains to trick users (e.g., 'login.google.com.attacker.com').
        3 or more subdomains is a frequent red flag for domain spoofing.
    """
    to_parse = url if "://" in url else "http://" + url
    parsed = urlparse(to_parse)
    hostname = parsed.netloc.split(":")[0].strip()

    # Skip IP addresses since subdomains don't apply to raw IPs
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
        return {
            "indicator": "excessive_subdomains",
            "triggered": False,
            "detail": "Host is an IP address; subdomain check not applicable."
        }

    parts = hostname.split(".")
    # For a standard domain like 'example.com', parts = ['example', 'com'] (0 subdomains).
    # For 'www.example.com', parts = ['www', 'example', 'com'] (1 subdomain).
    # Subdomain count = total parts - 2 (domain + TLD)
    subdomain_count = max(0, len(parts) - 2)

    if subdomain_count >= 3:
        return {
            "indicator": "excessive_subdomains",
            "triggered": True,
            "detail": f"URL contains {subdomain_count} subdomains in '{hostname}', which is unusually high."
        }
    else:
        return {
            "indicator": "excessive_subdomains",
            "triggered": False,
            "detail": f"Subdomain count ({subdomain_count}) is within normal parameters."
        }


def check_suspicious_keywords(url):
    """
    Check if the URL contains words commonly used in phishing URLs.

    Takes:   url (str)
    Returns: dict - {"indicator": "suspicious_keywords",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "matched_keywords": [...list of found words...]}

    Why this matters:
        Words like 'login', 'verify', 'update', 'banking' are frequently
        injected into fake links to create a false sense of trust.
    """
    keywords = _load_url_keywords()
    url_lower = url.lower()

    matched = []
    for word in keywords:
        if word in url_lower:
            matched.append(word)

    # Note: Only up to 3 keywords are counted towards scoring to prevent skewing
    if matched:
        return {
            "indicator": "suspicious_keywords",
            "triggered": True,
            "detail": f"Detected suspicious keyword(s) in URL: {', '.join(matched)}.",
            "matched_keywords": matched
        }
    else:
        return {
            "indicator": "suspicious_keywords",
            "triggered": False,
            "detail": "No suspicious keywords detected in the URL.",
            "matched_keywords": []
        }


def check_special_characters(url):
    """
    Check if the URL contains suspicious special characters like @, //, etc.

    Takes:   url (str)
    Returns: dict - {"indicator": "special_characters",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "found_characters": [...]}

    Why this matters:
        The '@' symbol in URLs causes browsers to treat everything before '@'
        as a username and redirect to the host after '@'.
        Multiple '//' after the protocol is also an obfuscation technique.
    """
    found = []

    # Check for '@' symbol
    if "@" in url:
        found.append("@")

    # Check for extra '//' after protocol
    # E.g. "http://example.com//fake" or "http://example.com/login//redirect"
    after_protocol = url.split("://", 1)[-1] if "://" in url else url
    if "//" in after_protocol:
        found.append("//")

    if found:
        return {
            "indicator": "special_characters",
            "triggered": True,
            "detail": f"Found suspicious character pattern(s) ({', '.join(found)}) often used for URL spoofing.",
            "found_characters": found
        }
    else:
        return {
            "indicator": "special_characters",
            "triggered": False,
            "detail": "No suspicious special characters found in the URL.",
            "found_characters": []
        }


def scan_url(url):
    """
    Run ALL URL checks and collect the results.

    Takes:   url (str) - the URL to analyze.
    Returns: list of dicts - one dict per indicator check.

    Why this exists:
        Provides a single, tidy entry point for scanning any URL.
        The risk engine can then iterate through the returned list to calculate the total score.
    """
    return [
        check_https(url),
        check_ip_address(url),
        check_url_length(url),
        check_subdomains(url),
        check_suspicious_keywords(url),
        check_special_characters(url)
    ]

