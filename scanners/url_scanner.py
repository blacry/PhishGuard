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


def check_https(url):
    """
    Check whether the URL uses HTTPS (secure) or HTTP (insecure).

    Takes:   url (str) — the URL to check, e.g. "http://example.com"
    Returns: dict — {"indicator": "https_check",
                      "triggered": True/False,
                      "detail": "...why this matters..."}

    Why this matters:
        HTTP sends data in plain text — anyone on the network can read it.
        HTTPS encrypts the connection. Phishing sites sometimes skip HTTPS,
        though modern phishers DO use HTTPS too, so this alone is not proof.
        Weight: LOW — it's a clue, not a verdict.
    """
    pass


def check_ip_address(url):
    """
    Check if the URL uses a raw IP address instead of a domain name.

    Takes:   url (str) — e.g. "http://192.168.1.1/login"
    Returns: dict — {"indicator": "ip_address",
                      "triggered": True/False,
                      "detail": "...explanation..."}

    Why this matters:
        Legitimate sites use domain names (google.com). Phishing sites
        sometimes use raw IPs (http://192.168.1.1/login) to hide their
        identity, because IPs are harder for humans to verify.
        Weight: HIGH — very suspicious for a login page.
    """
    pass


def check_url_length(url):
    """
    Check if the URL is unusually long.

    Takes:   url (str)
    Returns: dict — {"indicator": "url_length",
                      "triggered": True/False,
                      "detail": "...explanation..."}

    Why this matters:
        Phishing URLs are often very long because they stuff extra
        parameters, fake paths, or misleading subdomains into the URL
        to confuse the victim. Normal URLs are usually under 75 chars.
        Weight: MEDIUM — long URLs aren't always bad, but they're a clue.
    """
    pass


def check_subdomains(url):
    """
    Check if the URL has an excessive number of subdomains.

    Takes:   url (str) — e.g. "http://secure.login.bank.example.com"
    Returns: dict — {"indicator": "excessive_subdomains",
                      "triggered": True/False,
                      "detail": "...explanation..."}

    Why this matters:
        Phishers add extra subdomains to make a URL LOOK like it belongs
        to a trusted site: "login.google.security.evil.com" looks like
        Google but actually belongs to evil.com.
        Weight: MEDIUM-HIGH — 3+ subdomains is unusual for legit sites.
    """
    pass


def check_suspicious_keywords(url):
    """
    Check if the URL contains words commonly used in phishing URLs.

    Takes:   url (str)
    Returns: dict — {"indicator": "suspicious_keywords",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "matched_keywords": [...list of found words...]}

    Why this matters:
        Phishing URLs often include words like "login", "verify",
        "secure", "account", "update" to trick users into thinking
        the page is legitimate. We check against a keyword list.
        Weight: MEDIUM — these words appear in legit URLs too.
    """
    pass


def check_special_characters(url):
    """
    Check if the URL contains suspicious special characters like @, //, etc.

    Takes:   url (str)
    Returns: dict — {"indicator": "special_characters",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "found_characters": [...]}

    Why this matters:
        The '@' symbol in a URL can redirect the browser to a different
        site than what's displayed. Multiple '//' after the protocol
        can also be used to confuse URL parsers.
        Weight: HIGH — these are known obfuscation tricks.
    """
    pass


def scan_url(url):
    """
    Run ALL URL checks and collect the results.

    Takes:   url (str) — the URL to analyze.
    Returns: list of dicts — one dict per indicator check.

    Why this exists:
        Instead of calling each check function separately, this function
        calls them all and returns a neat list. The risk engine can then
        loop through the list to calculate the total score.
    """
    pass
