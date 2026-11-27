"""
validators.py — Input validation functions.

Before we analyze anything, we need to make sure the user's input
is actually valid. This module checks whether a string looks like
a URL or a message worth scanning.

"Validation" means checking that data meets certain rules BEFORE
processing it. This prevents errors downstream and gives the user
helpful error messages instead of crashes.

Python concepts used:
    - String methods (startswith, strip, len)
    - Regular expressions for URL pattern matching
    - Boolean return values
    - Defensive programming (assume input is bad until proven good)
"""


import ipaddress
import re
from urllib.parse import urlparse


def sanitize_input(text):
    """
    Clean up user input before processing.

    Takes:   text (str) - raw input from the user.
    Returns: str - cleaned version (stripped of leading/trailing whitespace).

    Why this exists:
        Users often accidentally paste extra spaces (e.g., "  http://example.com  ").
        .strip() removes whitespace from the start and end so our checks run cleanly.
    """
    if not isinstance(text, str):
        return ""
    return text.strip()


def is_valid_url(text):
    """
    Check if the given text looks like a valid URL to analyze.

    Takes:   text (str) - the string to check.
    Returns: bool - True if it looks like a URL, False otherwise.

    How it checks:
        1. Sanitize to strip surrounding spaces.
        2. URLs cannot contain whitespace in the middle.
        3. If no http:// or https:// prefix is provided, temporarily add it
           so Python's urlparse can inspect the domain name.
        4. Make sure a domain (netloc) exists and contains at least one dot
           (e.g., "example.com" or "192.168.1.1").
    """
    if not isinstance(text, str):
        return False

    cleaned = sanitize_input(text)
    if not cleaned:
        return False

    if re.search(r"\s", cleaned):
        return False

    if "://" in cleaned:
        scheme = cleaned.split(":", 1)[0].lower()
        if scheme not in {"http", "https"}:
            return False
        url_to_parse = cleaned
    else:
        if cleaned.startswith("//"):
            return False
        url_to_parse = "http://" + cleaned

    try:
        parsed = urlparse(url_to_parse)
        if parsed.scheme.lower() not in {"http", "https"}:
            return False

        hostname = parsed.hostname
        if not hostname or parsed.username or parsed.password:
            return False

        parsed.port

        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            pass

        if re.fullmatch(r"[0-9.]+", hostname):
            return False

        hostname = hostname.rstrip(".").lower()
        if "." not in hostname:
            return False

        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return False

        labels = ascii_hostname.split(".")
        if len(labels) < 2:
            return False

        for label in labels:
            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not re.fullmatch(r"[a-z0-9-]+", label)
            ):
                return False

        tld = labels[-1]
        if not (tld.isalpha() or tld.startswith("xn--")):
            return False

        return True
    except (UnicodeError, ValueError):
        return False


def is_valid_message(text):
    """
    Check if the given text is a message worth scanning.

    Takes:   text (str) - the message to check.
    Returns: bool - True if it's a non-empty string with enough words to analyze.

    How it checks:
        - Must be a string.
        - Must have at least 2 words and at least 5 characters.
    """
    if not isinstance(text, str):
        return False

    cleaned = sanitize_input(text)
    words = cleaned.split()

    # A message needs at least 2 words and 5 characters to analyze meaningful patterns
    return len(words) >= 2 and len(cleaned) >= 5

