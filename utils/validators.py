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

    # URLs should not have spaces inside them
    if " " in cleaned:
        return False

    # If the user omitted http:// or https://, add http:// temporarily for parsing
    url_to_parse = cleaned
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        url_to_parse = "http://" + cleaned

    try:
        parsed = urlparse(url_to_parse)
        domain = parsed.netloc

        # We must have a domain (or IP address), and it must contain a dot
        if not domain or "." not in domain:
            return False

        return True
    except Exception:
        # If urlparse crashes on strange input, fail safely by returning False
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

