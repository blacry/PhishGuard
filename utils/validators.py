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


def is_valid_url(text):
    """
    Check if the given text looks like a URL.

    Takes:   text (str) — the string to check.
    Returns: bool — True if it looks like a URL, False otherwise.

    How it checks:
        - Must start with "http://" or "https://" (or we add it).
        - Must contain at least one dot (e.g., ".com").
        - Must not be empty or just whitespace.

    Why this exists:
        If the user types "hello world" in the URL scanner, we should
        tell them "that's not a URL" instead of trying to analyze it
        and producing garbage results. Garbage in = garbage out.
    """
    pass


def is_valid_message(text):
    """
    Check if the given text is a message worth scanning.

    Takes:   text (str) — the message to check.
    Returns: bool — True if it's a non-empty string with enough content.

    How it checks:
        - Must not be empty or just whitespace.
        - Must have at least a few words (very short strings aren't
          useful to analyze for phishing patterns).

    Why this exists:
        Scanning an empty string or "hi" would waste time and give
        meaningless results. We set a minimum bar for useful input.
    """
    pass


def sanitize_input(text):
    """
    Clean up user input before processing.

    Takes:   text (str) — raw input from the user.
    Returns: str — cleaned version (stripped of leading/trailing whitespace).

    Why this exists:
        Users might accidentally type " http://example.com  " with
        extra spaces. strip() removes them so our checks work correctly.
        This is a common preprocessing step.
    """
    pass
