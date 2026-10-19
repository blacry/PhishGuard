"""
message_scanner.py — Analyzes text messages for phishing indicators.

This module reads a text message (email, SMS, chat) and looks for
language patterns that phishers commonly use to manipulate victims.
It also extracts any URLs embedded in the message for separate scanning.

The four main categories of phishing language are:
    1. Urgency   — "Act now!", "24 hours", "immediately"
    2. Threats   — "account suspended", "legal action"
    3. Credential requests — "verify your password", "confirm login"
    4. Financial requests  — "send payment", "bank details"

Python concepts used:
    - String methods (lower, split, find)
    - Regular expressions for extracting URLs
    - List comprehensions for filtering matches
    - Loops to check against keyword lists
"""


def extract_urls(message):
    """
    Find and return all URLs embedded in a text message.

    Takes:   message (str) — the full message text.
    Returns: list of str — all URLs found in the message.
             Returns an empty list if no URLs are found.

    Why this exists:
        A phishing message usually contains a link. By extracting URLs,
        we can pass them to the URL scanner for structural analysis too.
        We use a regex pattern to find strings that look like URLs.
    """
    pass


def detect_urgency(message):
    """
    Check if the message uses urgency language to pressure the reader.

    Takes:   message (str)
    Returns: dict — {"indicator": "urgency_language",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "matched_words": [...]}

    Why this matters:
        Phishers create panic so you act without thinking. Phrases like
        "act immediately", "expires in 24 hours", "urgent action required"
        are designed to bypass your critical thinking.
        Weight: MEDIUM — some legit messages are also urgent.
    """
    pass


def detect_threat_language(message):
    """
    Check if the message threatens negative consequences.

    Takes:   message (str)
    Returns: dict — {"indicator": "threat_language",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "matched_words": [...]}

    Why this matters:
        Threats like "your account will be closed" or "legal action"
        scare people into clicking links without verifying the sender.
        Weight: MEDIUM-HIGH — threats combined with a link are very suspicious.
    """
    pass


def detect_credential_request(message):
    """
    Check if the message asks for login credentials or personal info.

    Takes:   message (str)
    Returns: dict — {"indicator": "credential_request",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "matched_words": [...]}

    Why this matters:
        No legitimate company will ask you to "verify your password"
        or "confirm your SSN" via email or text. This is a top
        phishing indicator.
        Weight: HIGH — credential requests in messages are almost
        always phishing.
    """
    pass


def detect_financial_request(message):
    """
    Check if the message asks for money, payment, or bank details.

    Takes:   message (str)
    Returns: dict — {"indicator": "financial_request",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "matched_words": [...]}

    Why this matters:
        Phishing for money (e.g., "send gift cards", "wire transfer",
        "update billing info") is a direct financial attack. Even
        mentioning bank/card details in a message is a red flag.
        Weight: HIGH — financial requests from unknown senders = danger.
    """
    pass


def scan_message(message):
    """
    Run ALL message checks and collect the results.

    Takes:   message (str) — the message text to analyze.
    Returns: dict — {
                 "message_indicators": [list of indicator dicts],
                 "extracted_urls": [list of URL strings]
             }

    Why this exists:
        Like scan_url, this is the orchestrator. It runs every check,
        collects results, and also extracts URLs so the caller can
        optionally run URL checks on them too.
    """
    pass
