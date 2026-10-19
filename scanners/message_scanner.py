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


import re
import os
import csv


# Default fallback keywords if data/keywords.csv is unavailable
DEFAULT_URGENCY_WORDS = [
    "act now", "immediately", "urgent", "expires",
    "within 24 hours", "right away", "time sensitive", "don't delay"
]

DEFAULT_THREAT_WORDS = [
    "account suspended", "suspended", "account will be closed", "unauthorized access",
    "legal action", "will be locked", "locked", "security breach", "violation"
]

DEFAULT_CREDENTIAL_WORDS = [
    "verify your password", "confirm your identity", "update your account",
    "verify your account", "click here to verify", "enter your password",
    "login details", "social security"
]

DEFAULT_FINANCIAL_WORDS = [
    "bank account", "credit card", "send payment", "wire transfer",
    "gift card", "billing information", "update payment"
]


def _load_category_keywords(category_name, default_list):
    """
    Helper function to load keywords for a specific category from data/keywords.csv.
    Falls back to default_list if the file cannot be accessed.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    keywords_path = os.path.join(current_dir, "..", "data", "keywords.csv")

    keywords = []
    if os.path.exists(keywords_path):
        try:
            with open(keywords_path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("category", "").strip() == category_name:
                        word = row.get("keyword", "").strip().lower()
                        if word:
                            keywords.append(word)
        except Exception:
            keywords = default_list
    else:
        keywords = default_list

    return keywords if keywords else default_list


def extract_urls(message):
    """
    Find and return all URLs embedded in a text message.

    Takes:   message (str) - the full message text.
    Returns: list of str - all URLs found in the message (or empty list).

    How it works:
        Uses a regular expression to locate strings starting with http:// or https://.
        Also cleans off trailing punctuation (periods, commas, parentheses) that might
        belong to the surrounding English sentence rather than the URL itself.
    """
    if not isinstance(message, str):
        return []

    # Regex pattern: looks for http:// or https:// followed by non-space characters
    raw_urls = re.findall(r"https?://[^\s<>\"']+", message)

    cleaned_urls = []
    for raw in raw_urls:
        # Strip trailing punctuation marks like '.', ',', '!', ')' that end a sentence
        clean = raw.rstrip(".,;:!?)")
        if clean:
            cleaned_urls.append(clean)

    return cleaned_urls


def detect_urgency(message):
    """
    Check if the message uses urgency language to pressure the reader.

    Takes:   message (str)
    Returns: dict - {"indicator": "urgency_language",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "matched_words": [...]}

    Why this matters:
        Phishers manufacture artificial deadlines (e.g., 'within 24 hours', 'act now')
        to cause panic and bypass the victim's rational skepticism.
    """
    keywords = _load_category_keywords("urgency", DEFAULT_URGENCY_WORDS)
    msg_lower = message.lower() if isinstance(message, str) else ""

    matched = [word for word in keywords if word in msg_lower]

    if matched:
        return {
            "indicator": "urgency_language",
            "triggered": True,
            "detail": f"Urgency language detected ({', '.join(matched)}), attempting to pressure immediate action.",
            "matched_words": matched
        }
    else:
        return {
            "indicator": "urgency_language",
            "triggered": False,
            "detail": "No artificial urgency patterns detected.",
            "matched_words": []
        }


def detect_threat_language(message):
    """
    Check if the message threatens negative consequences.

    Takes:   message (str)
    Returns: dict - {"indicator": "threat_language",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "matched_words": [...]}

    Why this matters:
        Threats of account suspension, legal action, or security breaches
        exploit fear to coerce compliance. Legitimate services do not threaten
        customers via unsolicited SMS or emails.
    """
    keywords = _load_category_keywords("threat", DEFAULT_THREAT_WORDS)
    msg_lower = message.lower() if isinstance(message, str) else ""

    matched = [word for word in keywords if word in msg_lower]

    if matched:
        return {
            "indicator": "threat_language",
            "triggered": True,
            "detail": f"Threatening language detected ({', '.join(matched)}), exploiting fear of negative consequences.",
            "matched_words": matched
        }
    else:
        return {
            "indicator": "threat_language",
            "triggered": False,
            "detail": "No coercive or threatening language detected.",
            "matched_words": []
        }


def detect_credential_request(message):
    """
    Check if the message asks for login credentials or identity verification.

    Takes:   message (str)
    Returns: dict - {"indicator": "credential_request",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "matched_words": [...]}

    Why this matters:
        No legitimate service provider asks customers to verify passwords or login
        credentials through an unauthenticated message link. This is a primary phishing signature.
    """
    keywords = _load_category_keywords("credential", DEFAULT_CREDENTIAL_WORDS)
    msg_lower = message.lower() if isinstance(message, str) else ""

    matched = [word for word in keywords if word in msg_lower]

    if matched:
        return {
            "indicator": "credential_request",
            "triggered": True,
            "detail": f"Credential harvesting request detected ({', '.join(matched)}).",
            "matched_words": matched
        }
    else:
        return {
            "indicator": "credential_request",
            "triggered": False,
            "detail": "No requests for passwords or sensitive login credentials detected.",
            "matched_words": []
        }


def detect_financial_request(message):
    """
    Check if the message asks for money, payment, or banking information.

    Takes:   message (str)
    Returns: dict - {"indicator": "financial_request",
                      "triggered": True/False,
                      "detail": "...explanation...",
                      "matched_words": [...]}

    Why this matters:
        Unsolicited requests for bank details, wire transfers, or gift cards
        strongly correlate with financial fraud and credential theft.
    """
    keywords = _load_category_keywords("financial", DEFAULT_FINANCIAL_WORDS)
    msg_lower = message.lower() if isinstance(message, str) else ""

    matched = [word for word in keywords if word in msg_lower]

    if matched:
        return {
            "indicator": "financial_request",
            "triggered": True,
            "detail": f"Financial solicitation detected ({', '.join(matched)}), requesting monetary or payment details.",
            "matched_words": matched
        }
    else:
        return {
            "indicator": "financial_request",
            "triggered": False,
            "detail": "No unsolicited financial or payment requests detected.",
            "matched_words": []
        }


def scan_message(message):
    """
    Run ALL message checks and collect the results.

    Takes:   message (str) - the message text to analyze.
    Returns: dict - {
                 "message_indicators": [list of indicator dicts],
                 "extracted_urls": [list of URL strings]
             }

    Why this exists:
        Acts as the central orchestrator for message inspection. It checks for
        linguistic phishing red flags while also extracting any embedded URLs
        for secondary scanning.
    """
    indicators = [
        detect_urgency(message),
        detect_threat_language(message),
        detect_credential_request(message),
        detect_financial_request(message)
    ]
    extracted = extract_urls(message)

    return {
        "message_indicators": indicators,
        "extracted_urls": extracted
    }

