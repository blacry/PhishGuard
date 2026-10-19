"""
recommendation_engine.py — Generates explanations and safety advice.

After the risk engine scores a URL or message, this module turns
the raw results into something the user can understand and act on.

It does two things:
    1. EXPLAIN — tell the user which indicators fired and why.
    2. RECOMMEND — give actionable safety tips based on the threat level.

This is the "teacher" of PhishGuard: it doesn't just say "danger",
it says "here's WHY it's dangerous and here's WHAT you should do."

Python concepts used:
    - String formatting (f-strings)
    - Loops to build explanation text
    - Conditionals to pick the right recommendations
    - Lists to collect multiple tips
"""


def generate_explanation(indicator_results):
    """
    Create a human-readable explanation of which indicators triggered.

    Takes:   indicator_results (list of dict) — each dict has:
             {"indicator": str, "triggered": bool, "detail": str}
    Returns: str — a multi-line explanation text.

    Example output:
        "⚠️  HTTPS missing — The URL uses HTTP instead of HTTPS.
             This means data is sent without encryption.
         ⚠️  IP address used — The URL uses a raw IP (192.168.1.1)
             instead of a domain name. This hides the site's identity."

    Why this exists:
        A score of 65 is meaningless without context. The explanation
        tells the user exactly what triggered and why it's a red flag.
        This supports the project's "Educate" philosophy.
    """
    pass


def generate_recommendations(threat_level, indicator_results):
    """
    Give the user specific safety recommendations based on the threat.

    Takes:   threat_level (str) — "LOW", "MEDIUM", "HIGH", or "CRITICAL"
             indicator_results (list of dict) — to tailor advice.
    Returns: list of str — each string is one recommendation.

    Example output for CRITICAL:
        ["Do NOT click any links in this message.",
         "Do NOT enter any personal information.",
         "Report this to your IT department or email provider.",
         "Delete the message immediately."]

    Why this exists:
        Detection without advice is incomplete. The user needs to
        know what to DO, not just what's wrong. Recommendations are
        tailored to the threat level — LOW gets gentle reminders,
        CRITICAL gets urgent warnings.
    """
    pass
