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


# Friendly names for each indicator code
INDICATOR_NAMES = {
    "https_check": "Insecure Connection (HTTP)",
    "ip_address": "Raw IP Address Hostname",
    "url_length": "Abnormal URL Length",
    "excessive_subdomains": "Excessive Subdomains",
    "suspicious_keywords": "Suspicious Keywords Detected",
    "special_characters": "Suspicious Special Characters",
    "urgency_language": "Artificial Urgency Detected",
    "threat_language": "Threatening/Coercive Language",
    "credential_request": "Credential Harvesting Solicitation",
    "financial_request": "Financial Solicitation"
}


def generate_explanation(indicator_results):
    """
    Create a human-readable explanation of which indicators triggered.

    Takes:   indicator_results (list of dict) - each dict has:
             {"indicator": str, "triggered": bool, "detail": str}
    Returns: str - a multi-line formatted explanation.

    Why this exists:
        A score of 65 is meaningless without understanding the specific reasons.
        The explanation provides transparency so the user learns why it is dangerous.
    """
    if not indicator_results:
        return "[*] No indicators provided for evaluation."

    triggered = [r for r in indicator_results if r.get("triggered")]

    if not triggered:
        return "[*] No phishing indicators detected. The input appears consistent with standard communication."

    lines = [f"[*] Identified {len(triggered)} risk indicator(s):"]
    for item in triggered:
        code = item.get("indicator", "unknown")
        name = INDICATOR_NAMES.get(code, code.replace("_", " ").title())
        detail = item.get("detail", "Indicator triggered.")
        lines.append(f"  [!] {name}: {detail}")

    return "\n".join(lines)


def generate_recommendations(threat_level, indicator_results):
    """
    Give the user specific safety recommendations based on the threat level.

    Takes:   threat_level (str) - "LOW", "MEDIUM", "HIGH", or "CRITICAL"
             indicator_results (list of dict) - for context-specific advice.
    Returns: list of str - actionable recommendations.

    Why this exists:
        Detection without advice leaves the user uncertain of what steps to take.
        Advice scales from general vigilance to immediate incident response.
    """
    recs = []
    level = threat_level.upper() if isinstance(threat_level, str) else "LOW"

    # Base recommendations by threat level
    if level == "LOW":
        recs.append("No immediate threats detected, but always verify unfamiliar senders.")
        recs.append("Ensure you only submit passwords on verified, bookmarked websites.")
    elif level == "MEDIUM":
        recs.append("Exercise caution. Several suspicious attributes were identified.")
        recs.append("Do NOT enter personal credentials (passwords, PINs) or payment details.")
        recs.append("Verify this communication via an official, secondary channel before clicking.")
    elif level == "HIGH":
        recs.append("HIGH RISK: Strongly advised NOT to click links or download any attachments.")
        recs.append("Never share passwords, OTPs, or financial information.")
        recs.append("Mark this message as spam/phishing in your email or messaging client.")
        recs.append("If this claims to be from a bank or service, navigate to their official site manually.")
    elif level == "CRITICAL":
        recs.append("CRITICAL DANGER: Multiple strong phishing red flags detected.")
        recs.append("DO NOT click any links, open attachments, or reply to this communication.")
        recs.append("Never provide credentials, banking details, or one-time passcodes.")
        recs.append("Delete this message immediately or report it to your IT/security administrator.")
        recs.append("If you have already clicked this link or submitted info, change your passwords immediately.")

    # Contextual tips based on specific triggered indicators
    triggered_codes = {r.get("indicator") for r in indicator_results if r.get("triggered")}

    if "credential_request" in triggered_codes:
        recs.append("Tip: Legitimate institutions will NEVER ask you to verify your password via email or SMS.")

    if "financial_request" in triggered_codes:
        recs.append("Tip: Demands for wire transfers or gift cards are a hallmark of fraud.")

    if "ip_address" in triggered_codes:
        recs.append("Tip: Never enter personal data on websites identified only by a raw IP address.")

    return recs

