"""
risk_engine.py — Calculates risk scores and classifies threat levels.

This is the "brain" of PhishGuard. It takes the list of indicator
results from the scanners, multiplies each triggered indicator by
its weight, sums them up, caps the total at 100, and assigns a
threat level label.

Scoring logic:
    total_score = sum(weight for each triggered indicator)
    capped_score = min(total_score, 100)   # never exceeds 100

Classification:
    0  - 24  → LOW       (probably safe, but stay alert)
    25 - 49  → MEDIUM    (some red flags — be cautious)
    50 - 74  → HIGH      (multiple red flags — likely phishing)
    75 - 100 → CRITICAL  (strong phishing indicators — do not interact)

Python concepts used:
    - Dictionaries to store weights
    - Loops to iterate over indicator results
    - min() to cap values
    - if/elif/else for classification
    - Functions returning multiple values via a dict
"""

# Weights for each indicator (heuristic - tuned by judgment, not ML).
# Higher weight means a stronger signal of malicious intent.
INDICATOR_WEIGHTS = {
    # URL indicators (Max potential: 105 -> capped at 100)
    "https_check": 10,
    "ip_address": 25,
    "url_length": 15,
    "excessive_subdomains": 20,
    "suspicious_keywords": 15,  # 5 per matched word, up to 3 words
    "special_characters": 20,

    # Message indicators (Max potential: 85 -> capped at 100)
    "urgency_language": 15,
    "threat_language": 20,
    "credential_request": 25,
    "financial_request": 25
}


def calculate_risk_score(indicator_results):
    """
    Calculate a weighted risk score from indicator results.

    Takes:   indicator_results (list of dict) - each dict has at least:
             {"indicator": str, "triggered": bool}
    Returns: int - risk score from 0 to 100 (capped).

    How it works:
        1. Loop through each indicator result.
        2. If triggered is True:
           - For suspicious_keywords: score 5 points per keyword found (max 3 -> 15 pts).
           - For all other indicators: look up the fixed weight in INDICATOR_WEIGHTS.
        3. Accumulate total score.
        4. Cap the score at 100 using min().
    """
    if not indicator_results:
        return 0

    total = 0
    for res in indicator_results:
        if res.get("triggered"):
            ind = res.get("indicator")

            # Fine-tune scoring for suspicious keywords (5 per word, capped at 3 words = 15)
            if ind == "suspicious_keywords" and "matched_keywords" in res:
                matched_count = min(3, len(res["matched_keywords"]))
                total += matched_count * 5
            else:
                total += INDICATOR_WEIGHTS.get(ind, 0)

    # Never allow score to exceed 100
    return min(total, 100)


def classify_threat(risk_score):
    """
    Convert a numeric risk score into a human-readable threat level.

    Takes:   risk_score (int) - a number from 0 to 100.
    Returns: str - one of "LOW", "MEDIUM", "HIGH", "CRITICAL".

    Classification Thresholds:
        0  - 24  -> "LOW"       (mostly safe, stay alert)
        25 - 49  -> "MEDIUM"    (suspicious attributes present)
        50 - 74  -> "HIGH"      (multiple strong red flags)
        75 - 100 -> "CRITICAL"  (definite phishing pattern)
    """
    # Defensive check: ensure score is an integer
    score = int(risk_score) if isinstance(risk_score, (int, float)) else 0

    if score <= 24:
        return "LOW"
    elif score <= 49:
        return "MEDIUM"
    elif score <= 74:
        return "HIGH"
    else:
        return "CRITICAL"

