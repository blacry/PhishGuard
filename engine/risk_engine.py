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

# Weights for each indicator (heuristic — tuned by judgment, not ML).
# These will be filled in during Task 3.
INDICATOR_WEIGHTS = {}


def calculate_risk_score(indicator_results):
    """
    Calculate a weighted risk score from indicator results.

    Takes:   indicator_results (list of dict) — each dict has at least
             {"indicator": str, "triggered": bool}
    Returns: int — risk score from 0 to 100 (capped).

    How it works:
        1. Loop through each indicator result.
        2. If triggered is True, look up its weight in INDICATOR_WEIGHTS.
        3. Add the weight to a running total.
        4. Cap the total at 100 using min().

    Why cap at 100?
        A score of 250 doesn't mean "2.5x more phishy than 100."
        Capping keeps the scale easy to understand.
    """
    pass


def classify_threat(risk_score):
    """
    Convert a numeric risk score into a human-readable threat level.

    Takes:   risk_score (int) — a number from 0 to 100.
    Returns: str — one of "LOW", "MEDIUM", "HIGH", "CRITICAL".

    Why this exists:
        Numbers alone are hard to interpret. "72" doesn't immediately
        tell you what to do. "HIGH" does. The classification gives
        users a quick, intuitive understanding of the danger level.

    Thresholds (these are design decisions, not mathematical truths):
        0-24   → "LOW"
        25-49  → "MEDIUM"
        50-74  → "HIGH"
        75-100 → "CRITICAL"
    """
    pass
