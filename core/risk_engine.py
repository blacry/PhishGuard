"""Simple weighted scoring kept separate from detector rules."""

CLASSIFICATIONS = [(20, "Low Risk"), (40, "Moderate Risk"), (60, "Suspicious"), (80, "High Risk"), (100, "Critical Risk")]


def score_findings(findings):
    """Deduplicate findings by key, sum their points, and cap the score at 100."""
    unique = []
    seen = set()
    for finding in findings or []:
        key = finding.get("key") or finding.get("indicator")
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    score = min(100, sum(max(0, int(item.get("points", 0))) for item in unique))
    classification = next(label for limit, label in CLASSIFICATIONS if score <= limit)
    return {"score": score, "classification": classification, "findings": unique}
