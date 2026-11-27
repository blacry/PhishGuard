"""Email scanner wrapper around the shared text detector."""

from detectors.text_detector import analyze_text


def analyze_email(content, sender=""):
    return analyze_text(content, category="email", sender=sender)
