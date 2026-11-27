"""SMS and chat message scanner wrapper."""

from detectors.text_detector import analyze_text


def analyze_message(content):
    return analyze_text(content, category="message")
