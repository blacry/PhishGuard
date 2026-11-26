"""Pure result-oriented entry points for URL and message scans."""

from engine.risk_engine import calculate_risk_score, classify_threat
from scanners.message_scanner import scan_message as _scan_message_indicators
from scanners.url_scanner import scan_url as _scan_url_indicators
from engine.recommendation_engine import (
    generate_explanation,
    generate_recommendations,
)
from utils.validators import is_valid_message, is_valid_url, sanitize_input


def _format_indicators(results):
    """Return readable strings for triggered indicators."""
    return [
        f"{result['indicator']}: {result.get('detail', 'Indicator triggered.')}"
        for result in results
        if result.get("triggered")
    ]


def scan_url(url):
    """Analyze a URL and return its score, threat level, and indicators."""
    if not is_valid_url(url):
        raise ValueError("Invalid URL provided.")

    results = _scan_url_indicators(sanitize_input(url))
    score = calculate_risk_score(results)
    return {
        "score": score,
        "level": classify_threat(score),
        "indicators": _format_indicators(results),
    }


def scan_message(text):
    """Analyze a message and any embedded URLs."""
    if not is_valid_message(text):
        raise ValueError("Message is too short or empty.")

    message_results = _scan_message_indicators(text)
    results = list(message_results["message_indicators"])
    for url in message_results["extracted_urls"]:
        results.extend(_scan_url_indicators(url))

    score = calculate_risk_score(results)
    return {
        "score": score,
        "level": classify_threat(score),
        "indicators": _format_indicators(results),
    }


def get_explanation(result):
    """Format the result indicators for the existing CLI report."""
    indicator_results = [
        {
            "indicator": item.split(":", 1)[0],
            "triggered": True,
            "detail": item.split(":", 1)[1].strip(),
        }
        for item in result["indicators"]
    ]
    if not indicator_results:
        indicator_results = [{"indicator": "none", "triggered": False}]
    return generate_explanation(indicator_results)


def get_recommendations(result):
    """Return the existing safety recommendations for a scan result."""
    indicator_results = [
        {"indicator": item.split(":", 1)[0], "triggered": True}
        for item in result["indicators"]
    ]
    return generate_recommendations(result["level"], indicator_results)
