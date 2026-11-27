"""Tests for message text analysis and embedded URL extraction."""

from scanners.message_scanner import (
    detect_credential_request,
    detect_financial_request,
    detect_threat_language,
    detect_urgency,
    extract_urls,
)


def test_extract_urls_finds_url():
    urls = extract_urls("Please click http://example.com/login for details.")

    assert urls == ["http://example.com/login"]


def test_extract_urls_empty_message():
    assert extract_urls("Hello there, hope you have a great day!") == []


def test_detect_urgency_finds_urgent():
    result = detect_urgency("Act now! You must respond within 24 hours.")

    assert result["triggered"] is True
    assert result["indicator"] == "urgency_language"
    assert "act now" in result["matched_words"]


def test_detect_threat_language_finds_threat():
    result = detect_threat_language(
        "Your account will be suspended due to unauthorized access."
    )

    assert result["triggered"] is True
    assert result["indicator"] == "threat_language"


def test_detect_credential_request_finds_request():
    result = detect_credential_request("Please verify your password immediately.")

    assert result["triggered"] is True
    assert result["indicator"] == "credential_request"
    assert "verify your password" in result["matched_words"]


def test_detect_financial_request_finds_request():
    result = detect_financial_request(
        "Send payment using a gift card or bank account."
    )

    assert result["triggered"] is True
    assert result["indicator"] == "financial_request"
    assert "bank account" in result["matched_words"]
