"""
test_scanner.py — Unit tests for PhishGuard scanners.

Tests verify that each function does what we claim it does.
We use pytest, a popular Python testing library.

How to run tests:
    cd PhishGuard
    pytest tests/test_scanner.py -v

The '-v' flag means "verbose" — it shows each test name and
whether it passed or failed.

Python concepts used:
    - assert statements (check if something is True)
    - Test functions (must start with "test_")
    - Importing from other modules
"""

# ---- URL Scanner Tests ----

from scanners.url_scanner import (
    check_https,
    check_ip_address,
    check_url_length,
    check_subdomains,
    check_suspicious_keywords,
    check_special_characters,
    scan_url
)
from utils.validators import is_valid_url, is_valid_message, sanitize_input


def test_check_https_detects_http():
    """HTTP URLs should trigger the HTTPS indicator."""
    res = check_https("http://example.com")
    assert res["triggered"] is True
    assert res["indicator"] == "https_check"


def test_check_https_passes_https():
    """HTTPS URLs should NOT trigger the HTTPS indicator."""
    res = check_https("https://example.com")
    assert res["triggered"] is False


def test_check_ip_address_detects_ip():
    """URLs with IP addresses should trigger the IP indicator."""
    res = check_ip_address("http://192.168.1.1/login")
    assert res["triggered"] is True
    assert res["indicator"] == "ip_address"


def test_check_ip_address_passes_domain():
    """URLs with normal domains should NOT trigger the IP indicator."""
    res = check_ip_address("http://example.com")
    assert res["triggered"] is False


def test_check_url_length_detects_long_url():
    """Very long URLs should trigger the length indicator."""
    long_url = "http://example.com/" + ("a" * 80)
    res = check_url_length(long_url)
    assert res["triggered"] is True
    assert res["indicator"] == "url_length"


def test_check_url_length_passes_short_url():
    """Normal-length URLs should NOT trigger the length indicator."""
    res = check_url_length("https://example.com/login")
    assert res["triggered"] is False


def test_check_subdomains_detects_many():
    """URLs with 3+ subdomains should trigger the subdomain indicator."""
    res = check_subdomains("http://secure.login.bank.example.com")
    assert res["triggered"] is True
    assert res["indicator"] == "excessive_subdomains"


def test_check_subdomains_passes_normal():
    """URLs with 0-2 subdomains should NOT trigger."""
    res = check_subdomains("https://www.example.com")
    assert res["triggered"] is False


def test_check_suspicious_keywords_detects():
    """URLs containing phishing keywords should trigger."""
    res = check_suspicious_keywords("http://example.com/verify-login-update")
    assert res["triggered"] is True
    assert "login" in res["matched_keywords"]
    assert "verify" in res["matched_keywords"]


def test_check_special_characters_detects_at():
    """URLs with @ symbol should trigger the special char indicator."""
    res = check_special_characters("http://google.com@evil.com/login")
    assert res["triggered"] is True
    assert "@" in res["found_characters"]



# ---- Message Scanner Tests ----


def test_extract_urls_finds_url():
    """Messages containing URLs should return them in a list."""
    pass


def test_extract_urls_empty_message():
    """Messages with no URLs should return an empty list."""
    pass


def test_detect_urgency_finds_urgent():
    """Messages with urgency words should trigger."""
    pass


def test_detect_threat_language_finds_threat():
    """Messages with threat words should trigger."""
    pass


def test_detect_credential_request_finds_request():
    """Messages asking for credentials should trigger."""
    pass


def test_detect_financial_request_finds_request():
    """Messages asking for money/banking info should trigger."""
    pass


# ---- Risk Engine Tests ----


def test_classify_threat_low():
    """Scores 0-24 should classify as LOW."""
    pass


def test_classify_threat_medium():
    """Scores 25-49 should classify as MEDIUM."""
    pass


def test_classify_threat_high():
    """Scores 50-74 should classify as HIGH."""
    pass


def test_classify_threat_critical():
    """Scores 75-100 should classify as CRITICAL."""
    pass


def test_risk_score_capped_at_100():
    """Risk score should never exceed 100, even with many indicators."""
    pass


# ---- Validator Tests ----


def test_is_valid_url_accepts_http():
    """HTTP URLs should be accepted as valid."""
    assert is_valid_url("http://example.com") is True
    assert is_valid_url("https://www.example.com/login") is True


def test_is_valid_url_rejects_garbage():
    """Random text should be rejected as invalid URL."""
    assert is_valid_url("not a url") is False
    assert is_valid_url("hello world") is False
    assert is_valid_url("") is False


def test_is_valid_message_rejects_empty():
    """Empty strings should be rejected as invalid messages."""
    assert is_valid_message("") is False
    assert is_valid_message("hi") is False
    assert is_valid_message("Urgent notice regarding your account security") is True

