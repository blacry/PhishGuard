"""Tests for URL scanning, validation, and risk scoring."""

from engine.recommendation_engine import (
    generate_explanation,
    generate_recommendations,
)
from engine.risk_engine import (
    calculate_risk_score,
    classify_threat,
    classify_with_reputation,
)
from scanners.url_scanner import (
    check_https,
    check_ip_address,
    check_special_characters,
    check_subdomains,
    check_suspicious_keywords,
    check_url_length,
)
from utils.validators import is_valid_message, is_valid_url


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


def test_check_subdomains_handles_malformed_ipv6_host():
    res = check_subdomains("http://[malformed")

    assert res["triggered"] is False
    assert "could not be parsed" in res["detail"]


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



# ---- Risk Engine Tests ----


def test_classify_threat_low():
    """Scores 0-24 should classify as LOW."""
    assert classify_threat(0) == "LOW"
    assert classify_threat(15) == "LOW"
    assert classify_threat(24) == "LOW"


def test_classify_threat_medium():
    """Scores 25-49 should classify as MEDIUM."""
    assert classify_threat(25) == "MEDIUM"
    assert classify_threat(35) == "MEDIUM"
    assert classify_threat(49) == "MEDIUM"


def test_classify_threat_high():
    """Scores 50-74 should classify as HIGH."""
    assert classify_threat(50) == "HIGH"
    assert classify_threat(65) == "HIGH"
    assert classify_threat(74) == "HIGH"


def test_classify_threat_critical():
    """Scores 75-100 should classify as CRITICAL."""
    assert classify_threat(75) == "CRITICAL"
    assert classify_threat(90) == "CRITICAL"
    assert classify_threat(100) == "CRITICAL"


def test_reputation_escalates_label_without_changing_static_score():
    result = {"status": "known_malicious"}
    assert classify_with_reputation(10, [result]) == "CRITICAL"
    assert classify_with_reputation(10, [{"status": "not_listed"}]) == "LOW"


def test_risk_score_capped_at_100():
    """Risk score should never exceed 100, even with many indicators."""
    many_indicators = [
        {"indicator": "ip_address", "triggered": True},        # 25
        {"indicator": "credential_request", "triggered": True},# 25
        {"indicator": "financial_request", "triggered": True}, # 25
        {"indicator": "special_characters", "triggered": True},# 20
        {"indicator": "threat_language", "triggered": True},   # 20
        {"indicator": "url_length", "triggered": True}         # 15
    ]
    # Total raw weight = 130 -> capped to 100
    score = calculate_risk_score(many_indicators)
    assert score == 100


def test_generate_explanation_and_recommendations():
    """Explanation and recommendations should contain actionable details."""
    sample = [
        {"indicator": "ip_address", "triggered": True, "detail": "Raw IP used"}
    ]
    explanation = generate_explanation(sample)
    recs = generate_recommendations("HIGH", sample)

    assert "Raw IP Address" in explanation
    assert len(recs) > 0
    assert any("HIGH RISK" in r for r in recs)



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


def test_is_valid_url_rejects_unsafe_schemes():
    assert is_valid_url("javascript:alert(1)") is False
    assert is_valid_url("ftp://example.com/file") is False
    assert is_valid_url("file:///tmp/example") is False


def test_is_valid_url_rejects_malformed_hosts():
    assert is_valid_url("http://") is False
    assert is_valid_url("http://user:pass@example.com") is False
    assert is_valid_url("http://999.999.999.999") is False
    assert is_valid_url("http://example-.com") is False
    assert is_valid_url("http://example.com:99999") is False
    assert is_valid_url("http://example.com/\npath") is False


def test_is_valid_url_accepts_ipv4_ipv6_and_idn():
    assert is_valid_url("http://192.168.1.1/login") is True
    assert is_valid_url("http://[2001:db8::1]/login") is True
    assert is_valid_url("https://example.com") is True
    assert is_valid_url("https://münich.example") is True


def test_is_valid_message_rejects_empty():
    """Empty strings should be rejected as invalid messages."""
    assert is_valid_message("") is False
    assert is_valid_message("hi") is False
    assert is_valid_message("Urgent notice regarding your account security") is True



