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


def test_check_https_detects_http():
    """HTTP URLs should trigger the HTTPS indicator."""
    # Will call check_https("http://example.com") and verify
    # that triggered is True.
    pass


def test_check_https_passes_https():
    """HTTPS URLs should NOT trigger the HTTPS indicator."""
    pass


def test_check_ip_address_detects_ip():
    """URLs with IP addresses should trigger the IP indicator."""
    pass


def test_check_ip_address_passes_domain():
    """URLs with normal domains should NOT trigger the IP indicator."""
    pass


def test_check_url_length_detects_long_url():
    """Very long URLs should trigger the length indicator."""
    pass


def test_check_url_length_passes_short_url():
    """Normal-length URLs should NOT trigger the length indicator."""
    pass


def test_check_subdomains_detects_many():
    """URLs with 3+ subdomains should trigger the subdomain indicator."""
    pass


def test_check_subdomains_passes_normal():
    """URLs with 0-2 subdomains should NOT trigger."""
    pass


def test_check_suspicious_keywords_detects():
    """URLs containing phishing keywords should trigger."""
    pass


def test_check_special_characters_detects_at():
    """URLs with @ symbol should trigger the special char indicator."""
    pass


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
    pass


def test_is_valid_url_rejects_garbage():
    """Random text should be rejected as invalid URL."""
    pass


def test_is_valid_message_rejects_empty():
    """Empty strings should be rejected as invalid messages."""
    pass
