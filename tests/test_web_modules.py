import pytest

import storage
from engine.risk_engine import calculate_risk_score, classify_threat
from scanner import scan_message, scan_url
from scanners.message_scanner import scan_message as legacy_scan_message
from scanners.url_scanner import scan_url as legacy_scan_url


def test_scan_url_preserves_existing_score_and_indicators():
    url = "http://example.com/verify-login"
    old_results = legacy_scan_url(url)
    result = scan_url(url)

    assert result["score"] == calculate_risk_score(old_results)
    assert result["level"] == classify_threat(result["score"])
    assert len(result["indicators"]) == sum(
        indicator["triggered"] for indicator in old_results
    )


def test_scan_message_includes_embedded_url_analysis():
    message = "Urgent! Verify your password at http://192.168.1.1/login"
    old_message = legacy_scan_message(message)
    old_results = list(old_message["message_indicators"])
    for url in old_message["extracted_urls"]:
        old_results.extend(legacy_scan_url(url))
    result = scan_message(message)

    assert result["score"] == calculate_risk_score(old_results)
    assert result["level"] == classify_threat(result["score"])


@pytest.mark.parametrize(
    ("scanner", "value"),
    [(scan_url, "not a url"), (scan_message, "hi")],
)
def test_scanners_reject_invalid_input(scanner, value):
    with pytest.raises(ValueError):
        scanner(value)


def test_json_storage_adds_stats_and_clears_history(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "HISTORY_FILE", tmp_path / "history.json")

    storage.add_scan("URL", "https://example.com", 10, "LOW")
    storage.add_scan("Message", "Urgent account notice", 55, "HIGH")

    assert len(storage.get_history()) == 2
    assert storage.get_stats() == {
        "total_scans": 2,
        "counts_per_level": {
            "LOW": 1,
            "MEDIUM": 0,
            "HIGH": 1,
            "CRITICAL": 0,
        },
        "average_score": 32.5,
    }

    storage.clear_history()
    assert storage.get_history() == []
