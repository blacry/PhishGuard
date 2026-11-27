import unittest

from detectors.email_detector import analyze_email
from detectors.message_detector import analyze_message
from detectors.text_detector import extract_urls


class EmailDetectorTests(unittest.TestCase):
    def test_urgency_is_detected(self):
        result = analyze_email("Urgent: account suspended. Act immediately.")
        self.assertIn("urgent_language", {item["key"] for item in result["findings"]})

    def test_sensitive_request_is_detected(self):
        result = analyze_email("Reply with your OTP and password.")
        self.assertIn("sensitive_request", {item["key"] for item in result["findings"]})

    def test_url_extraction_and_analysis(self):
        result = analyze_email("Please visit https://bit.ly/verify now.")
        self.assertEqual(result["urls"], ["https://bit.ly/verify"])
        self.assertEqual(len(result["url_results"]), 1)
        self.assertIn("shortened_url", {item["key"] for item in result["findings"]})

    def test_unique_url_extraction(self):
        self.assertEqual(extract_urls("https://example.com https://example.com."), ["https://example.com"])

    def test_message_patterns(self):
        result = analyze_message("Your delivery failed. Pay a fee now: http://example.com")
        keys = {item["key"] for item in result["findings"]}
        self.assertIn("scam_pattern", keys)
        self.assertIn("payment_request", keys)

    def test_empty_content_is_invalid(self):
        self.assertFalse(analyze_email(" ")["valid"])


if __name__ == "__main__":
    unittest.main()
