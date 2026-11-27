import unittest

from detectors.url_detector import analyze_url


class UrlDetectorTests(unittest.TestCase):
    def test_valid_url_is_parsed(self):
        result = analyze_url("https://example.com/path?a=1")
        self.assertTrue(result["valid"])
        self.assertEqual(result["details"]["hostname"], "example.com")
        self.assertEqual(result["details"]["protocol"], "https")

    def test_invalid_url_is_rejected(self):
        self.assertFalse(analyze_url("not a url")["valid"])
        self.assertFalse(analyze_url("")["valid"])

    def test_http_is_flagged(self):
        result = analyze_url("http://example.com")
        self.assertIn("http", {item["key"] for item in result["findings"]})

    def test_ip_address_is_flagged(self):
        result = analyze_url("http://192.168.1.10/login")
        self.assertIn("ip_address", {item["key"] for item in result["findings"]})

    def test_suspicious_keyword_is_explained(self):
        result = analyze_url("https://example.com/verify-account")
        finding = next(item for item in result["findings"] if item["key"] == "url_keyword")
        self.assertIn("verify", finding["explanation"])

    def test_legitimate_official_brand_domain_is_not_impersonation(self):
        result = analyze_url("https://mail.google.com/")
        self.assertFalse(any(item["key"].startswith("brand_impersonation") for item in result["findings"]))

    def test_lookalike_domain_is_flagged(self):
        result = analyze_url("https://paypa1.com/login")
        self.assertTrue(any(item["key"].startswith("brand_impersonation") for item in result["findings"]))


if __name__ == "__main__":
    unittest.main()
