import unittest

from core.risk_engine import score_findings


class RiskEngineTests(unittest.TestCase):
    def test_empty_findings_are_low(self):
        result = score_findings([])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["classification"], "Low Risk")

    def test_duplicate_indicators_only_count_once(self):
        finding = {"key": "same", "points": 20, "indicator": "Example"}
        result = score_findings([finding, finding])
        self.assertEqual(result["score"], 20)
        self.assertEqual(len(result["findings"]), 1)

    def test_score_is_capped_at_one_hundred(self):
        result = score_findings([{"key": str(i), "points": 40} for i in range(5)])
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["classification"], "Critical Risk")

    def test_classification_boundaries(self):
        cases = [(20, "Low Risk"), (21, "Moderate Risk"), (40, "Moderate Risk"), (41, "Suspicious"), (61, "High Risk"), (81, "Critical Risk")]
        for points, expected in cases:
            with self.subTest(points=points):
                self.assertEqual(score_findings([{"key": "x", "points": points}])["classification"], expected)


if __name__ == "__main__":
    unittest.main()
