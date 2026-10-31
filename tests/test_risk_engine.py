
import unittest

from backend.engine.risk_engine import calculate_risk


class TestRiskEngine(unittest.TestCase):

    def test_empty_findings(self):
        result = calculate_risk([])

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "LOW")

    def test_score_calculation(self):
        findings = [
            {
                "rule_id": "RULE_A",
                "description": "First finding",
                "points": 25
            },
            {
                "rule_id": "RULE_B",
                "description": "Second finding",
                "points": 25
            }
        ]

        result = calculate_risk(findings)

        self.assertEqual(result["risk_score"], 50)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_duplicate_rule_not_counted_twice(self):
        finding = {
            "rule_id": "RULE_A",
            "description": "Repeated evidence",
            "points": 25
        }

        result = calculate_risk([finding, finding])

        self.assertEqual(result["risk_score"], 25)

    def test_score_capped_at_100(self):
        findings = [
            {
                "rule_id": f"RULE_{i}",
                "description": "Finding",
                "points": 50
            }
            for i in range(4)
        ]

        self.assertEqual(
            calculate_risk(findings)["risk_score"],
            100
        )


if __name__ == "__main__":
    unittest.main()
