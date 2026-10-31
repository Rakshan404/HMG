
import unittest

from backend.engine.analyzer import analyze_events


def event(event_id, service, name, details):
    return {
        "event_id": event_id,
        "timestamp": "2026-10-31T10:00:00+00:00",
        "source_ip": "192.168.50.20",
        "source_mac": None,
        "honeypot": service,
        "event": name,
        "details": details
    }


class TestAnalyzer(unittest.TestCase):

    def test_admin_path_finding(self):
        events = [
            event("E1", "HTTP", "suspicious_request",
                  {"path": "/admin"})
        ]

        findings = analyze_events(events)

        self.assertIn(
            "HTTP_ADMIN_PATH",
            [finding["rule_id"] for finding in findings]
        )

    def test_repeated_login_finding(self):
        events = [
            event(f"E{i}", "SSH", "login_attempt", {})
            for i in range(3)
        ]

        findings = analyze_events(events)

        self.assertIn(
            "REPEATED_LOGIN_ATTEMPTS",
            [finding["rule_id"] for finding in findings]
        )

    def test_multiple_honeypots(self):
        events = [
            event("E1", "HTTP", "request", {}),
            event("E2", "SSH", "connection", {})
        ]

        findings = analyze_events(events)

        self.assertIn(
            "MULTI_HONEYPOT_INTERACTION",
            [finding["rule_id"] for finding in findings]
        )

    def test_no_findings_for_unmatched_activity(self):
        events = [
            event("E1", "HTTP", "ordinary_request",
                  {"path": "/"})
        ]

        self.assertEqual(analyze_events(events), [])


if __name__ == "__main__":
    unittest.main()
