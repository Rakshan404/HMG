
import unittest
import tempfile

from pathlib import Path

from backend.engine.pipeline import process_events
from backend.audit.audit_logger import AuditLogger
from backend.audit.audit_verifier import verify_audit_log


class TestPipeline(unittest.TestCase):

    def test_complete_pipeline(self):

        events = [
            {
                "event_id": "E1",
                "timestamp": "2026-10-31T10:00:00+00:00",
                "source_ip": "192.168.50.20",
                "source_mac": "AA:BB:CC:DD:EE:FF",
                "honeypot": "HTTP",
                "event": "suspicious_request",
                "details": {
                    "path": "/admin",
                    "remote_ip": "203.0.113.10"
                }
            },
            {
                "event_id": "E2",
                "timestamp": "2026-10-31T10:01:00+00:00",
                "source_ip": "192.168.50.20",
                "source_mac": "AA:BB:CC:DD:EE:FF",
                "honeypot": "SSH",
                "event": "login_attempt",
                "details": {
                    "username": "admin"
                }
            },
            {
                "event_id": "E3",
                "timestamp": "2026-10-31T10:02:00+00:00",
                "source_ip": "192.168.50.20",
                "source_mac": "AA:BB:CC:DD:EE:FF",
                "honeypot": "SSH",
                "event": "login_attempt",
                "details": {
                    "username": "root"
                }
            },
            {
                "event_id": "E4",
                "timestamp": "2026-10-31T10:03:00+00:00",
                "source_ip": "192.168.50.20",
                "source_mac": "AA:BB:CC:DD:EE:FF",
                "honeypot": "SSH",
                "event": "login_attempt",
                "details": {
                    "username": "operator"
                }
            }
        ]

        with tempfile.TemporaryDirectory() as directory:

            db_path = Path(directory) / "audit.db"
            logger = AuditLogger(db_path)

            result = process_events(events, logger)

            self.assertEqual(result["events_processed"], 4)
            self.assertEqual(result["device_groups"], 1)
            self.assertEqual(len(result["incidents"]), 1)

            incident = result["incidents"][0]

            self.assertEqual(incident["source_ip"], "192.168.50.20")
            self.assertEqual(incident["risk_level"], "HIGH")
            self.assertEqual(incident["status"], "PENDING_REVIEW")

            verification = verify_audit_log(db_path)

            self.assertTrue(verification["valid"])
            self.assertEqual(verification["records_checked"], 1)


if __name__ == "__main__":
    unittest.main()
