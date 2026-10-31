
import unittest

from backend.engine.normalizer import (
    normalize_event,
    EventValidationError
)


VALID_EVENT = {
    "event_id": "EVT-001",
    "timestamp": "2026-10-31T12:39:02.559998+00:00",
    "source_ip": "127.0.0.1",
    "source_mac": "AA:BB:CC:DD:EE:FF",
    "honeypot": "HTTP",
    "event": "suspicious_request",
    "details": {
        "user_agent": "curl/8.21.0",
        "endpoint": "/login",
        "username": "operator"
    }
}


class TestNormalizer(unittest.TestCase):

    def test_valid_event(self):
        result = normalize_event(VALID_EVENT)
        self.assertEqual(result, VALID_EVENT)

    def test_nullable_mac(self):
        event = VALID_EVENT.copy()
        event["source_mac"] = None

        result = normalize_event(event)
        self.assertIsNone(result["source_mac"])

    def test_invalid_ip(self):
        event = VALID_EVENT.copy()
        event["source_ip"] = "192.168.50.999"

        with self.assertRaises(EventValidationError):
            normalize_event(event)

    def test_missing_event_id(self):
        event = VALID_EVENT.copy()
        del event["event_id"]

        with self.assertRaises(EventValidationError):
            normalize_event(event)

    def test_invalid_honeypot(self):
        event = VALID_EVENT.copy()
        event["honeypot"] = "FTP"

        with self.assertRaises(EventValidationError):
            normalize_event(event)

    def test_invalid_mac(self):
        event = VALID_EVENT.copy()
        event["source_mac"] = "INVALID-MAC"

        with self.assertRaises(EventValidationError):
            normalize_event(event)

    def test_timezone_required(self):
        event = VALID_EVENT.copy()
        event["timestamp"] = "2026-10-31T12:39:02"

        with self.assertRaises(EventValidationError):
            normalize_event(event)


if __name__ == "__main__":
    unittest.main()
