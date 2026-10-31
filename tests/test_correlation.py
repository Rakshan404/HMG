
import unittest

from backend.engine.correlation import correlate_events


def make_event(event_id, ip, mac, service, time):
    return {
        "event_id": event_id,
        "timestamp": time,
        "source_ip": ip,
        "source_mac": mac,
        "honeypot": service,
        "event": "login_attempt",
        "details": {}
    }


class TestCorrelation(unittest.TestCase):

    def test_same_device_grouped(self):
        events = [
            make_event(
                "E1", "192.168.50.20", "AA:BB:CC:DD:EE:FF",
                "HTTP", "2026-10-31T10:00:00+00:00"
            ),
            make_event(
                "E2", "192.168.50.20", "AA:BB:CC:DD:EE:FF",
                "SSH", "2026-10-31T10:01:00+00:00"
            )
        ]

        groups = correlate_events(events)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["event_count"], 2)
        self.assertEqual(groups[0]["honeypots"], ["HTTP", "SSH"])

    def test_different_devices_separated(self):
        events = [
            make_event(
                "E1", "192.168.50.20", None,
                "HTTP", "2026-10-31T10:00:00+00:00"
            ),
            make_event(
                "E2", "192.168.50.21", None,
                "SSH", "2026-10-31T10:01:00+00:00"
            )
        ]

        self.assertEqual(len(correlate_events(events)), 2)

    def test_time_window_separates_events(self):
        events = [
            make_event(
                "E1", "192.168.50.20", None,
                "HTTP", "2026-10-31T10:00:00+00:00"
            ),
            make_event(
                "E2", "192.168.50.20", None,
                "SSH", "2026-10-31T11:00:00+00:00"
            )
        ]

        self.assertEqual(len(correlate_events(events)), 2)


if __name__ == "__main__":
    unittest.main()
