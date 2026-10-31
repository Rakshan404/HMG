
import unittest

from backend.engine.ioc_extractor import extract_iocs


class TestIOCExtractor(unittest.TestCase):

    def test_extract_ip(self):
        events = [{
            "event_id": "E1",
            "details": {
                "remote_ip": "203.0.113.10"
            }
        }]

        result = extract_iocs(events)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "ip")

    def test_extract_domain(self):
        events = [{
            "event_id": "E1",
            "details": {
                "domain": "example.com"
            }
        }]

        result = extract_iocs(events)

        self.assertEqual(result[0]["type"], "domain")

    def test_extract_sha256(self):
        digest = "a" * 64

        events = [{
            "event_id": "E1",
            "details": {
                "file_hash": digest
            }
        }]

        result = extract_iocs(events)

        self.assertEqual(result[0]["type"], "sha256")

    def test_ignore_invalid_ip(self):
        events = [{
            "event_id": "E1",
            "details": {
                "remote_ip": "999.999.999.999"
            }
        }]

        self.assertEqual(extract_iocs(events), [])


if __name__ == "__main__":
    unittest.main()

