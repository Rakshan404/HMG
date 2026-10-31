
import unittest

from backend.engine.mitre_mapper import map_to_mitre


class TestMitreMapper(unittest.TestCase):

    def test_repeated_login_mapping(self):
        findings = [{
            "rule_id": "REPEATED_LOGIN_ATTEMPTS",
            "event_ids": ["E1", "E2", "E3"]
        }]

        result = map_to_mitre(findings)

        self.assertEqual(result[0]["technique_id"], "T1110")

    def test_smb_mapping(self):
        findings = [{
            "rule_id": "SMB_SHARE_ENUMERATION",
            "event_ids": ["E1"]
        }]

        result = map_to_mitre(findings)

        self.assertEqual(result[0]["technique_id"], "T1135")

    def test_unmapped_finding(self):
        findings = [{
            "rule_id": "HTTP_ADMIN_PATH",
            "event_ids": ["E1"]
        }]

        self.assertEqual(map_to_mitre(findings), [])


if __name__ == "__main__":
    unittest.main()
