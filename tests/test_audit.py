
import sqlite3
import tempfile
import unittest

from pathlib import Path

from backend.audit.audit_logger import AuditLogger
from backend.audit.audit_verifier import verify_audit_log


class TestAudit(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_audit.db"
        self.logger = AuditLogger(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_append_records(self):
        self.logger.append(
            "TEST_EVENT",
            {"event_id": "E1"}
        )

        result = verify_audit_log(self.db_path)

        self.assertTrue(result["valid"])
        self.assertEqual(result["records_checked"], 1)

    def test_multiple_records(self):
        self.logger.append("EVENT", {"id": 1})
        self.logger.append("INCIDENT", {"id": 2})

        result = verify_audit_log(self.db_path)

        self.assertTrue(result["valid"])
        self.assertEqual(result["records_checked"], 2)

    def test_update_blocked(self):

        # First insert an audit record.
        self.logger.append(
            "TEST_EVENT",
            {"event_id": "E1"}
        )

        # Now attempt to modify that existing record.
        with sqlite3.connect(self.db_path) as connection:

            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("""
                    UPDATE audit_records
                    SET record_type = 'MODIFIED'
                    WHERE sequence = 1
                """)

    def test_delete_blocked(self):
        self.logger.append("EVENT", {"id": 1})

        with sqlite3.connect(self.db_path) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("""
                    DELETE FROM audit_records
                    WHERE sequence = 1
                """)

    def test_tampering_detected(self):
        self.logger.append("EVENT", {"id": 1})
        self.logger.append("EVENT", {"id": 2})

        # Make a separate copy and remove its protections
        # to simulate privileged database tampering.
        tampered_path = Path(self.temp_dir.name) / "tampered.db"

        with sqlite3.connect(self.db_path) as source:
            with sqlite3.connect(tampered_path) as target:
                source.backup(target)

        with sqlite3.connect(tampered_path) as connection:
            connection.execute("DROP TRIGGER prevent_audit_update")
            connection.execute("""
                UPDATE audit_records
                SET payload_json = '{"id":999}'
                WHERE sequence = 1
            """)

        result = verify_audit_log(tampered_path)

        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])


if __name__ == "__main__":
    unittest.main()
