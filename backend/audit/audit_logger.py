
import hashlib
import json
import sqlite3

from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing


GENESIS_HASH = "0" * 64


def canonical_json(data):
    """Produce deterministic JSON for hashing."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


class AuditLogger:

    def __init__(self, db_path="data/hmg_audit.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._initialise_database()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _initialise_database(self):
        with closing(self._connect()) as connection:
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS audit_records (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        record_type TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        record_hash TEXT NOT NULL UNIQUE
                    )
                """)

                connection.execute("""
                    CREATE TRIGGER IF NOT EXISTS prevent_audit_update
                    BEFORE UPDATE ON audit_records
                    BEGIN
                        SELECT RAISE(ABORT, 'Audit records cannot be updated');
                    END;
                """)

                connection.execute("""
                    CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
                    BEFORE DELETE ON audit_records
                    BEGIN
                        SELECT RAISE(ABORT, 'Audit records cannot be deleted');
                    END;
                """)

    def append(self, record_type, payload):
        """Append a new record to the audit chain."""

        if not isinstance(record_type, str) or not record_type.strip():
            raise ValueError("record_type must be a non-empty string")

        if not isinstance(payload, dict):
            raise ValueError("payload must be a dictionary")

        timestamp = datetime.now(timezone.utc).isoformat()
        payload_json = canonical_json(payload)

        with closing(self._connect()) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")

                previous = connection.execute("""
                    SELECT sequence, record_hash
                    FROM audit_records
                    ORDER BY sequence DESC
                    LIMIT 1
                """).fetchone()

                if previous:
                    sequence = previous[0] + 1
                    previous_hash = previous[1]
                else:
                    sequence = 1
                    previous_hash = GENESIS_HASH

                hash_data = {
                    "sequence": sequence,
                    "timestamp": timestamp,
                    "record_type": record_type,
                    "payload": payload,
                    "previous_hash": previous_hash
                }

                record_hash = hashlib.sha256(
                    canonical_json(hash_data).encode("utf-8")
                ).hexdigest()

                connection.execute("""
                    INSERT INTO audit_records (
                        sequence,
                        timestamp,
                        record_type,
                        payload_json,
                        previous_hash,
                        record_hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    sequence,
                    timestamp,
                    record_type,
                    payload_json,
                    previous_hash,
                    record_hash
                ))

        return {
            "sequence": sequence,
            "record_hash": record_hash,
            "previous_hash": previous_hash
        }
