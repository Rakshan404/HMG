
import hashlib
import json
import sqlite3

from pathlib import Path

from backend.audit.audit_logger import (
    GENESIS_HASH,
    canonical_json
)


def verify_audit_log(db_path="data/hmg_audit.db"):
    """Verify every record and link in the audit chain."""

    path = Path(db_path).resolve()

    if not path.exists():
        return {
            "valid": False,
            "records_checked": 0,
            "errors": ["Audit database does not exist"]
        }

    connection = sqlite3.connect(
        f"file:{path.as_posix()}?mode=ro",
        uri=True
    )

    errors = []
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    records_checked = 0

    try:
        rows = connection.execute("""
            SELECT
                sequence,
                timestamp,
                record_type,
                payload_json,
                previous_hash,
                record_hash
            FROM audit_records
            ORDER BY sequence ASC
        """).fetchall()

        for row in rows:

            (
                sequence,
                timestamp,
                record_type,
                payload_json,
                stored_previous_hash,
                stored_hash
            ) = row

            records_checked += 1

            if sequence != expected_sequence:
                errors.append(
                    f"Unexpected sequence at record {sequence}"
                )

            payload = json.loads(payload_json)

            if stored_previous_hash != previous_hash:
                errors.append(
                    f"Previous hash mismatch at record {sequence}"
                )

            hash_data = {
                "sequence": sequence,
                "timestamp": timestamp,
                "record_type": record_type,
                "payload": payload,
                "previous_hash": stored_previous_hash
            }

            calculated_hash = hashlib.sha256(
                canonical_json(hash_data).encode("utf-8")
            ).hexdigest()

            if calculated_hash != stored_hash:
                errors.append(
                    f"Record hash mismatch at record {sequence}"
                )

            previous_hash = stored_hash
            expected_sequence += 1

    except (sqlite3.Error, json.JSONDecodeError) as exc:
        errors.append(f"Verification error: {exc}")

    finally:
        connection.close()

    return {
        "valid": len(errors) == 0,
        "records_checked": records_checked,
        "last_hash": previous_hash if records_checked else None,
        "errors": errors
    }
