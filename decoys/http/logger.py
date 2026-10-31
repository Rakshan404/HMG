
"""Structured HTTP honeypot event logging.

Passwords and other submitted secrets are never logged.
Events follow the shared HMG seven-field event contract.
"""

import json
import logging
import re
import threading

from datetime import datetime, timezone
from pathlib import Path


EVENTS_FILE = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "http_events.jsonl"
)

_event_lock = threading.Lock()

logger = logging.getLogger("hmg.http")

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def _next_event_id():
    """Find the next event ID using the existing JSONL history."""

    highest_id = 0

    if EVENTS_FILE.exists():
        with EVENTS_FILE.open("r", encoding="utf-8") as events_file:
            for line in events_file:
                try:
                    record = json.loads(line)
                    event_id = record.get("event_id", "")
                    match = re.fullmatch(r"EVT-(\d+)", event_id)

                    if match:
                        highest_id = max(
                            highest_id,
                            int(match.group(1))
                        )

                except (json.JSONDecodeError, AttributeError):
                    continue

    return f"EVT-{highest_id + 1:03d}"


def log_event(
    *,
    source_ip,
    user_agent,
    endpoint,
    username,
    event="login_attempt",
    source_mac=None
):
    """Create and persist one structured HTTP security event."""

    with _event_lock:

        EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)

        record = {
            "event_id": _next_event_id(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "source_mac": source_mac,
            "honeypot": "HTTP",
            "event": event,
            "details": {
                "user_agent": user_agent,
                "endpoint": endpoint,
                "username": username
            }
        }

        serialized = json.dumps(
            record,
            ensure_ascii=True,
            separators=(",", ":")
        )

        logger.info(serialized)

        try:
            with EVENTS_FILE.open(
                "a",
                encoding="utf-8",
                newline="\n"
            ) as events_file:
                events_file.write(serialized + "\n")
                events_file.flush()

        except OSError as exc:
            logger.error(
                "HTTP event persistence failed for %s: %s",
                EVENTS_FILE,
                exc
            )
            raise

    return record
