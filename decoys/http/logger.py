"""Structured interaction logging; submitted passwords are never logged."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

EVENTS_FILE = Path(__file__).resolve().parents[2] / "data" / "http_events.jsonl"

logger = logging.getLogger("hmg.http")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def log_event(*, source_ip, user_agent, endpoint, username, event="login_attempt"):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "endpoint": endpoint,
        "username": username,
    }
    serialized = json.dumps(record, ensure_ascii=True, separators=(",", ":"))
    logger.info(serialized)
    try:
        EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS_FILE.open("a", encoding="utf-8", newline="\n") as events_file:
            events_file.write(serialized + "\n")
            events_file.flush()
    except OSError as exc:
        logger.error("HTTP event persistence failed for %s: %s", EVENTS_FILE, exc)
        raise
