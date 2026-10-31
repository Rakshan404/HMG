"""Structured interaction logging; submitted passwords are never logged."""
import json
import logging
from datetime import datetime, timezone

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
    logger.info(json.dumps(record, ensure_ascii=True, separators=(",", ":")))
