
import ipaddress
import re
from datetime import datetime
from copy import deepcopy


class EventValidationError(ValueError):
    """Raised when an incoming HMG event is invalid."""
    pass


REQUIRED_FIELDS = {
    "event_id",
    "timestamp",
    "source_ip",
    "source_mac",
    "honeypot",
    "event",
    "details"
}

ALLOWED_HONEYPOTS = {"HTTP", "SSH", "SMB"}

MAC_PATTERN = re.compile(
    r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
)


def normalize_event(event: dict) -> dict:
    """
    Validate and normalise an incoming HMG security event.

    Returns a copy of the event if valid.
    Raises EventValidationError if invalid.
    """

    # 1. Check that the input is a dictionary.
    if not isinstance(event, dict):
        raise EventValidationError("Event must be a JSON object")

    # 2. Check required fields and reject unexpected fields.
    missing = REQUIRED_FIELDS - event.keys()
    extra = event.keys() - REQUIRED_FIELDS

    if missing:
        raise EventValidationError(
            f"Missing required fields: {sorted(missing)}"
        )

    if extra:
        raise EventValidationError(
            f"Unexpected fields: {sorted(extra)}"
        )

    # 3. Validate event ID.
    if not isinstance(event["event_id"], str) or not event["event_id"].strip():
        raise EventValidationError("Invalid event_id")

    # 4. Validate timestamp.
    if not isinstance(event["timestamp"], str):
        raise EventValidationError("Timestamp must be a string")

    try:
        timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            raise EventValidationError(
                "Timestamp must include timezone information"
            )

    except ValueError as exc:
        raise EventValidationError(
            "Invalid ISO 8601 timestamp"
        ) from exc

    # 5. Validate source IP.
    try:
        source_ip = ipaddress.ip_address(event["source_ip"])

        if source_ip.version != 4:
            raise EventValidationError("Only IPv4 addresses are supported")

    except ValueError as exc:
        raise EventValidationError("Invalid source_ip") from exc

    # 6. Validate source MAC.
    source_mac = event["source_mac"]

    if source_mac is not None:
        if not isinstance(source_mac, str):
            raise EventValidationError(
                "source_mac must be a string or null"
            )

        if not MAC_PATTERN.fullmatch(source_mac):
            raise EventValidationError("Invalid MAC address")

    # 7. Validate honeypot.
    if event["honeypot"] not in ALLOWED_HONEYPOTS:
        raise EventValidationError("Unsupported honeypot")

    # 8. Validate event name.
    if not isinstance(event["event"], str) or not event["event"].strip():
        raise EventValidationError("Invalid event name")

    # 9. Validate details.
    if not isinstance(event["details"], dict):
        raise EventValidationError("details must be a JSON object")

    # 10. Return a copy so the original event is not modified.
    return deepcopy(event)
