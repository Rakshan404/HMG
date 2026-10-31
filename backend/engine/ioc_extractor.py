
import hashlib
import ipaddress
import re


HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$")
}

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


IP_KEYS = {"ip", "remote_ip", "target_ip", "destination_ip"}
DOMAIN_KEYS = {"domain", "hostname", "remote_domain"}
HASH_KEYS = {"file_hash", "hash", "md5", "sha1", "sha256"}


def extract_iocs(events):
    """Extract candidate IOCs from explicitly labelled event details."""

    indicators = []
    seen = set()

    def add_indicator(kind, value, event_id):
        key = (kind, value.lower())

        if key in seen:
            return

        seen.add(key)

        indicators.append({
            "type": kind,
            "value": value,
            "source_event_id": event_id,
            "confidence": "candidate"
        })

    def inspect(data, event_id):
        if isinstance(data, dict):

            for key, value in data.items():
                normal_key = key.lower()

                if not isinstance(value, str):
                    inspect(value, event_id)
                    continue

                if normal_key in IP_KEYS:
                    try:
                        ipaddress.ip_address(value)
                        add_indicator("ip", value, event_id)
                    except ValueError:
                        pass

                elif normal_key in DOMAIN_KEYS:
                    if DOMAIN_PATTERN.fullmatch(value):
                        add_indicator("domain", value, event_id)

                elif normal_key in HASH_KEYS:
                    for hash_type, pattern in HASH_PATTERNS.items():
                        if pattern.fullmatch(value):
                            add_indicator(hash_type, value.lower(), event_id)
                            break

        elif isinstance(data, list):
            for item in data:
                inspect(item, event_id)

    for event in events:
        inspect(event["details"], event["event_id"])

    return indicators
