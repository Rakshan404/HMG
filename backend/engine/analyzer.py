
from collections import defaultdict


ADMIN_PATHS = {
    "/admin",
    "/wp-admin",
    "/phpmyadmin"
}


def analyze_events(events):
    """
    Analyse a list of validated events.

    Returns evidence-based findings.
    Does not directly decide whether a device is malicious.
    """

    findings = []

    by_device = defaultdict(list)

    for event in events:
        key = (
            event["source_mac"].lower()
            if event["source_mac"]
            else event["source_ip"]
        )

        by_device[key].append(event)

    for device_key, device_events in by_device.items():

        source_ip = device_events[0]["source_ip"]

        # Rule 1: Access to commonly targeted admin paths.
        admin_events = []

        for event in device_events:
            details = event["details"]

            path = details.get(
                "path",
                details.get("endpoint", "")
            )

            if path in ADMIN_PATHS:
                admin_events.append(event)

        if admin_events:
            findings.append({
                "rule_id": "HTTP_ADMIN_PATH",
                "description": "Interaction with an administrative endpoint",
                "severity": "low",
                "points": 10,
                "source_ip": source_ip,
                "event_ids": [
                    event["event_id"] for event in admin_events
                ]
            })

        # Rule 2: Repeated login attempts.
        login_events = [
            event for event in device_events
            if "login" in event["event"].lower()
            or "auth" in event["event"].lower()
        ]

        if len(login_events) >= 3:
            findings.append({
                "rule_id": "REPEATED_LOGIN_ATTEMPTS",
                "description": "Three or more authentication-related interactions",
                "severity": "medium",
                "points": 25,
                "source_ip": source_ip,
                "event_ids": [
                    event["event_id"] for event in login_events
                ]
            })

        # Rule 3: Interactions with multiple honeypot services.
        services = {
            event["honeypot"] for event in device_events
        }

        if len(services) >= 2:
            findings.append({
                "rule_id": "MULTI_HONEYPOT_INTERACTION",
                "description": "Device interacted with multiple honeypot services",
                "severity": "medium",
                "points": 25,
                "source_ip": source_ip,
                "event_ids": [
                    event["event_id"] for event in device_events
                ]
            })

        # Rule 4: SMB share enumeration indicators.
        smb_events = []

        for event in device_events:
            if event["honeypot"] != "SMB":
                continue

            details = event["details"]

            action = str(
                details.get("action", "")
            ).lower()

            event_name = event["event"].lower()

            if (
                "enumerat" in action
                or "list_share" in action
                or "share_enum" in event_name
            ):
                smb_events.append(event)

        if smb_events:
            findings.append({
                "rule_id": "SMB_SHARE_ENUMERATION",
                "description": "SMB share enumeration behaviour observed",
                "severity": "medium",
                "points": 25,
                "source_ip": source_ip,
                "event_ids": [
                    event["event_id"] for event in smb_events
                ]
            })

    return findings
