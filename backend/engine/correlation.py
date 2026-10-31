
from collections import defaultdict
from datetime import datetime, timedelta


def _parse_timestamp(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def _device_key(event):
    """
    Prefer MAC address when available.
    Otherwise use source IP.
    """
    mac = event.get("source_mac")

    if mac:
        return f"mac:{mac.lower()}"

    return f"ip:{event['source_ip']}"


def correlate_events(events, window_seconds=300):
    """
    Group events belonging to the same device.

    Events in one group must also fall within the
    configured time window.
    """

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    devices = defaultdict(list)

    for event in events:
        key = _device_key(event)
        devices[key].append(event)

    groups = []

    for device_key, device_events in devices.items():

        device_events.sort(
            key=lambda event: _parse_timestamp(event["timestamp"])
        )

        current_group = []

        for event in device_events:

            event_time = _parse_timestamp(event["timestamp"])

            if current_group:
                first_time = _parse_timestamp(
                    current_group[0]["timestamp"]
                )

                if event_time - first_time > timedelta(
                    seconds=window_seconds
                ):
                    groups.append(
                        _build_group(device_key, current_group)
                    )
                    current_group = []

            current_group.append(event)

        if current_group:
            groups.append(
                _build_group(device_key, current_group)
            )

    return groups


def _build_group(device_key, events):
    timestamps = [
        _parse_timestamp(event["timestamp"])
        for event in events
    ]

    return {
        "device_key": device_key,
        "source_ip": events[-1]["source_ip"],
        "source_mac": events[-1]["source_mac"],
        "event_count": len(events),
        "honeypots": sorted({
            event["honeypot"] for event in events
        }),
        "events": events,
        "start_time": min(timestamps).isoformat(),
        "end_time": max(timestamps).isoformat()
    }
