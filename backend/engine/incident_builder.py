
import uuid
from datetime import datetime, timezone


def build_incident(device_group, findings, risk, iocs, mitre):
    """Build a consolidated incident from analysis results."""

    events = device_group["events"]

    return {
        "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": device_group["source_ip"],
        "source_mac": device_group["source_mac"],
        "event_ids": [
            event["event_id"] for event in events
        ],
        "honeypots": device_group["honeypots"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "findings": findings,
        "iocs": iocs,
        "mitre_techniques": mitre,
        "status": "PENDING_REVIEW",
        "recommended_action": (
            "REVIEW_FOR_QUARANTINE"
            if risk["risk_score"] >= 60
            else "MONITOR"
        ),
        "administrator_decision": None
    }
