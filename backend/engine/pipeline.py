
from backend.engine.normalizer import normalize_event
from backend.engine.correlation import correlate_events
from backend.engine.analyzer import analyze_events
from backend.engine.risk_engine import calculate_risk
from backend.engine.ioc_extractor import extract_iocs
from backend.engine.mitre_mapper import map_to_mitre
from backend.engine.incident_builder import build_incident


def process_events(raw_events, audit_logger=None):
    """
    Run incoming events through the complete Member 3 pipeline.

    Returns validated events, findings, and incidents.
    """

    # Stage 1: Validate all incoming events.
    valid_events = [
        normalize_event(event)
        for event in raw_events
    ]

    # Stage 2: Group events by device and time.
    groups = correlate_events(valid_events)

    incidents = []

    # Stage 3: Analyse each device group.
    for group in groups:

        findings = analyze_events(group["events"])
        if not findings:
            continue

        # Stage 4: Calculate risk.
        risk = calculate_risk(findings)

        # Stage 5: Extract IOCs.
        iocs = extract_iocs(group["events"])

        # Stage 6: Map supported findings to MITRE.
        mitre = map_to_mitre(findings)

        # Stage 7: Build incident.
        incident = build_incident(
            group,
            findings,
            risk,
            iocs,
            mitre
        )

        incidents.append(incident)

        # Stage 8: Record incident in audit log.
        if audit_logger is not None:
            audit_logger.append(
                "INCIDENT_CREATED",
                incident
            )

    return {
        "events_processed": len(valid_events),
        "device_groups": len(groups),
        "incidents": incidents
    }
