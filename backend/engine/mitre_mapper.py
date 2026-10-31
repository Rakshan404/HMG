
MITRE_MAPPINGS = {
    "REPEATED_LOGIN_ATTEMPTS": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "explanation": "Repeated authentication-related interactions were observed."
    },
    "SMB_SHARE_ENUMERATION": {
        "technique_id": "T1135",
        "technique_name": "Network Share Discovery",
        "tactic": "Discovery",
        "explanation": "SMB share enumeration behaviour was observed."
    }
}


def map_to_mitre(findings):
    """
    Map supported findings to MITRE ATT&CK techniques.

    A mapping describes observed behaviour.
    It does not prove that an attacker successfully performed the technique.
    """

    mappings = []
    seen = set()

    for finding in findings:

        rule_id = finding["rule_id"]

        mapping = MITRE_MAPPINGS.get(rule_id)

        if mapping is None:
            continue

        technique_id = mapping["technique_id"]

        if technique_id in seen:
            continue

        seen.add(technique_id)

        mappings.append({
            **mapping,
            "source_rule": rule_id,
            "event_ids": finding["event_ids"],
            "status": "observed_behaviour"
        })

    return mappings
