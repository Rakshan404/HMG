
SEVERITY_LEVELS = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100)
}


def calculate_risk(findings):
    """
    Calculate an explainable risk score.

    Each detection rule contributes points once.
    Maximum score is 100.
    """

    seen_rules = set()
    score = 0
    reasons = []

    for finding in findings:

        rule_id = finding["rule_id"]

        # Prevent duplicate evidence from adding points repeatedly.
        if rule_id in seen_rules:
            continue

        seen_rules.add(rule_id)

        points = finding["points"]

        score += points

        reasons.append({
            "rule_id": rule_id,
            "description": finding["description"],
            "points": points
        })

    score = min(score, 100)

    if score <= 29:
        level = "LOW"
    elif score <= 59:
        level = "MEDIUM"
    elif score <= 79:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons
    }
