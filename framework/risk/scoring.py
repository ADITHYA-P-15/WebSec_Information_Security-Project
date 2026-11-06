
def calculate_risk(
    impact,
    exploitability,
    confidence,
):
    """
    Calculate a preliminary risk score from 0 to 100.

    Each input is rated from 1 to 5:
      1 = very low
      2 = low
      3 = moderate
      4 = high
      5 = very high

    This is a project-specific score, not CVSS.
    """

    factors = {
        "impact": impact,
        "exploitability": exploitability,
        "confidence": confidence,
    }

    for name, value in factors.items():
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError(f"{name} must be a number from 1 to 5.")

        if not 1 <= value <= 5:
            raise ValueError(f"{name} must be between 1 and 5.")

    # Normalize each factor to 0–100, then apply weights.
    impact_score = ((impact - 1) / 4) * 100
    exploitability_score = ((exploitability - 1) / 4) * 100
    confidence_score = ((confidence - 1) / 4) * 100

    score = (
        impact_score * 0.40
        + exploitability_score * 0.35
        + confidence_score * 0.25
    )

    score = round(score, 1)

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    elif score >= 20:
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        "score": score,
        "severity": severity,
        "factors": factors,
        "weights": {
            "impact": 0.40,
            "exploitability": 0.35,
            "confidence": 0.25,
        },
        "method": "project_preliminary_risk_v1",
    }
