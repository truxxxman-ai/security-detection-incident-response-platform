# =========================================================
# Risk Scoring Engine
# =========================================================


ATTACK_SCORES = {
    "PORT_SCAN": 20,
    "SSH_BRUTEFORCE": 40,
    "WEB_ENUMERATION": 25,
    "SQL_INJECTION": 55
}


SEVERITY_SCORES = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 15,
    "CRITICAL": 25
}


CONFIDENCE_SCORES = {
    "LOW": 0,
    "MEDIUM": 5,
    "HIGH": 15
}


def calculate_alert_volume_score(
    alert_count
):

    """
    Alert volume contributes to risk,
    but is deliberately capped so that
    noisy IDS alerts do not dominate
    the total risk score.
    """

    if alert_count >= 100:
        return 10

    elif alert_count >= 50:
        return 8

    elif alert_count >= 20:
        return 6

    elif alert_count >= 5:
        return 3

    return 0


def calculate_risk_score(
    incident
):

    attack_type = incident.get(
        "attack_type",
        ""
    )

    severity = incident.get(
        "severity",
        "LOW"
    )

    confidence = incident.get(
        "confidence",
        "LOW"
    )

    alert_count = incident.get(
        "alert_count",
        incident.get(
            "raw_alert_count",
            1
        )
    )


    # =====================================================
    # Attack-type score
    # =====================================================

    attack_score = ATTACK_SCORES.get(
        attack_type,
        10
    )


    # =====================================================
    # Severity score
    # =====================================================

    severity_score = SEVERITY_SCORES.get(
        severity,
        5
    )


    # =====================================================
    # Confidence score
    # =====================================================

    confidence_score = CONFIDENCE_SCORES.get(
        confidence,
        0
    )


    # =====================================================
    # Alert volume score
    # =====================================================

    volume_score = calculate_alert_volume_score(
        alert_count
    )


    # =====================================================
    # Final score
    # =====================================================

    total_score = (
        attack_score
        +
        severity_score
        +
        confidence_score
        +
        volume_score
    )


    return min(
        total_score,
        100
    )


def get_risk_level(
    score
):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


def score_incident(
    incident
):

    score = calculate_risk_score(
        incident
    )

    incident[
        "risk_score"
    ] = score

    incident[
        "risk_level"
    ] = get_risk_level(
        score
    )

    return incident


def score_incidents(
    incidents
):

    return [
        score_incident(
            incident
        )
        for incident in incidents
    ]
