import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from incidents.alert_collector import collect_alerts
from incidents.alert_deduplicator import deduplicate_alerts


def calculate_risk_score(incident):
    score = 0

    # 1. 攻击类型基础分
    attack_scores = {
        "PORT_SCAN": 30,
        "SSH_BRUTEFORCE": 45,
        "WEB_ENUMERATION": 35,
        "SQL_INJECTION": 60
    }

    score += attack_scores.get(
        incident["attack_type"],
        20
    )

    # 2. 严重程度
    severity_scores = {
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 20,
        "CRITICAL": 30
    }

    score += severity_scores.get(
        incident["severity"],
        0
    )

    # 3. 多个检测来源同时发现
    if incident["confidence"] == "HIGH":
        score += 20
    elif incident["confidence"] == "MEDIUM":
        score += 10

    # 4. 原始告警数量
    alert_count = incident["alert_count"]

    if alert_count >= 100:
        score += 20
    elif alert_count >= 50:
        score += 15
    elif alert_count >= 20:
        score += 10
    elif alert_count >= 5:
        score += 5

    # 最大不超过100
    score = min(score, 100)

    return score


def get_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"


if __name__ == "__main__":

    alerts = collect_alerts()

    incidents = deduplicate_alerts(alerts)

    print("=" * 65)
    print("SECURITY INCIDENT RISK ASSESSMENT")
    print("=" * 65)

    for incident in incidents:

        score = calculate_risk_score(
            incident
        )

        level = get_risk_level(
            score
        )

        print()

        print(
            f"Attack:       "
            f"{incident['attack_type']}"
        )

        print(
            f"Source IP:    "
            f"{incident['source_ip']}"
        )

        print(
            f"Target IP:    "
            f"{incident['destination_ip']}"
        )

        print(
            f"Evidence:     "
            f"{', '.join(incident['sources'])}"
        )

        print(
            f"Raw Alerts:   "
            f"{incident['alert_count']}"
        )

        print(
            f"Confidence:   "
            f"{incident['confidence']}"
        )

        print(
            f"Risk Score:   "
            f"{score}/100"
        )

        print(
            f"Risk Level:   "
            f"{level}"
        )

        print("-" * 65)
