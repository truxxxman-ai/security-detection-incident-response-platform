import sys
import os
import json
from datetime import datetime

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from incidents.alert_collector import collect_alerts
from incidents.alert_deduplicator import deduplicate_alerts
from incidents.risk_scorer import (
    calculate_risk_score,
    get_risk_level
)


OUTPUT_FILE = "data/incidents.json"


def create_incidents():

    alerts = collect_alerts()

    deduplicated_alerts = deduplicate_alerts(
        alerts
    )

    incidents = []

    # 按真实开始时间排序
    deduplicated_alerts.sort(
        key=lambda item: item.get(
            "first_seen",
            ""
        )
    )

    for index, item in enumerate(
        deduplicated_alerts,
        start=1
    ):

        risk_score = calculate_risk_score(
            item
        )

        risk_level = get_risk_level(
            risk_score
        )

        incident = {

            "incident_id":
                f"INC-{index:04d}",

            "attack_type":
                item["attack_type"],

            "source_ip":
                item["source_ip"],

            "destination_ip":
                item["destination_ip"],

            "severity":
                item["severity"],

            "evidence_sources":
                item["sources"],

            "raw_alert_count":
                item["alert_count"],

            "confidence":
                item["confidence"],

            "first_seen":
                item["first_seen"],

            "last_seen":
                item["last_seen"],

            "duration":
                item["duration"],

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "status":
                "OPEN",

            "created_at":
                datetime.now().isoformat()
        }

        incidents.append(
            incident
        )

    return incidents


def save_incidents(incidents):

    os.makedirs(
        os.path.dirname(
            OUTPUT_FILE
        ),
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w"
    ) as file:

        json.dump(
            incidents,
            file,
            indent=4
        )


if __name__ == "__main__":

    incidents = create_incidents()

    save_incidents(
        incidents
    )

    print("=" * 75)
    print("SECURITY INCIDENT MANAGER")
    print("=" * 75)

    if not incidents:

        print(
            "No incidents found."
        )

    for incident in incidents:

        print()

        print(
            f"Incident ID:   "
            f"{incident['incident_id']}"
        )

        print(
            f"Attack:        "
            f"{incident['attack_type']}"
        )

        print(
            f"Attacker:      "
            f"{incident['source_ip']}"
        )

        print(
            f"Target:        "
            f"{incident['destination_ip']}"
        )

        print(
            f"Evidence:      "
            f"{', '.join(incident['evidence_sources'])}"
        )

        print(
            f"Raw Alerts:    "
            f"{incident['raw_alert_count']}"
        )

        print(
            f"Confidence:    "
            f"{incident['confidence']}"
        )

        print(
            f"First Seen:    "
            f"{incident['first_seen']}"
        )

        print(
            f"Last Seen:     "
            f"{incident['last_seen']}"
        )

        print(
            f"Duration:      "
            f"{incident['duration']:.2f} seconds"
        )

        print(
            f"Risk Score:    "
            f"{incident['risk_score']}/100"
        )

        print(
            f"Risk Level:    "
            f"{incident['risk_level']}"
        )

        print(
            f"Status:        "
            f"{incident['status']}"
        )

        print("-" * 75)

    print()

    print(
        f"Incidents saved to: "
        f"{OUTPUT_FILE}"
    )
