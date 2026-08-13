import sys
import os
import json
from collections import defaultdict
from datetime import datetime

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from incidents.incident_manager import create_incidents


OUTPUT_FILE = "data/attack_chains.json"

# 相邻两个事件最多允许间隔 30 分钟
CHAIN_WINDOW_SECONDS = 30 * 60


ATTACK_STAGES = {
    "PORT_SCAN": "RECONNAISSANCE",
    "SSH_BRUTEFORCE": "CREDENTIAL_ATTACK",
    "WEB_ENUMERATION": "DISCOVERY",
    "SQL_INJECTION": "EXPLOITATION"
}


def parse_timestamp(timestamp):

    if not timestamp:
        return None

    try:

        timestamp = timestamp.replace(
            "Z",
            "+00:00"
        )

        dt = datetime.fromisoformat(
            timestamp
        )

        return dt.timestamp()

    except (ValueError, TypeError):

        return None


def get_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"


def build_chain(
    incidents,
    chain_number,
    source_ip,
    destination_ip
):

    if len(incidents) < 2:
        return None

    stages = []

    first_seen_epoch = None
    last_seen_epoch = None

    highest_risk = 0

    for incident in incidents:

        start_epoch = parse_timestamp(
            incident["first_seen"]
        )

        end_epoch = parse_timestamp(
            incident["last_seen"]
        )

        if start_epoch is not None:

            if (
                first_seen_epoch is None
                or
                start_epoch < first_seen_epoch
            ):

                first_seen_epoch = start_epoch

        if end_epoch is not None:

            if (
                last_seen_epoch is None
                or
                end_epoch > last_seen_epoch
            ):

                last_seen_epoch = end_epoch

        highest_risk = max(
            highest_risk,
            incident["risk_score"]
        )

        stage = {

            "incident_id":
                incident["incident_id"],

            "attack_type":
                incident["attack_type"],

            "stage":
                ATTACK_STAGES.get(
                    incident["attack_type"],
                    "UNKNOWN"
                ),

            "first_seen":
                incident["first_seen"],

            "last_seen":
                incident["last_seen"],

            "duration":
                incident["duration"],

            "risk_score":
                incident["risk_score"],

            "risk_level":
                incident["risk_level"],

            "confidence":
                incident["confidence"],

            "evidence_sources":
                incident["evidence_sources"]
        }

        stages.append(
            stage
        )

    # 多阶段攻击额外提高风险
    chain_bonus = (
        len(stages) - 1
    ) * 5

    chain_risk_score = min(
        highest_risk + chain_bonus,
        100
    )

    chain_risk_level = get_risk_level(
        chain_risk_score
    )

    if (
        first_seen_epoch is not None
        and
        last_seen_epoch is not None
    ):

        chain_duration = max(
            0.0,
            last_seen_epoch
            -
            first_seen_epoch
        )

    else:

        chain_duration = 0.0

    return {

        "chain_id":
            f"CHAIN-{chain_number:04d}",

        "source_ip":
            source_ip,

        "destination_ip":
            destination_ip,

        "incident_count":
            len(stages),

        "first_seen":
            incidents[0]["first_seen"],

        "last_seen":
            incidents[-1]["last_seen"],

        "duration":
            chain_duration,

        "risk_score":
            chain_risk_score,

        "risk_level":
            chain_risk_level,

        "status":
            "OPEN",

        "stages":
            stages,

        "created_at":
            datetime.now().isoformat()
    }


def correlate_attack_chains(incidents):

    grouped = defaultdict(list)

    # =====================================================
    # Group by attacker + target
    # =====================================================

    for incident in incidents:

        key = (
            incident["source_ip"],
            incident["destination_ip"]
        )

        grouped[key].append(
            incident
        )

    attack_chains = []

    chain_number = 1

    # =====================================================
    # Analyse each attacker -> target pair
    # =====================================================

    for (
        source_ip,
        destination_ip
    ), related_incidents in grouped.items():

        # Add parsed timestamp for sorting
        valid_incidents = []

        for incident in related_incidents:

            timestamp = parse_timestamp(
                incident["first_seen"]
            )

            if timestamp is None:
                continue

            incident_copy = incident.copy()

            incident_copy[
                "_timestamp"
            ] = timestamp

            valid_incidents.append(
                incident_copy
            )

        valid_incidents.sort(
            key=lambda item:
                item["_timestamp"]
        )

        if len(valid_incidents) < 2:
            continue

        # =================================================
        # Split into separate chains by time gap
        # =================================================

        current_chain = [
            valid_incidents[0]
        ]

        for incident in valid_incidents[1:]:

            previous = current_chain[-1]

            previous_time = parse_timestamp(
                previous["last_seen"]
            )

            current_time = parse_timestamp(
                incident["first_seen"]
            )

            if (
                previous_time is None
                or
                current_time is None
            ):
                continue

            gap = (
                current_time
                -
                previous_time
            )

            # Same attack campaign
            if (
                gap
                <=
                CHAIN_WINDOW_SECONDS
            ):

                current_chain.append(
                    incident
                )

            else:

                # Finish previous chain
                if len(current_chain) >= 2:

                    chain = build_chain(
                        current_chain,
                        chain_number,
                        source_ip,
                        destination_ip
                    )

                    if chain:

                        attack_chains.append(
                            chain
                        )

                        chain_number += 1

                # Start new chain
                current_chain = [
                    incident
                ]

        # =================================================
        # Save final chain
        # =================================================

        if len(current_chain) >= 2:

            chain = build_chain(
                current_chain,
                chain_number,
                source_ip,
                destination_ip
            )

            if chain:

                attack_chains.append(
                    chain
                )

                chain_number += 1

    return attack_chains


def save_attack_chains(chains):

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
            chains,
            file,
            indent=4
        )


if __name__ == "__main__":

    incidents = create_incidents()

    chains = correlate_attack_chains(
        incidents
    )

    save_attack_chains(
        chains
    )

    print("=" * 80)
    print("TIME-BASED ATTACK CHAIN CORRELATION")
    print("=" * 80)

    if not chains:

        print(
            "No multi-stage attack chain detected."
        )

    for chain in chains:

        print()

        print(
            f"Chain ID:       "
            f"{chain['chain_id']}"
        )

        print(
            f"Attacker:       "
            f"{chain['source_ip']}"
        )

        print(
            f"Target:         "
            f"{chain['destination_ip']}"
        )

        print(
            f"Incidents:      "
            f"{chain['incident_count']}"
        )

        print(
            f"First Seen:     "
            f"{chain['first_seen']}"
        )

        print(
            f"Last Seen:      "
            f"{chain['last_seen']}"
        )

        print(
            f"Duration:       "
            f"{chain['duration']:.2f} seconds"
        )

        print(
            f"Risk Score:     "
            f"{chain['risk_score']}/100"
        )

        print(
            f"Risk Level:     "
            f"{chain['risk_level']}"
        )

        print()
        print("ATTACK TIMELINE")
        print("-" * 80)

        for number, stage in enumerate(
            chain["stages"],
            start=1
        ):

            print(
                f"{number}. "
                f"{stage['first_seen']}"
            )

            print(
                f"   [{stage['stage']}] "
                f"{stage['attack_type']}"
            )

            print(
                f"   Incident: "
                f"{stage['incident_id']}"
            )

            print(
                f"   Risk: "
                f"{stage['risk_score']}/100 "
                f"({stage['risk_level']})"
            )

            print(
                f"   Evidence: "
                f"{', '.join(stage['evidence_sources'])}"
            )

            if number < len(
                chain["stages"]
            ):

                print()
                print("             ↓")
                print()

        print("-" * 80)

    print()

    print(
        f"Attack chains saved to: "
        f"{OUTPUT_FILE}"
    )
