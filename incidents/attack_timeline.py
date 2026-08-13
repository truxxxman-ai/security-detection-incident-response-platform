import sys
import os
from datetime import datetime

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from parsers.zeek_parser import read_zeek_connections
from incidents.incident_manager import create_incidents


ZEEK_LOG = "/opt/zeek/logs/current/conn.log"


def format_timestamp(timestamp):
    try:
        return datetime.fromtimestamp(
            float(timestamp)
        ).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return str(timestamp)


def build_timeline(incident, connections):
    relevant_events = []

    for conn in connections:

        if (
            conn["source_ip"] == incident["source_ip"]
            and
            conn["destination_ip"] == incident["destination_ip"]
        ):

            try:
                timestamp = float(
                    conn["timestamp"]
                )
            except (ValueError, TypeError):
                continue

            relevant_events.append(
                {
                    "timestamp": timestamp,
                    "source_port":
                        conn["source_port"],
                    "destination_port":
                        conn["destination_port"],
                    "protocol":
                        conn["protocol"],
                    "service":
                        conn["service"],
                    "state":
                        conn["connection_state"]
                }
            )

    relevant_events.sort(
        key=lambda x: x["timestamp"]
    )

    return relevant_events


if __name__ == "__main__":

    incidents = create_incidents()

    connections = read_zeek_connections(
        ZEEK_LOG
    )

    print("=" * 70)
    print("ATTACK TIMELINE")
    print("=" * 70)

    for incident in incidents:

        timeline = build_timeline(
            incident,
            connections
        )

        print()
        print(
            f"Incident:      "
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

        if not timeline:
            print("No related Zeek events found.")
            continue

        start_time = timeline[0]["timestamp"]
        end_time = timeline[-1]["timestamp"]

        duration = end_time - start_time

        unique_ports = sorted(
            {
                event["destination_port"]
                for event in timeline
            }
        )

        print(
            f"Start Time:    "
            f"{format_timestamp(start_time)}"
        )

        print(
            f"End Time:      "
            f"{format_timestamp(end_time)}"
        )

        print(
            f"Duration:      "
            f"{duration:.2f} seconds"
        )

        print(
            f"Connections:   "
            f"{len(timeline)}"
        )

        print(
            f"Unique Ports:  "
            f"{len(unique_ports)}"
        )

        print()
        print("First 10 Events:")
        print("-" * 70)

        for event in timeline[:10]:

            print(
                f"{format_timestamp(event['timestamp'])} | "
                f"{incident['source_ip']} "
                f"-> "
                f"{incident['destination_ip']}:"
                f"{event['destination_port']} | "
                f"{event['protocol']} | "
                f"{event['state']}"
            )

        print("-" * 70)
