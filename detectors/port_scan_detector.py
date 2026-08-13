import sys
import os
from collections import defaultdict
from datetime import datetime

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from parsers.zeek_parser import read_zeek_connections


ZEEK_LOG = "/opt/zeek/logs/current/conn.log"

TIME_WINDOW = 10
PORT_THRESHOLD = 20


def format_time(timestamp):
    return datetime.fromtimestamp(
        timestamp
    ).isoformat()


def detect_port_scans(connections):

    grouped = defaultdict(list)

    detections = []

    # =====================================================
    # Group TCP connections by attacker -> target
    # =====================================================

    for conn in connections:

        if conn["protocol"] != "tcp":
            continue

        try:
            timestamp = float(
                conn["timestamp"]
            )

            destination_port = int(
                conn["destination_port"]
            )

        except (ValueError, TypeError):
            continue

        key = (
            conn["source_ip"],
            conn["destination_ip"]
        )

        grouped[key].append(
            {
                "timestamp": timestamp,
                "port": destination_port
            }
        )

    # =====================================================
    # Sliding-window detection
    # =====================================================

    for (
        source_ip,
        destination_ip
    ), events in grouped.items():

        events.sort(
            key=lambda x: x["timestamp"]
        )

        start = 0

        for end in range(len(events)):

            while (
                events[end]["timestamp"]
                -
                events[start]["timestamp"]
                >
                TIME_WINDOW
            ):
                start += 1

            current_events = events[
                start:end + 1
            ]

            unique_ports = {
                event["port"]
                for event in current_events
            }

            if (
                len(unique_ports)
                >=
                PORT_THRESHOLD
            ):

                first_seen = current_events[
                    0
                ]["timestamp"]

                last_seen = current_events[
                    -1
                ]["timestamp"]

                detection = {

                    "attack_type":
                        "PORT_SCAN",

                    "source_ip":
                        source_ip,

                    "destination_ip":
                        destination_ip,

                    "unique_ports":
                        len(unique_ports),

                    "time_window":
                        TIME_WINDOW,

                    "severity":
                        "HIGH",

                    "first_seen":
                        format_time(
                            first_seen
                        ),

                    "last_seen":
                        format_time(
                            last_seen
                        ),

                    "duration":
                        last_seen
                        -
                        first_seen
                }

                detections.append(
                    detection
                )

                # 一个 src -> dst 暂时只生成一次扫描事件
                break

    return detections


if __name__ == "__main__":

    connections = read_zeek_connections(
        ZEEK_LOG
    )

    detections = detect_port_scans(
        connections
    )

    print("=" * 70)
    print("PORT SCAN DETECTOR")
    print("=" * 70)

    if not detections:
        print(
            "No port scan detected."
        )

    for detection in detections:

        print()
        print(
            "[!] PORT SCAN DETECTED"
        )

        print(
            f"Source IP:     "
            f"{detection['source_ip']}"
        )

        print(
            f"Target IP:     "
            f"{detection['destination_ip']}"
        )

        print(
            f"Unique Ports:  "
            f"{detection['unique_ports']}"
        )

        print(
            f"First Seen:    "
            f"{detection['first_seen']}"
        )

        print(
            f"Last Seen:     "
            f"{detection['last_seen']}"
        )

        print(
            f"Duration:      "
            f"{detection['duration']:.3f} seconds"
        )

        print(
            f"Severity:      "
            f"{detection['severity']}"
        )

        print("-" * 70)

