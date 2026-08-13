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

from parsers.nginx_parser import read_nginx_logs


NGINX_LOG = "/var/log/nginx/access.log"

TIME_WINDOW = 60
NOT_FOUND_THRESHOLD = 8


def parse_time(timestamp):
    try:
        return datetime.strptime(
            timestamp,
            "%d/%b/%Y:%H:%M:%S %z"
        )
    except ValueError:
        return None


def detect_web_enumeration(events):

    grouped = defaultdict(list)
    detections = []

    # =====================================================
    # Only analyse HTTP 404 requests
    # =====================================================

    for event in events:

        if event["status"] != 404:
            continue

        event_time = parse_time(
            event["timestamp"]
        )

        if event_time is None:
            continue

        grouped[
            event["source_ip"]
        ].append(
            {
                "time": event_time,
                "path": event["path"]
            }
        )

    # =====================================================
    # Sliding-window detection
    # =====================================================

    for source_ip, requests in grouped.items():

        requests.sort(
            key=lambda x: x["time"]
        )

        start = 0

        for end in range(
            len(requests)
        ):

            while (
                requests[end]["time"]
                -
                requests[start]["time"]
            ).total_seconds() > TIME_WINDOW:

                start += 1

            current = requests[
                start:end + 1
            ]

            unique_paths = {
                item["path"]
                for item in current
            }

            if (
                len(unique_paths)
                >=
                NOT_FOUND_THRESHOLD
            ):

                first_seen = current[
                    0
                ]["time"]

                last_seen = current[
                    -1
                ]["time"]

                duration = (
                    last_seen
                    -
                    first_seen
                ).total_seconds()

                detection = {

                    "attack_type":
                        "WEB_ENUMERATION",

                    "source_ip":
                        source_ip,

                    "request_count":
                        len(current),

                    "unique_paths":
                        len(unique_paths),

                    "paths":
                        sorted(unique_paths),

                    "time_window":
                        TIME_WINDOW,

                    "severity":
                        "MEDIUM",

                    "first_seen":
                        first_seen.isoformat(),

                    "last_seen":
                        last_seen.isoformat(),

                    "duration":
                        duration
                }

                detections.append(
                    detection
                )

                break

    return detections


if __name__ == "__main__":

    events = read_nginx_logs(
        NGINX_LOG
    )

    detections = detect_web_enumeration(
        events
    )

    print("=" * 70)
    print("WEB ENUMERATION DETECTOR")
    print("=" * 70)

    if not detections:
        print(
            "No web enumeration detected."
        )

    for detection in detections:

        print()
        print(
            "[!] WEB ENUMERATION DETECTED"
        )

        print(
            f"Source IP:     "
            f"{detection['source_ip']}"
        )

        print(
            f"Requests:      "
            f"{detection['request_count']}"
        )

        print(
            f"Unique Paths:  "
            f"{detection['unique_paths']}"
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
            f"{detection['duration']:.2f} seconds"
        )

        print(
            f"Severity:      "
            f"{detection['severity']}"
        )

        print()

        print("Paths:")

        for path in detection["paths"]:
            print(
                f"  - {path}"
            )

        print("-" * 70)
