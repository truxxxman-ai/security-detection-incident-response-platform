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

from parsers.auth_parser import read_ssh_failed_logins


TIME_WINDOW = 60
FAIL_THRESHOLD = 5


def parse_time(timestamp):
    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def detect_ssh_bruteforce(events):

    grouped = defaultdict(list)
    detections = []

    # =====================================================
    # Group failed logins by source IP
    # =====================================================

    for event in events:

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
                "username": event["username"]
            }
        )

    # =====================================================
    # Sliding-window detection
    # =====================================================

    for source_ip, attempts in grouped.items():

        attempts.sort(
            key=lambda x: x["time"]
        )

        start = 0

        for end in range(
            len(attempts)
        ):

            while (
                attempts[end]["time"]
                -
                attempts[start]["time"]
            ).total_seconds() > TIME_WINDOW:

                start += 1

            current = attempts[
                start:end + 1
            ]

            if len(current) >= FAIL_THRESHOLD:

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

                usernames = sorted(
                    {
                        item["username"]
                        for item in current
                    }
                )

                detection = {

                    "attack_type":
                        "SSH_BRUTEFORCE",

                    "source_ip":
                        source_ip,

                    "failed_attempts":
                        len(current),

                    "usernames":
                        usernames,

                    "time_window":
                        TIME_WINDOW,

                    "severity":
                        "HIGH",

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

    events = read_ssh_failed_logins()

    detections = detect_ssh_bruteforce(
        events
    )

    print("=" * 70)
    print("SSH BRUTEFORCE DETECTOR")
    print("=" * 70)

    if not detections:
        print(
            "No SSH bruteforce detected."
        )

    for detection in detections:

        print()
        print(
            "[!] SSH BRUTEFORCE DETECTED"
        )

        print(
            f"Source IP:       "
            f"{detection['source_ip']}"
        )

        print(
            f"Failed Attempts: "
            f"{detection['failed_attempts']}"
        )

        print(
            f"Usernames:       "
            f"{', '.join(detection['usernames'])}"
        )

        print(
            f"First Seen:      "
            f"{detection['first_seen']}"
        )

        print(
            f"Last Seen:       "
            f"{detection['last_seen']}"
        )

        print(
            f"Duration:        "
            f"{detection['duration']:.2f} seconds"
        )

        print(
            f"Severity:        "
            f"{detection['severity']}"
        )

        print("-" * 70)
