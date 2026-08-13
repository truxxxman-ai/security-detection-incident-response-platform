import sys
import os
from datetime import datetime
from urllib.parse import unquote

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from parsers.nginx_parser import read_nginx_logs


NGINX_LOG = "/var/log/nginx/access.log"


SQLI_PATTERNS = [
    "union select",
    "or 1=1",
    "or '1'='1",
    'or "1"="1',
    "information_schema",
    "sleep(",
    "benchmark(",
    "'--",
    "\"--"
]


def parse_time(timestamp):

    try:
        return datetime.strptime(
            timestamp,
            "%d/%b/%Y:%H:%M:%S %z"
        )

    except ValueError:
        return None


def detect_sql_injection(events):

    detections = []

    for event in events:

        decoded_path = unquote(
            event["path"]
        ).lower()

        matched_pattern = None

        for pattern in SQLI_PATTERNS:

            if pattern in decoded_path:

                matched_pattern = pattern
                break

        if matched_pattern is None:
            continue

        event_time = parse_time(
            event["timestamp"]
        )

        if event_time is None:
            continue

        detection = {

            "attack_type":
                "SQL_INJECTION",

            "source_ip":
                event["source_ip"],

            "path":
                event["path"],

            "decoded_path":
                decoded_path,

            "matched_pattern":
                matched_pattern,

            "severity":
                "CRITICAL",

            "first_seen":
                event_time.isoformat(),

            "last_seen":
                event_time.isoformat(),

            "duration":
                0.0
        }

        detections.append(
            detection
        )

    return detections


if __name__ == "__main__":

    events = read_nginx_logs(
        NGINX_LOG
    )

    detections = detect_sql_injection(
        events
    )

    print("=" * 70)
    print("SQL INJECTION DETECTOR")
    print("=" * 70)

    if not detections:

        print(
            "No SQL injection detected."
        )

    for detection in detections:

        print()

        print(
            "[!] SQL INJECTION DETECTED"
        )

        print(
            f"Source IP:      "
            f"{detection['source_ip']}"
        )

        print(
            f"Request:        "
            f"{detection['path']}"
        )

        print(
            f"Pattern:        "
            f"{detection['matched_pattern']}"
        )

        print(
            f"First Seen:     "
            f"{detection['first_seen']}"
        )

        print(
            f"Last Seen:      "
            f"{detection['last_seen']}"
        )

        print(
            f"Duration:       "
            f"{detection['duration']:.2f} seconds"
        )

        print(
            f"Severity:       "
            f"{detection['severity']}"
        )

        print("-" * 70)
