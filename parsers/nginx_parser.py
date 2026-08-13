import re
from datetime import datetime


LOG_FILE = "/var/log/nginx/access.log"


def read_nginx_logs(log_file):
    events = []

    pattern = re.compile(
        r'(?P<source_ip>\S+) '
        r'\S+ \S+ '
        r'\[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) '
        r'(?P<path>\S+) '
        r'[^"]+" '
        r'(?P<status>\d{3})'
    )

    with open(log_file, "r") as file:

        for line in file:

            match = pattern.search(line)

            if not match:
                continue

            event = {
                "source_ip": match.group("source_ip"),
                "timestamp": match.group("timestamp"),
                "method": match.group("method"),
                "path": match.group("path"),
                "status": int(match.group("status")),
                "event_type": "WEB_REQUEST"
            }

            events.append(event)

    return events


if __name__ == "__main__":

    events = read_nginx_logs(LOG_FILE)

    print("=" * 65)
    print("NGINX WEB EVENTS")
    print("=" * 65)

    print(f"Total requests: {len(events)}")

    for event in events[-20:]:

        print()
        print(f"Source IP: {event['source_ip']}")
        print(f"Method:    {event['method']}")
        print(f"Path:      {event['path']}")
        print(f"Status:    {event['status']}")
        print(f"Time:      {event['timestamp']}")
        print("-" * 65)
