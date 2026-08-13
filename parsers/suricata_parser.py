import json

LOG_FILE = "/var/log/suricata/eve.json"


def read_suricata_alerts(log_file):
    alerts = []

    with open(log_file, "r") as file:
        for line in file:
            try:
                event = json.loads(line)

                if event.get("event_type") == "alert":
                    alert = {
                        "timestamp": event.get("timestamp"),
                        "source_ip": event.get("src_ip"),
                        "source_port": event.get("src_port"),
                        "destination_ip": event.get("dest_ip"),
                        "destination_port": event.get("dest_port"),
                        "protocol": event.get("proto"),
                        "attack_type": event.get("alert", {}).get("signature"),
                        "severity": event.get("alert", {}).get("severity")
                    }

                    alerts.append(alert)

            except json.JSONDecodeError:
                continue

    return alerts


if __name__ == "__main__":
    alerts = read_suricata_alerts(LOG_FILE)

    print(f"Total alerts found: {len(alerts)}")
    print("-" * 60)

    for alert in alerts[-10:]:
        print(f"Time:        {alert['timestamp']}")
        print(f"Source:      {alert['source_ip']}:{alert['source_port']}")
        print(f"Destination: {alert['destination_ip']}:{alert['destination_port']}")
        print(f"Protocol:    {alert['protocol']}")
        print(f"Attack:      {alert['attack_type']}")
        print(f"Severity:    {alert['severity']}")
        print("-" * 60)
