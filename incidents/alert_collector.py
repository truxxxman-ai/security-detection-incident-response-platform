import sys
import os

# =========================================================
# Project path
# =========================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.insert(0, PROJECT_ROOT)


# =========================================================
# Parsers
# =========================================================

from parsers.suricata_parser import read_suricata_alerts
from parsers.zeek_parser import read_zeek_connections
from parsers.auth_parser import read_ssh_failed_logins
from parsers.nginx_parser import read_nginx_logs


# =========================================================
# Detectors
# =========================================================

from detectors.port_scan_detector import detect_port_scans
from detectors.ssh_bruteforce_detector import detect_ssh_bruteforce
from detectors.web_enumeration_detector import detect_web_enumeration
from detectors.sql_injection_detector import detect_sql_injection


# =========================================================
# Log locations
# =========================================================

SURICATA_LOG = "/var/log/suricata/eve.json"
ZEEK_LOG = "/opt/zeek/logs/current/conn.log"
NGINX_LOG = "/var/log/nginx/access.log"

UBUNTU_IP = "192.168.42.129"


# =========================================================
# Collect all alerts
# =========================================================

def collect_alerts():

    unified_alerts = []

    # =====================================================
    # 1. Suricata Port Scan
    # =====================================================

    suricata_alerts = read_suricata_alerts(
        SURICATA_LOG
    )

    for alert in suricata_alerts:

        if (
            alert["attack_type"]
            != "CUSTOM Possible TCP Port Scan"
        ):
            continue

        timestamp = alert["timestamp"]

        unified_alerts.append(
            {
                "source": "SURICATA",
                "attack_type": "PORT_SCAN",
                "source_ip": alert["source_ip"],
                "destination_ip": alert["destination_ip"],
                "severity": "HIGH",

                "first_seen": timestamp,
                "last_seen": timestamp,
                "duration": 0.0
            }
        )

    # =====================================================
    # 2. Zeek + Python Port Scan
    # =====================================================

    connections = read_zeek_connections(
        ZEEK_LOG
    )

    port_scan_detections = detect_port_scans(
        connections
    )

    for detection in port_scan_detections:

        unified_alerts.append(
            {
                "source": "PYTHON_ZEEK",
                "attack_type":
                    detection["attack_type"],

                "source_ip":
                    detection["source_ip"],

                "destination_ip":
                    detection["destination_ip"],

                "severity":
                    detection["severity"],

                "first_seen":
                    detection["first_seen"],

                "last_seen":
                    detection["last_seen"],

                "duration":
                    detection["duration"]
            }
        )

    # =====================================================
    # 3. SSH Bruteforce
    # =====================================================

    ssh_events = read_ssh_failed_logins()

    ssh_detections = detect_ssh_bruteforce(
        ssh_events
    )

    for detection in ssh_detections:

        unified_alerts.append(
            {
                "source": "PYTHON_AUTH",

                "attack_type":
                    detection["attack_type"],

                "source_ip":
                    detection["source_ip"],

                "destination_ip":
                    UBUNTU_IP,

                "severity":
                    detection["severity"],

                "first_seen":
                    detection["first_seen"],

                "last_seen":
                    detection["last_seen"],

                "duration":
                    detection["duration"]
            }
        )

    # =====================================================
    # 4. Web Enumeration
    # =====================================================

    web_events = read_nginx_logs(
        NGINX_LOG
    )

    web_detections = detect_web_enumeration(
        web_events
    )

    for detection in web_detections:

        unified_alerts.append(
            {
                "source": "PYTHON_NGINX",

                "attack_type":
                    detection["attack_type"],

                "source_ip":
                    detection["source_ip"],

                "destination_ip":
                    UBUNTU_IP,

                "severity":
                    detection["severity"],

                "first_seen":
                    detection["first_seen"],

                "last_seen":
                    detection["last_seen"],

                "duration":
                    detection["duration"]
            }
        )

    # =====================================================
    # 5. SQL Injection
    # =====================================================

    sql_detections = detect_sql_injection(
        web_events
    )

    for detection in sql_detections:

        unified_alerts.append(
            {
                "source": "PYTHON_NGINX",

                "attack_type":
                    detection["attack_type"],

                "source_ip":
                    detection["source_ip"],

                "destination_ip":
                    UBUNTU_IP,

                "severity":
                    detection["severity"],

                "first_seen":
                    detection["first_seen"],

                "last_seen":
                    detection["last_seen"],

                "duration":
                    detection["duration"]
            }
        )

    return unified_alerts


# =========================================================
# Test
# =========================================================

if __name__ == "__main__":

    alerts = collect_alerts()

    print("=" * 75)
    print("UNIFIED SECURITY ALERTS")
    print("=" * 75)

    print(
        f"Total Alerts: {len(alerts)}"
    )

    for alert in alerts[-30:]:

        print()

        print(
            f"Source:       "
            f"{alert['source']}"
        )

        print(
            f"Attack:       "
            f"{alert['attack_type']}"
        )

        print(
            f"Source IP:    "
            f"{alert['source_ip']}"
        )

        print(
            f"Target IP:    "
            f"{alert['destination_ip']}"
        )

        print(
            f"Severity:     "
            f"{alert['severity']}"
        )

        print(
            f"First Seen:   "
            f"{alert['first_seen']}"
        )

        print(
            f"Last Seen:    "
            f"{alert['last_seen']}"
        )

        print(
            f"Duration:     "
            f"{alert['duration']} seconds"
        )

        print("-" * 75)
