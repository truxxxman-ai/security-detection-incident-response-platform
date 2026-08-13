import sys
import os
import subprocess
import ipaddress

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from incidents.incident_manager import create_incidents
from response.playbook import get_response_playbook


LAB_NETWORK = ipaddress.ip_network("192.168.42.0/24")

PROTECTED_IPS = {
    "192.168.42.129"
}


def validate_ip(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return False

    if ip not in LAB_NETWORK:
        print(
            f"[!] Refusing to block {ip_address}: "
            "outside the lab network."
        )
        return False

    if ip_address in PROTECTED_IPS:
        print(
            f"[!] Refusing to block protected host "
            f"{ip_address}."
        )
        return False

    return True


def already_blocked(ip_address):
    result = subprocess.run(
        [
            "iptables",
            "-C",
            "INPUT",
            "-s",
            ip_address,
            "-j",
            "DROP"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def block_ip(ip_address):

    if not validate_ip(ip_address):
        return False

    if already_blocked(ip_address):
        print(
            f"[*] {ip_address} is already blocked."
        )
        return True

    result = subprocess.run(
        [
            "iptables",
            "-I",
            "INPUT",
            "1",
            "-s",
            ip_address,
            "-j",
            "DROP"
        ]
    )

    if result.returncode == 0:
        print(
            f"[+] Successfully blocked "
            f"{ip_address}"
        )
        return True

    print(
        f"[-] Failed to block {ip_address}"
    )
    return False


if __name__ == "__main__":

    incidents = create_incidents()

    print("=" * 65)
    print("INCIDENT RESPONSE EXECUTION")
    print("=" * 65)

    for incident in incidents:

        playbook = get_response_playbook(
            incident
        )

        print()
        print(
            f"Incident:    "
            f"{incident['incident_id']}"
        )

        print(
            f"Attack:      "
            f"{incident['attack_type']}"
        )

        print(
            f"Attacker:    "
            f"{incident['source_ip']}"
        )

        print(
            f"Risk Level:  "
            f"{incident['risk_level']}"
        )

        print(
            f"Block Recommended: "
            f"{playbook['block_recommended']}"
        )

        if not playbook["block_recommended"]:
            print(
                "[*] No blocking action recommended."
            )
            continue

        answer = input(
            f"\nBlock {incident['source_ip']}? "
            "[y/N]: "
        )

        if answer.lower() == "y":

            block_ip(
                incident["source_ip"]
            )

        else:
            print(
                "[*] Blocking cancelled."
            )
