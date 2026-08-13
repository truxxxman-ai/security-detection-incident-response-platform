import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from incidents.incident_manager import create_incidents


def get_response_playbook(incident):

    attack_type = incident["attack_type"]
    risk_level = incident["risk_level"]

    playbook = {
        "investigation_steps": [],
        "response_actions": [],
        "block_recommended": False
    }

    # =========================
    # PORT SCAN
    # =========================
    if attack_type == "PORT_SCAN":

        playbook["investigation_steps"] = [
            "Confirm the source IP and target IP.",
            "Review Zeek connection logs for scanned ports.",
            "Check Suricata alerts related to the source IP.",
            "Check whether the same source IP triggered other attacks.",
            "Verify whether any exposed service was successfully accessed."
        ]

        playbook["response_actions"] = [
            "Continue monitoring the source IP.",
            "Review unnecessary exposed ports on the target host.",
            "Restrict unnecessary network services.",
            "Consider temporary blocking if repeated scanning continues."
        ]

        if risk_level in ["HIGH", "CRITICAL"]:
            playbook["block_recommended"] = True

    # =========================
    # SSH BRUTEFORCE
    # =========================
    elif attack_type == "SSH_BRUTEFORCE":

        playbook["investigation_steps"] = [
            "Review SSH authentication logs.",
            "Count failed login attempts.",
            "Check whether any login eventually succeeded.",
            "Identify targeted usernames.",
            "Review activity after any successful login."
        ]

        playbook["response_actions"] = [
            "Block or rate-limit the attacking IP.",
            "Reset affected credentials if compromise is suspected.",
            "Disable password authentication where possible.",
            "Enable stronger SSH access controls."
        ]

        playbook["block_recommended"] = True

    # =========================
    # SQL INJECTION
    # =========================
    elif attack_type == "SQL_INJECTION":

        playbook["investigation_steps"] = [
            "Review the suspicious HTTP request.",
            "Identify the affected URL and parameter.",
            "Check related web server logs.",
            "Check whether the request returned a successful response.",
            "Review application and database activity."
        ]

        playbook["response_actions"] = [
            "Block the malicious source if confirmed.",
            "Validate and sanitize affected input parameters.",
            "Use parameterized SQL queries.",
            "Review application logs for possible data exposure."
        ]

        playbook["block_recommended"] = True

    else:

        playbook["investigation_steps"] = [
            "Review all available logs.",
            "Validate the alert.",
            "Determine affected assets.",
            "Identify related activity."
        ]

        playbook["response_actions"] = [
            "Continue monitoring.",
            "Escalate for manual investigation."
        ]

    return playbook


if __name__ == "__main__":

    incidents = create_incidents()

    print("=" * 70)
    print("INCIDENT RESPONSE PLAYBOOK")
    print("=" * 70)

    for incident in incidents:

        playbook = get_response_playbook(
            incident
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
            f"Source IP:     "
            f"{incident['source_ip']}"
        )

        print(
            f"Target IP:     "
            f"{incident['destination_ip']}"
        )

        print(
            f"Risk Level:    "
            f"{incident['risk_level']}"
        )

        print()
        print("INVESTIGATION STEPS")

        for number, step in enumerate(
            playbook["investigation_steps"],
            start=1
        ):
            print(f"{number}. {step}")

        print()
        print("RESPONSE ACTIONS")

        for number, action in enumerate(
            playbook["response_actions"],
            start=1
        ):
            print(f"{number}. {action}")

        print()
        print(
            "Block Recommended: "
            f"{playbook['block_recommended']}"
        )

        print("-" * 70)
