import json
import os


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

STATE_FILE = os.path.join(
    PROJECT_ROOT,
    "data",
    "incident_state.json"
)


def incident_key(incident):
    return "|".join(
        [
            str(incident.get("attack_type", "")),
            str(incident.get("source_ip", "")),
            str(incident.get("destination_ip", "")),
            str(incident.get("first_seen", ""))
        ]
    )


def load_states():

    if not os.path.exists(STATE_FILE):
        return {}

    try:
        with open(STATE_FILE, "r") as file:
            return json.load(file)

    except (OSError, json.JSONDecodeError):
        return {}


def save_states(states):

    os.makedirs(
        os.path.dirname(STATE_FILE),
        exist_ok=True
    )

    with open(STATE_FILE, "w") as file:
        json.dump(
            states,
            file,
            indent=4
        )


def get_incident_status(incident):

    states = load_states()

    key = incident_key(incident)

    return states.get(
        key,
        {}
    ).get(
        "status",
        incident.get("status", "OPEN")
    )


def set_incident_status(
    incident,
    status
):

    states = load_states()

    key = incident_key(incident)

    states[key] = {
        "status": status
    }

    save_states(states)
