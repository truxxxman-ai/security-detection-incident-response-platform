import re
import subprocess


def read_ssh_failed_logins():
    events = []

    result = subprocess.run(
        [
            "journalctl",
            "-u",
            "ssh",
            "--since",
            "today",
            "-o",
            "short-iso",
            "--no-pager"
        ],
        capture_output=True,
        text=True
    )

    pattern = re.compile(
        r"Failed password for (?:invalid user )?(\S+) "
        r"from ([0-9a-fA-F:.]+) port (\d+)"
    )

    for line in result.stdout.splitlines():

        match = pattern.search(line)

        if not match:
            continue

        parts = line.split()

        event = {
            "timestamp": parts[0],
            "username": match.group(1),
            "source_ip": match.group(2),
            "source_port": match.group(3),
            "event_type": "SSH_FAILED_LOGIN"
        }

        events.append(event)

    return events


if __name__ == "__main__":

    events = read_ssh_failed_logins()

    print("=" * 65)
    print("SSH FAILED LOGIN EVENTS")
    print("=" * 65)

    print(f"Total failed logins: {len(events)}")

    for event in events[-20:]:

        print()
        print(f"Time:      {event['timestamp']}")
        print(f"Source IP: {event['source_ip']}")
        print(f"Port:      {event['source_port']}")
        print(f"Username:  {event['username']}")
        print(f"Event:     {event['event_type']}")
        print("-" * 65)
