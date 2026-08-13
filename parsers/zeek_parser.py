LOG_FILE = "/opt/zeek/logs/current/conn.log"


def read_zeek_connections(log_file):
    connections = []
    fields = []

    with open(log_file, "r") as file:
        for line in file:

            # 获取 Zeek 字段名称
            if line.startswith("#fields"):
                fields = line.strip().split("\t")[1:]
                continue

            # 跳过其他头部信息
            if line.startswith("#"):
                continue

            values = line.strip().split("\t")

            if not fields or len(values) != len(fields):
                continue

            event = dict(zip(fields, values))

            connection = {
                "timestamp": event.get("ts"),
                "source_ip": event.get("id.orig_h"),
                "source_port": event.get("id.orig_p"),
                "destination_ip": event.get("id.resp_h"),
                "destination_port": event.get("id.resp_p"),
                "protocol": event.get("proto"),
                "service": event.get("service"),
                "duration": event.get("duration"),
                "connection_state": event.get("conn_state")
            }

            connections.append(connection)

    return connections


if __name__ == "__main__":

    connections = read_zeek_connections(LOG_FILE)

    print(f"Total connections found: {len(connections)}")
    print("-" * 70)

    for connection in connections[-20:]:

        print(f"Time:        {connection['timestamp']}")
        print(
            f"Source:      "
            f"{connection['source_ip']}:{connection['source_port']}"
        )
        print(
            f"Destination: "
            f"{connection['destination_ip']}:{connection['destination_port']}"
        )
        print(f"Protocol:    {connection['protocol']}")
        print(f"Service:     {connection['service']}")
        print(f"State:       {connection['connection_state']}")
        print("-" * 70)
