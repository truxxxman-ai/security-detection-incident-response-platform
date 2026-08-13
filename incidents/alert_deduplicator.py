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

from incidents.alert_collector import collect_alerts


# 同一种告警之间超过 2 分钟，就认为是新的事件
DEDUP_WINDOW_SECONDS = 120


SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def parse_timestamp(timestamp):

    if timestamp is None:
        return None

    try:

        timestamp = timestamp.replace(
            "Z",
            "+00:00"
        )

        dt = datetime.fromisoformat(
            timestamp
        )

        return dt.timestamp()

    except (ValueError, TypeError):

        return None


def create_cluster(alert):

    first_epoch = parse_timestamp(
        alert["first_seen"]
    )

    last_epoch = parse_timestamp(
        alert["last_seen"]
    )

    return {
        "attack_type":
            alert["attack_type"],

        "source_ip":
            alert["source_ip"],

        "destination_ip":
            alert["destination_ip"],

        "severity":
            alert["severity"],

        "sources":
            {alert["source"]},

        "alert_count":
            1,

        "first_seen":
            alert["first_seen"],

        "last_seen":
            alert["last_seen"],

        "_first_epoch":
            first_epoch,

        "_last_epoch":
            last_epoch
    }


def add_alert_to_cluster(
    cluster,
    alert
):

    first_epoch = parse_timestamp(
        alert["first_seen"]
    )

    last_epoch = parse_timestamp(
        alert["last_seen"]
    )

    cluster["sources"].add(
        alert["source"]
    )

    cluster["alert_count"] += 1

    # 保留最高严重等级
    if (
        SEVERITY_RANK.get(
            alert["severity"],
            0
        )
        >
        SEVERITY_RANK.get(
            cluster["severity"],
            0
        )
    ):

        cluster["severity"] = (
            alert["severity"]
        )

    # 最早开始时间
    if first_epoch is not None:

        if (
            cluster["_first_epoch"] is None
            or
            first_epoch
            <
            cluster["_first_epoch"]
        ):

            cluster["_first_epoch"] = (
                first_epoch
            )

            cluster["first_seen"] = (
                alert["first_seen"]
            )

    # 最晚结束时间
    if last_epoch is not None:

        if (
            cluster["_last_epoch"] is None
            or
            last_epoch
            >
            cluster["_last_epoch"]
        ):

            cluster["_last_epoch"] = (
                last_epoch
            )

            cluster["last_seen"] = (
                alert["last_seen"]
            )


def deduplicate_alerts(alerts):

    grouped = defaultdict(list)

    # ===============================================
    # 先按照 攻击类型 + 源IP + 目标IP 分类
    # ===============================================

    for alert in alerts:

        key = (
            alert["attack_type"],
            alert["source_ip"],
            alert["destination_ip"]
        )

        grouped[key].append(
            alert
        )

    results = []

    # ===============================================
    # 每一类再按照时间窗口划分
    # ===============================================

    for key, related_alerts in grouped.items():

        valid_alerts = []

        for alert in related_alerts:

            timestamp = parse_timestamp(
                alert["first_seen"]
            )

            if timestamp is None:
                continue

            alert_copy = alert.copy()

            alert_copy[
                "_sort_time"
            ] = timestamp

            valid_alerts.append(
                alert_copy
            )

        valid_alerts.sort(
            key=lambda item:
                item["_sort_time"]
        )

        if not valid_alerts:
            continue

        current_cluster = create_cluster(
            valid_alerts[0]
        )

        for alert in valid_alerts[1:]:

            alert_start = parse_timestamp(
                alert["first_seen"]
            )

            cluster_end = current_cluster[
                "_last_epoch"
            ]

            if (
                alert_start is None
                or
                cluster_end is None
            ):
                continue

            gap = (
                alert_start
                -
                cluster_end
            )

            # 两条告警间隔 <= 2分钟
            # 继续归入同一个安全事件
            if gap <= DEDUP_WINDOW_SECONDS:

                add_alert_to_cluster(
                    current_cluster,
                    alert
                )

            else:

                results.append(
                    current_cluster
                )

                current_cluster = (
                    create_cluster(
                        alert
                    )
                )

        results.append(
            current_cluster
        )

    # ===============================================
    # 最终整理
    # ===============================================

    final_results = []

    for incident in results:

        incident["sources"] = sorted(
            list(
                incident["sources"]
            )
        )

        if len(
            incident["sources"]
        ) >= 2:

            incident["confidence"] = (
                "HIGH"
            )

        else:

            incident["confidence"] = (
                "MEDIUM"
            )

        first_epoch = incident[
            "_first_epoch"
        ]

        last_epoch = incident[
            "_last_epoch"
        ]

        if (
            first_epoch is not None
            and
            last_epoch is not None
        ):

            incident["duration"] = max(
                0.0,
                last_epoch
                -
                first_epoch
            )

        else:

            incident["duration"] = 0.0

        incident.pop(
            "_first_epoch",
            None
        )

        incident.pop(
            "_last_epoch",
            None
        )

        final_results.append(
            incident
        )

    final_results.sort(
        key=lambda item:
            parse_timestamp(
                item["first_seen"]
            ) or 0
    )

    return final_results


if __name__ == "__main__":

    alerts = collect_alerts()

    incidents = deduplicate_alerts(
        alerts
    )

    print("=" * 78)
    print("TIME-WINDOW ALERT DEDUPLICATION")
    print("=" * 78)

    print(
        f"Raw Unified Alerts: {len(alerts)}"
    )

    print(
        f"Deduplicated Events: {len(incidents)}"
    )

    for incident in incidents:

        print()

        print(
            f"Attack:       "
            f"{incident['attack_type']}"
        )

        print(
            f"Source IP:    "
            f"{incident['source_ip']}"
        )

        print(
            f"Target IP:    "
            f"{incident['destination_ip']}"
        )

        print(
            f"Severity:     "
            f"{incident['severity']}"
        )

        print(
            f"Evidence:     "
            f"{', '.join(incident['sources'])}"
        )

        print(
            f"Raw Alerts:   "
            f"{incident['alert_count']}"
        )

        print(
            f"Confidence:   "
            f"{incident['confidence']}"
        )

        print(
            f"First Seen:   "
            f"{incident['first_seen']}"
        )

        print(
            f"Last Seen:    "
            f"{incident['last_seen']}"
        )

        print(
            f"Duration:     "
            f"{incident['duration']:.2f} seconds"
        )

        print("-" * 78)
