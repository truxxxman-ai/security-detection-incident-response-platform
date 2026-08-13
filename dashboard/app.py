import json
import os
import sys
import ipaddress

import pandas as pd
import streamlit as st


# =========================================================
# Project path
# =========================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.insert(0, PROJECT_ROOT)


# =========================================================
# Project modules
# =========================================================

from response.playbook import get_response_playbook

from dashboard.state_manager import (
    get_incident_status,
    set_incident_status
)

from scripts.refresh_data import (
    refresh_security_data
)


# =========================================================
# Data files
# =========================================================

INCIDENT_FILE = os.path.join(
    PROJECT_ROOT,
    "data",
    "incidents.json"
)

CHAIN_FILE = os.path.join(
    PROJECT_ROOT,
    "data",
    "attack_chains.json"
)


# =========================================================
# Lab security scope
# =========================================================

LAB_NETWORK = ipaddress.ip_network(
    "192.168.42.0/24"
)

PROTECTED_IPS = {
    "192.168.42.129"
}


# =========================================================
# Streamlit page configuration
# =========================================================

st.set_page_config(
    page_title="Security Operations Center",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# Helper functions
# =========================================================

def load_json(path):

    if not os.path.exists(path):
        return []

    try:

        with open(
            path,
            "r"
        ) as file:

            return json.load(file)

    except (
        OSError,
        json.JSONDecodeError
    ):

        return []


def safe_block_commands(ip_string):

    try:

        ip = ipaddress.ip_address(
            ip_string
        )

    except ValueError:

        return None, None

    # Only allow lab addresses
    if ip not in LAB_NETWORK:

        return None, None

    # Never block protected Ubuntu host
    if ip_string in PROTECTED_IPS:

        return None, None

    block_command = (
        f"sudo iptables -I INPUT 1 "
        f"-s {ip_string} -j DROP"
    )

    unblock_command = (
        f"sudo iptables -D INPUT "
        f"-s {ip_string} -j DROP"
    )

    return (
        block_command,
        unblock_command
    )


# =========================================================
# Header
# =========================================================

st.title(
    "Security Operations Center"
)

st.caption(
    "Security Detection & Automated Incident Response Platform"
)


# =========================================================
# Refresh Detection Pipeline
# =========================================================

if "refresh_message" in st.session_state:

    st.success(
        st.session_state.pop(
            "refresh_message"
        )
    )


refresh_col, info_col = st.columns(
    [1, 3]
)


with refresh_col:

    if st.button(
        "Refresh Detection Data",
        type="primary",
        use_container_width=True
    ):

        with st.spinner(
            "Reading security logs and running detection pipeline..."
        ):

            try:

                result = refresh_security_data()

                st.session_state[
                    "refresh_message"
                ] = (
                    f"Refresh complete: "
                    f"{result['incidents']} incidents, "
                    f"{result['chains']} attack chains."
                )

                st.rerun()

            except PermissionError as error:

                st.error(
                    f"Permission error: {error}"
                )

            except Exception as error:

                st.error(
                    f"Refresh failed: {error}"
                )


with info_col:

    st.caption(
        "Reads Suricata, Zeek, SSH and Nginx logs, "
        "then regenerates incidents and attack chains."
    )


st.divider()


# =========================================================
# Load latest data
# =========================================================

incidents = load_json(
    INCIDENT_FILE
)

attack_chains = load_json(
    CHAIN_FILE
)


# Apply saved SOC workflow state
for incident in incidents:

    incident["status"] = (
        get_incident_status(
            incident
        )
    )


# =========================================================
# Summary metrics
# =========================================================

total_incidents = len(
    incidents
)

critical_count = sum(
    1
    for incident in incidents
    if incident.get(
        "risk_level"
    ) == "CRITICAL"
)

high_count = sum(
    1
    for incident in incidents
    if incident.get(
        "risk_level"
    ) == "HIGH"
)

active_count = sum(
    1
    for incident in incidents
    if incident.get(
        "status"
    ) in [
        "OPEN",
        "INVESTIGATING"
    ]
)


metric1, metric2, metric3, metric4 = st.columns(
    4
)

with metric1:

    st.metric(
        "Total Incidents",
        total_incidents
    )


with metric2:

    st.metric(
        "Critical",
        critical_count
    )


with metric3:

    st.metric(
        "High",
        high_count
    )


with metric4:

    st.metric(
        "Active",
        active_count
    )


st.divider()


# =========================================================
# Main tabs
# =========================================================

tab1, tab2, tab3 = st.tabs(
    [
        "Incidents",
        "Attack Chains",
        "Risk Overview"
    ]
)


# =========================================================
# TAB 1
# Incidents
# =========================================================

with tab1:

    st.subheader(
        "Security Incidents"
    )

    if not incidents:

        st.warning(
            "No incident data available."
        )

    else:

        # -------------------------------------------------
        # Incident table
        # -------------------------------------------------

        incident_rows = []

        for incident in incidents:

            incident_rows.append(
                {
                    "Incident ID":
                        incident.get(
                            "incident_id"
                        ),

                    "Attack":
                        incident.get(
                            "attack_type"
                        ),

                    "Attacker":
                        incident.get(
                            "source_ip"
                        ),

                    "Target":
                        incident.get(
                            "destination_ip"
                        ),

                    "Risk Score":
                        incident.get(
                            "risk_score"
                        ),

                    "Risk Level":
                        incident.get(
                            "risk_level"
                        ),

                    "Confidence":
                        incident.get(
                            "confidence"
                        ),

                    "First Seen":
                        incident.get(
                            "first_seen"
                        ),

                    "Last Seen":
                        incident.get(
                            "last_seen"
                        ),

                    "Duration":
                        round(
                            incident.get(
                                "duration",
                                0
                            ),
                            2
                        ),

                    "Status":
                        incident.get(
                            "status"
                        )
                }
            )


        incident_df = pd.DataFrame(
            incident_rows
        )


        st.dataframe(
            incident_df,
            use_container_width=True,
            hide_index=True
        )


        st.divider()


        # -------------------------------------------------
        # Incident investigation
        # -------------------------------------------------

        st.subheader(
            "Incident Investigation"
        )


        incident_ids = [
            incident.get(
                "incident_id"
            )
            for incident in incidents
        ]


        selected_id = st.selectbox(
            "Select Incident",
            incident_ids
        )


        selected = next(
            (
                incident
                for incident in incidents
                if incident.get(
                    "incident_id"
                ) == selected_id
            ),
            None
        )


        if selected:

            left, right = st.columns(
                2
            )


            # =============================================
            # Left details
            # =============================================

            with left:

                st.write(
                    "**Attack Type:**",
                    selected.get(
                        "attack_type"
                    )
                )

                st.write(
                    "**Attacker:**",
                    selected.get(
                        "source_ip"
                    )
                )

                st.write(
                    "**Target:**",
                    selected.get(
                        "destination_ip"
                    )
                )

                st.write(
                    "**Evidence:**",
                    ", ".join(
                        selected.get(
                            "evidence_sources",
                            []
                        )
                    )
                )

                st.write(
                    "**First Seen:**",
                    selected.get(
                        "first_seen"
                    )
                )

                st.write(
                    "**Last Seen:**",
                    selected.get(
                        "last_seen"
                    )
                )

                st.write(
                    "**Duration:**",
                    f"{selected.get('duration', 0):.2f} seconds"
                )


            # =============================================
            # Right details
            # =============================================

            with right:

                st.write(
                    "**Risk Score:**",
                    selected.get(
                        "risk_score"
                    )
                )

                st.write(
                    "**Risk Level:**",
                    selected.get(
                        "risk_level"
                    )
                )

                st.write(
                    "**Severity:**",
                    selected.get(
                        "severity"
                    )
                )

                st.write(
                    "**Confidence:**",
                    selected.get(
                        "confidence"
                    )
                )

                st.write(
                    "**Raw Alerts:**",
                    selected.get(
                        "raw_alert_count"
                    )
                )

                st.write(
                    "**Status:**",
                    selected.get(
                        "status"
                    )
                )


            st.divider()


            # =================================================
            # Incident workflow
            # =================================================

            st.subheader(
                "Incident Workflow"
            )


            button1, button2, button3 = st.columns(
                3
            )


            with button1:

                if st.button(
                    "Start Investigation",
                    use_container_width=True
                ):

                    set_incident_status(
                        selected,
                        "INVESTIGATING"
                    )

                    st.rerun()


            with button2:

                if st.button(
                    "Resolve Incident",
                    use_container_width=True
                ):

                    set_incident_status(
                        selected,
                        "RESOLVED"
                    )

                    st.rerun()


            with button3:

                if st.button(
                    "Reopen Incident",
                    use_container_width=True
                ):

                    set_incident_status(
                        selected,
                        "OPEN"
                    )

                    st.rerun()


            st.divider()


            # =================================================
            # Response Playbook
            # =================================================

            st.subheader(
                "Response Playbook"
            )


            playbook = get_response_playbook(
                selected
            )


            st.markdown(
                "### Investigation Steps"
            )


            for number, step in enumerate(
                playbook[
                    "investigation_steps"
                ],
                start=1
            ):

                st.write(
                    f"{number}. {step}"
                )


            st.markdown(
                "### Recommended Actions"
            )


            for number, action in enumerate(
                playbook[
                    "response_actions"
                ],
                start=1
            ):

                st.write(
                    f"{number}. {action}"
                )


            st.divider()


            # =================================================
            # Containment
            # =================================================

            st.subheader(
                "Containment"
            )


            if playbook[
                "block_recommended"
            ]:

                st.warning(
                    "Temporary source-IP blocking is recommended."
                )


                (
                    block_command,
                    unblock_command
                ) = safe_block_commands(
                    selected.get(
                        "source_ip"
                    )
                )


                if block_command:

                    st.write(
                        "**Block command:**"
                    )

                    st.code(
                        block_command,
                        language="bash"
                    )


                    st.write(
                        "**Rollback command:**"
                    )

                    st.code(
                        unblock_command,
                        language="bash"
                    )


                    st.caption(
                        "The command is generated only for "
                        "approved lab-network addresses. "
                        "Execution remains manual."
                    )


                else:

                    st.error(
                        "Block command generation refused. "
                        "The IP is outside the lab network "
                        "or belongs to a protected host."
                    )


            else:

                st.info(
                    "IP blocking is not currently recommended "
                    "for this incident."
                )


# =========================================================
# TAB 2
# Attack Chains
# =========================================================

with tab2:

    st.subheader(
        "Multi-stage Attack Chains"
    )


    if not attack_chains:

        st.info(
            "No multi-stage attack chain available."
        )


    else:

        chain_ids = [
            chain.get(
                "chain_id"
            )
            for chain in attack_chains
        ]


        selected_chain_id = st.selectbox(
            "Select Attack Chain",
            chain_ids
        )


        selected_chain = next(
            (
                chain
                for chain in attack_chains
                if chain.get(
                    "chain_id"
                ) == selected_chain_id
            ),
            None
        )


        if selected_chain:

            chain1, chain2, chain3, chain4 = st.columns(
                4
            )


            with chain1:

                st.metric(
                    "Incidents",
                    selected_chain.get(
                        "incident_count",
                        0
                    )
                )


            with chain2:

                st.metric(
                    "Risk Score",
                    selected_chain.get(
                        "risk_score",
                        0
                    )
                )


            with chain3:

                st.metric(
                    "Risk Level",
                    selected_chain.get(
                        "risk_level",
                        "UNKNOWN"
                    )
                )


            with chain4:

                st.metric(
                    "Duration",
                    f"{selected_chain.get('duration', 0):.1f}s"
                )


            st.write(
                "**Attacker:**",
                selected_chain.get(
                    "source_ip"
                )
            )

            st.write(
                "**Target:**",
                selected_chain.get(
                    "destination_ip"
                )
            )

            st.write(
                "**First Seen:**",
                selected_chain.get(
                    "first_seen"
                )
            )

            st.write(
                "**Last Seen:**",
                selected_chain.get(
                    "last_seen"
                )
            )


            st.divider()


            # =================================================
            # Attack Timeline
            # =================================================

            st.subheader(
                "Attack Timeline"
            )


            stages = selected_chain.get(
                "stages",
                []
            )


            for number, stage in enumerate(
                stages,
                start=1
            ):

                st.markdown(
                    f"""
### {number}. {stage.get('attack_type')}

**Stage:** {stage.get('stage')}

**Time:** {stage.get('first_seen')}

**Incident:** {stage.get('incident_id')}

**Risk:** {stage.get('risk_score')}/100 ({stage.get('risk_level')})

**Confidence:** {stage.get('confidence')}

**Evidence:** {", ".join(stage.get('evidence_sources', []))}
"""
                )


                if number < len(
                    stages
                ):

                    st.markdown(
                        "## ↓"
                    )


# =========================================================
# TAB 3
# Risk Overview
# =========================================================

with tab3:

    st.subheader(
        "Risk Overview"
    )


    if not incidents:

        st.info(
            "No incident data available."
        )


    else:

        # =================================================
        # Risk level chart
        # =================================================

        risk_counts = {}


        for incident in incidents:

            level = incident.get(
                "risk_level",
                "UNKNOWN"
            )

            risk_counts[level] = (
                risk_counts.get(
                    level,
                    0
                )
                +
                1
            )


        risk_df = pd.DataFrame(
            {
                "Risk Level":
                    list(
                        risk_counts.keys()
                    ),

                "Incidents":
                    list(
                        risk_counts.values()
                    )
            }
        )


        st.subheader(
            "Incidents by Risk Level"
        )


        st.bar_chart(
            risk_df.set_index(
                "Risk Level"
            )
        )


        st.divider()


        # =================================================
        # Attack type statistics
        # =================================================

        attack_counts = {}


        for incident in incidents:

            attack = incident.get(
                "attack_type",
                "UNKNOWN"
            )

            attack_counts[attack] = (
                attack_counts.get(
                    attack,
                    0
                )
                +
                1
            )


        attack_df = pd.DataFrame(
            {
                "Attack Type":
                    list(
                        attack_counts.keys()
                    ),

                "Count":
                    list(
                        attack_counts.values()
                    )
            }
        )


        st.subheader(
            "Attack Types"
        )


        st.dataframe(
            attack_df,
            use_container_width=True,
            hide_index=True
        )


        st.divider()


        # =================================================
        # Status statistics
        # =================================================

        status_counts = {}


        for incident in incidents:

            status = incident.get(
                "status",
                "UNKNOWN"
            )

            status_counts[status] = (
                status_counts.get(
                    status,
                    0
                )
                +
                1
            )


        status_df = pd.DataFrame(
            {
                "Status":
                    list(
                        status_counts.keys()
                    ),

                "Incidents":
                    list(
                        status_counts.values()
                    )
            }
        )


        st.subheader(
            "Incident Status"
        )


        st.dataframe(
            status_df,
            use_container_width=True,
            hide_index=True
        )


# =========================================================
# Footer
# =========================================================

st.divider()

st.caption(
    "Data Sources: Suricata | Zeek | Linux SSH Logs | Nginx"
)
