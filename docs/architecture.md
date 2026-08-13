# System Architecture

The platform follows a layered security monitoring and incident response architecture.

```mermaid
flowchart TD

    A["Kali Linux<br/>Attack Simulation<br/>192.168.42.128"]

    B["Ubuntu Security Host<br/>192.168.42.129"]

    A -->|"Controlled Lab Traffic"| B

    B --> S["Suricata IDS"]
    B --> Z["Zeek Network Monitor"]
    B --> SSH["Linux SSH Journal"]
    B --> N["Nginx Access Logs"]

    S --> SP["Suricata Parser"]
    Z --> ZP["Zeek Parser"]
    SSH --> AP["Authentication Parser"]
    N --> NP["Nginx Parser"]

    SP --> AC["Unified Alert Collector"]

    ZP --> PD["Port Scan Detector"]
    AP --> SD["SSH Brute Force Detector"]
    NP --> WD["Web Enumeration Detector"]
    NP --> SQL["SQL Injection Detector"]

    PD --> AC
    SD --> AC
    WD --> AC
    SQL --> AC

    AC --> DD["Alert Deduplication<br/>Time-Window Correlation"]

    DD --> RS["Risk Scoring Engine"]

    RS --> IM["Incident Manager"]

    IM --> CH["Attack Chain Correlator"]

    IM --> RP["Incident Response Playbooks"]

    CH --> DB["Streamlit SOC Dashboard"]
    RP --> DB

    DB --> WF["Incident Workflow<br/>OPEN → INVESTIGATING → RESOLVED"]

    DB --> CT["Containment Recommendation"]

    CT --> HC["Human Confirmation"]

    HC --> FW["iptables<br/>Block / Rollback"]
```

## Processing Flow

```text
Security Telemetry
        ↓
Parsing
        ↓
Detection
        ↓
Alert Normalisation
        ↓
Time-Window Deduplication
        ↓
Risk Scoring
        ↓
Incident Generation
        ↓
Attack Chain Correlation
        ↓
Response Playbook
        ↓
SOC Dashboard
        ↓
Human-in-the-loop Containment
```

## Security Design

The dashboard operates without root privileges.

Security telemetry is accessed using least-privilege permissions:

```text
Suricata → Readable alert log
Zeek     → zeek group
SSH      → Journal access
Nginx    → adm group
```

Privileged firewall operations are not executed directly by the web application. Instead, the platform generates validated lab-only containment and rollback commands for analyst review.
