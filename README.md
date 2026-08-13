# Security Detection & Incident Response Platform

A lightweight Security Operations Center (SOC) platform built in a virtual lab environment for network monitoring, threat detection, alert correlation, risk assessment, attack-chain analysis, and incident response.

The platform collects security telemetry from **Suricata, Zeek, Linux SSH logs, and Nginx**, normalises events into a unified alert format, detects suspicious behaviour using Python-based detection logic, correlates alerts into security incidents, calculates risk scores, reconstructs multi-stage attack chains, and displays the results through a Streamlit SOC dashboard.

---

## 1. Project Overview

Modern security environments generate large volumes of alerts from different data sources. Reviewing these alerts individually creates noise and makes it difficult to identify a complete attack process.

This project implements a simplified SOC workflow:

```text
Security Logs
     ↓
Parsing
     ↓
Detection
     ↓
Alert Normalisation
     ↓
Alert Deduplication
     ↓
Risk Scoring
     ↓
Incident Management
     ↓
Attack Chain Correlation
     ↓
Response Playbook
     ↓
SOC Dashboard
```

The goal is to convert low-level security logs into actionable security incidents.

---

## 2. Lab Architecture

The project runs inside a VMware-based isolated lab environment.

```text
┌────────────────────────────┐
│         Kali Linux         │
│                            │
│  Attack Simulation Client  │
│      192.168.42.128        │
└─────────────┬──────────────┘
              │
              │ Security Events
              ▼
┌────────────────────────────┐
│       Ubuntu Server        │
│      192.168.42.129        │
│                            │
│  ┌──────────────────────┐  │
│  │ Suricata IDS         │  │
│  └──────────────────────┘  │
│                            │
│  ┌──────────────────────┐  │
│  │ Zeek                 │  │
│  └──────────────────────┘  │
│                            │
│  ┌──────────────────────┐  │
│  │ OpenSSH              │  │
│  └──────────────────────┘  │
│                            │
│  ┌──────────────────────┐  │
│  │ Nginx                │  │
│  └──────────────────────┘  │
│                            │
│  Python Detection Platform │
│                            │
│  Streamlit SOC Dashboard   │
└────────────────────────────┘
```

---

## 3. Data Sources

The platform currently integrates four security telemetry sources.

| Data Source | Purpose |
|---|---|
| Suricata | IDS alerts and packet-based detection |
| Zeek | Network connection behaviour analysis |
| Linux SSH Journal | Authentication and failed-login monitoring |
| Nginx Access Log | Web request monitoring |

---

## 4. Detection Capabilities

The platform currently detects four types of suspicious behaviour.

### 4.1 TCP Port Scan

Data sources:

- Suricata
- Zeek
- Python detection logic

Detection logic:

```text
Same Source IP
      +
Same Destination IP
      +
≥ 20 unique TCP ports
      +
Within 10 seconds
      ↓
PORT_SCAN
```

Example:

```text
Attack:       PORT_SCAN
Source IP:    192.168.42.128
Target IP:    192.168.42.129
Severity:     HIGH
First Seen:   2026-08-13T21:00:10
Last Seen:    2026-08-13T21:00:11
```

---

### 4.2 SSH Brute Force

Data source:

- Linux SSH authentication journal

Detection logic:

```text
Same Source IP
      +
≥ 5 failed SSH logins
      +
Within 60 seconds
      ↓
SSH_BRUTEFORCE
```

Example:

```text
Attack:          SSH_BRUTEFORCE
Source IP:       192.168.42.128
Failed Attempts: 5
Severity:        HIGH
```

---

### 4.3 Web Enumeration

Data source:

- Nginx access log

Detection logic:

```text
Same Source IP
      +
Multiple HTTP 404 responses
      +
≥ 8 unique paths
      +
Within 60 seconds
      ↓
WEB_ENUMERATION
```

Example suspicious paths:

```text
/admin
/login
/backup
/config
/phpmyadmin
/private
/dashboard
/secret
```

---

### 4.4 SQL Injection Pattern Detection

Data source:

- Nginx access log

The detector URL-decodes HTTP requests and searches for common SQL injection indicators such as:

```text
union select
or 1=1
information_schema
sleep(
benchmark(
```

Example:

```text
/?id=1%27%20OR%201%3D1--
```

Decoded request:

```text
/?id=1' OR 1=1--
```

Detection result:

```text
Attack:    SQL_INJECTION
Severity:  CRITICAL
```

This module detects suspicious SQL injection patterns in HTTP logs; it does not by itself prove successful database exploitation.

---

## 5. Unified Alert Normalisation

Different security tools generate different log structures.

The platform converts them into a unified format:

```json
{
    "source": "PYTHON_NGINX",
    "attack_type": "SQL_INJECTION",
    "source_ip": "192.168.42.128",
    "destination_ip": "192.168.42.129",
    "severity": "CRITICAL",
    "first_seen": "2026-08-13T21:16:16+10:00",
    "last_seen": "2026-08-13T21:16:16+10:00",
    "duration": 0.0
}
```

This allows detections from different technologies to enter the same incident pipeline.

---

## 6. Alert Deduplication

Security tools may generate many alerts for a single attack.

For example:

```text
500 Suricata Alerts
+
1 Zeek Detection
      ↓
1 Security Incident
```

Alerts are grouped using:

```text
Attack Type
+
Source IP
+
Destination IP
+
Time Window
```

The deduplication engine retains:

- Earliest first-seen time
- Latest last-seen time
- Duration
- Alert count
- Highest severity
- Evidence sources
- Confidence level

---

## 7. Multi-Source Confidence

The platform uses a simple evidence-based confidence model.

```text
Single detection source
        ↓
MEDIUM Confidence

Multiple independent sources
        ↓
HIGH Confidence
```

Example:

```text
PORT_SCAN

Evidence:
SURICATA
PYTHON_ZEEK

Confidence:
HIGH
```

---

## 8. Risk Scoring

Each security incident receives a risk score between:

```text
0 - 100
```

The score currently considers:

- Attack type
- Severity
- Detection confidence
- Raw alert volume

Example scoring concept:

```text
SSH_BRUTEFORCE      +45
HIGH Severity       +20
MEDIUM Confidence   +10
Alert Volume        +...
                    ----
Risk Score
```

Risk levels:

| Score | Risk Level |
|---:|---|
| 0–39 | LOW |
| 40–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

---

## 9. Incident Management

Deduplicated alerts are converted into structured security incidents.

Example:

```text
Incident ID:   INC-0004
Attack:        SQL_INJECTION
Attacker:      192.168.42.128
Target:        192.168.42.129
Risk Score:    100/100
Risk Level:    CRITICAL
Confidence:    MEDIUM
Status:        OPEN
```

Incident workflow states include:

```text
OPEN
    ↓
INVESTIGATING
    ↓
RESOLVED
```

Incidents can also be reopened if further investigation is required.

---

## 10. Time-Based Attack Chain Correlation

Individual incidents are correlated using:

```text
Same Source IP
+
Same Destination IP
+
Temporal proximity
```

The current correlation window is:

```text
30 minutes
```

Example reconstructed attack chain:

```text
Attacker: 192.168.42.128
Target:   192.168.42.129

PORT_SCAN
    ↓
SSH_BRUTEFORCE
    ↓
WEB_ENUMERATION
    ↓
SQL_INJECTION
```

The stages can be classified as:

```text
RECONNAISSANCE
      ↓
CREDENTIAL_ATTACK
      ↓
DISCOVERY
      ↓
EXPLOITATION
```

This helps convert isolated alerts into a higher-level view of attacker behaviour.

---

## 11. Incident Response Playbooks

The platform generates investigation and response recommendations according to attack type.

Example for SSH brute force:

### Investigation

```text
1. Review SSH authentication logs.
2. Count failed login attempts.
3. Check whether any login eventually succeeded.
4. Identify targeted usernames.
5. Review activity after successful authentication.
```

### Response

```text
1. Block or rate-limit the attacking source.
2. Reset credentials if compromise is suspected.
3. Disable password authentication where appropriate.
4. Apply stronger SSH access controls.
```

---

## 12. Containment

For selected high-risk incidents, the platform recommends temporary source-IP blocking.

Example:

```bash
sudo iptables -I INPUT 1 -s 192.168.42.128 -j DROP
```

Rollback:

```bash
sudo iptables -D INPUT -s 192.168.42.128 -j DROP
```

The dashboard does **not** execute privileged firewall commands directly.

Instead:

```text
Detection
    ↓
Risk Assessment
    ↓
Response Recommendation
    ↓
Human Review
    ↓
Manual Containment
```

This reduces the risk of automatically blocking legitimate traffic because of a false positive.

The command-generation logic is restricted to the configured lab network.

---

## 13. SOC Dashboard

The platform includes a Streamlit-based Security Operations Center dashboard.

Main functionality includes:

### Security Metrics

```text
Total Incidents
Critical Incidents
High-Risk Incidents
Active Incidents
```

### Incident Table

Displays:

- Incident ID
- Attack Type
- Attacker
- Target
- Risk Score
- Risk Level
- Confidence
- First Seen
- Last Seen
- Duration
- Status

### Incident Investigation

Analysts can:

```text
Start Investigation
Resolve Incident
Reopen Incident
```

### Attack Chain View

Displays correlated multi-stage attacks and their timeline.

### Risk Overview

Provides:

- Incident distribution by risk level
- Attack-type statistics
- Incident status statistics

---

## 14. Detection Pipeline Refresh

The dashboard includes a:

```text
Refresh Detection Data
```

button.

When triggered, the system automatically performs:

```text
Read Security Logs
        ↓
Run Detection Engines
        ↓
Normalise Alerts
        ↓
Deduplicate Alerts
        ↓
Calculate Risk
        ↓
Generate Incidents
        ↓
Correlate Attack Chains
        ↓
Refresh Dashboard
```

---

## 15. Least-Privilege Design

The dashboard does not run as root.

The normal application user receives only the permissions required to read relevant security telemetry.

Example:

```text
Suricata Logs    → Read
Zeek Logs        → zeek group
SSH Journal      → Read
Nginx Logs       → adm group
```

Privileged firewall actions remain outside the web application.

This follows the principle of least privilege and reduces the impact of a potential dashboard compromise.

---

## 16. Project Structure

```text
security-response-platform/
│
├── dashboard/
│   ├── app.py
│   └── state_manager.py
│
├── detectors/
│   ├── port_scan_detector.py
│   ├── ssh_bruteforce_detector.py
│   ├── web_enumeration_detector.py
│   └── sql_injection_detector.py
│
├── parsers/
│   ├── suricata_parser.py
│   ├── zeek_parser.py
│   ├── auth_parser.py
│   └── nginx_parser.py
│
├── incidents/
│   ├── alert_collector.py
│   ├── alert_deduplicator.py
│   ├── risk_scorer.py
│   ├── incident_manager.py
│   ├── attack_timeline.py
│   └── attack_chain_correlator.py
│
├── response/
│   ├── playbook.py
│   └── block_ip.py
│
├── scripts/
│   └── refresh_data.py
│
├── data/
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 17. Technologies

### Security

- Suricata
- Zeek
- Nmap
- Linux authentication logging
- iptables
- Nginx

### Development

- Python
- Streamlit
- Pandas
- JSON

### Infrastructure

- VMware Workstation
- Ubuntu Linux
- Kali Linux

---

## 18. Installation

Clone the repository:

```bash
git clone <repository-url>
```

Enter the project:

```bash
cd security-response-platform
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

The required security services and log paths must also be configured on the host system.

---

## 19. Running the Detection Pipeline

Generate the latest incidents and attack chains:

```bash
python3 scripts/refresh_data.py
```

---

## 20. Running the Dashboard

Start Streamlit:

```bash
streamlit run dashboard/app.py
```

Then open:

```text
http://localhost:8501
```

---

## 21. Example Lab Attack Simulation

The isolated lab can generate controlled security events for testing.

### TCP Port Scan

```bash
sudo nmap -sS -T4 -p 1-1000 <LAB_TARGET_IP>
```

### SSH Failed Authentication

Connect to the lab SSH service and intentionally provide invalid credentials several times.

### Web Enumeration

Request multiple nonexistent paths from the lab web server.

### SQL Injection Pattern

Send a URL-encoded SQL-like test string to the lab web server and verify that the request is detected from the access log.

All testing should be performed only against systems that you own or are explicitly authorised to test.

---

## 22. Key Engineering Concepts

This project demonstrates:

- Network security monitoring
- IDS alert processing
- Network traffic analysis
- Authentication log analysis
- Web log analysis
- Python security automation
- Detection engineering
- Alert normalisation
- Alert deduplication
- Sliding-window detection
- Multi-source event correlation
- Risk scoring
- Incident management
- Attack-chain reconstruction
- Incident response playbooks
- Least-privilege architecture
- SOC dashboard development

---

## 23. Current Limitations

This project is designed as a security engineering lab and learning platform rather than a production SIEM.

Current limitations include:

- Rule-based detection logic
- Simple heuristic risk scoring
- IP-based attack correlation
- File-based JSON storage
- No distributed log ingestion
- No authentication or RBAC for the dashboard
- No production-scale event queue
- No persistent database
- Manual approval for privileged containment

These limitations provide potential directions for future development.

---

## 24. Future Improvements

Potential extensions include:

- PostgreSQL or Elasticsearch storage
- Real-time log streaming
- Kafka-based event ingestion
- MITRE ATT&CK mapping
- Threat-intelligence enrichment
- IOC reputation lookup
- Dashboard authentication and RBAC
- Email or Slack alert notifications
- False-positive suppression
- Machine-learning anomaly detection
- Docker deployment
- REST API support
- Case notes and analyst audit logs
- Automated reporting

---

## 25. Security Notice

This project is intended for defensive cybersecurity learning and authorised lab testing.

All attack simulations should be performed only against systems that the operator owns or has explicit permission to test.
