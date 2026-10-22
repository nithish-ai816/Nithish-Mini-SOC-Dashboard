# Mini SOC Dashboard

**Security Event Monitoring and Alert Analysis System**

A browser-based security dashboard built with Python and Streamlit that simulates how a Security Operations Centre analyst views, filters, and analyses network security events. The application classifies 63 synthetic log events by severity, detects brute-force login patterns, and visualises activity through interactive charts — all running locally with no external data source required.

Built as part of the IBM SkillsBuild Cyber Security Bootcamp 2026 (BharatCares).

---

## Overview

Real-world SOC analysts work with continuous streams of security log data and need to quickly surface the most critical events from the noise. This project implements a simplified version of that workflow using Python: structured log data is loaded into a Pandas DataFrame, classified by rule-based severity logic, filtered interactively through a Streamlit sidebar, and displayed alongside Plotly charts for pattern analysis.

The dataset is synthetic and embedded directly in the application. No database, API, or external file is required to run the project.

> This is an educational prototype. It demonstrates SOC concepts using simulated data and is not intended for deployment in a live security environment.

---

## Project Structure

```
Mini_SOC_Dashboard/
├── Nithish_MiniSOCDashboard.py   # Streamlit application (complete, single file)
├── requirements.txt              # Python dependencies
├── Nithish_ProjectReport.docx    # Academic project report
└── README.md                     # This file
```

---

## Problem Statement

Entry-level cybersecurity learners often understand security concepts in theory but lack hands-on experience with the tooling and workflows SOC analysts use daily. This project bridges that gap by building a working local dashboard that applies concepts including log analysis, severity classification, threshold-based alerting, and data visualisation to a realistic (if synthetic) security dataset.

---

## Objectives

- Load and structure security log data using Pandas
- Apply rule-based severity classification to each event
- Detect repeated failed login attempts and flag potential brute-force sources
- Present filtered, colour-coded event data through a Streamlit interface
- Visualise event distribution, severity breakdown, and temporal patterns using Plotly
- Export filtered results to CSV

---

## Technology Stack

| Technology | Version | Role |
|---|---|---|
| Python | 3.9+ | Core language |
| Streamlit | >= 1.32.0 | Dashboard UI and interactivity |
| Pandas | >= 2.0.0 | Data loading, transformation, filtering |
| Plotly Express | >= 5.18.0 | Interactive charts |
| python-docx | >= 1.1.0 | Project report generation |

---

## Application Workflow

```
Embedded synthetic logs (RAW_LOGS list)
        |
        v
  load_data()  --  parse timestamps, derive hour/date columns
        |
        v
  assign_severity()  --  rule-based tagging per event type
        |
        v
  Streamlit sidebar filters  --  severity / event type / source IP / threshold
        |
        v
  Filtered DataFrame
        |
   _____|______________________________________
  |             |              |               |
KPI cards  Brute-force    Event log       4 Plotly
           alert table  (colour-coded)    charts
                                              |
                                         CSV export
```

---

## Detection Logic

### Severity Classification

Every event is assigned exactly one severity level by the `assign_severity` function. The rules, in priority order, are:

| Severity | Event types |
|---|---|
| Critical | Data Exfiltration, Privilege Escalation |
| High | Brute Force, Malware Detected, Port Scan |
| Medium | Failed Login, Firewall Block, Suspicious Traffic |
| Low | Successful Login, Normal Traffic |

### Brute-Force Detection

The `detect_brute_force` function groups events of type `Failed Login` and `Brute Force` by source IP. Any source IP whose combined count meets or exceeds a configurable threshold (default: 5) is surfaced in the alert panel with columns: Source IP, Failed Attempts, First Seen, Last Seen, Target IP, Country.

At the default threshold of 5, two IPs trigger the alert from the embedded dataset:

| Source IP | Failed Login | Brute Force | Total |
|---|---:|---:|---:|
| 192.168.1.105 | 7 | 3 | 10 |
| 172.16.5.10 | 5 | 0 | 5 |
| 100.64.0.5 | 3 | 0 | 3 (no alert) |

The threshold is adjustable at runtime via a sidebar slider (range: 2–15). Setting it to 3 will also flag `100.64.0.5`.

---

## Synthetic Dataset

The embedded dataset contains **63 events** across one simulated day (2025-01-15). All IP addresses, usernames, and hostnames are fictional.

| Event Type | Count | Severity |
|---|---:|---|
| Normal Traffic | 17 | Low |
| Failed Login | 15 | Medium |
| Port Scan | 7 | High |
| Successful Login | 6 | Low |
| Firewall Block | 5 | Medium |
| Brute Force | 3 | High |
| Malware Detected | 3 | High |
| Suspicious Traffic | 3 | Medium |
| Privilege Escalation | 2 | Critical |
| Data Exfiltration | 2 | Critical |
| **Total** | **63** | |

Event fields per record: `timestamp`, `source_ip`, `destination_ip`, `event_type`, `protocol`, `port`, `username`, `status`, `country`.

---

## Dashboard Features

### Metric Cards

Five live-updating cards at the top of the page:

| Card | What it counts |
|---|---|
| Total Events | All events passing current filters |
| Critical | Events with Critical severity |
| High | Events with High severity |
| Medium | Events with Medium severity |
| Failed Logins | `Failed Login` + `Brute Force` events combined |

### Brute-Force Alert Panel

Displays a table of IPs exceeding the failed-login threshold, or a green confirmation if none exist. Updates immediately when the threshold slider is moved.

### Security Event Log

Sortable, scrollable table of all filtered events. The severity column is colour-coded (red for Critical, orange for High, yellow for Medium, green for Low). Events are pre-sorted by severity then timestamp.

### Charts

| Chart | Type | What it shows |
|---|---|---|
| Event Type Distribution | Vertical bar | Count per event type |
| Severity Breakdown | Pie | Proportion of each severity level |
| Security Events Over Time (Hourly) | Line with markers | Hourly counts, one line per severity level |
| Top 10 Source IPs by Event Count | Horizontal bar | Most active source IPs |

### Sidebar Filters

| Filter | Control | Default |
|---|---|---|
| Severity Level | Multi-select | All selected |
| Event Type | Multi-select | All selected |
| Source IP | Multi-select | All selected |
| Brute-Force Threshold | Slider (2–15) | 5 |

All filters apply simultaneously to every chart, table, and metric card.

### CSV Export

A download button exports the current filtered view as `soc_filtered_events.csv`.

---

## Setup and Installation (Windows)

### Prerequisites

- Python 3.9 or higher: https://www.python.org/downloads/
  During installation, tick **Add Python to PATH**.
- pip is included with Python.
- PowerShell or Command Prompt.

### Steps

**1. Clone or download the repository**

```
git clone https://github.com/YOUR-USERNAME/YOUR-REPO-NAME.git
cd YOUR-REPO-NAME
```

Replace `YOUR-USERNAME` and `YOUR-REPO-NAME` with your actual GitHub details once the repository is created.

**2. Create a virtual environment (recommended)**

```
python -m venv venv
venv\Scripts\activate
```

The prompt will show `(venv)` when the environment is active.

**3. Install dependencies**

```
pip install -r requirements.txt
```

**4. Run the application**

```
streamlit run Nithish_MiniSOCDashboard.py
```

The dashboard opens automatically at http://localhost:8501. Press Ctrl+C to stop.

---

## Limitations

- The dataset is static and synthetic. The application has no connection to live systems, log files, or network interfaces.
- Detection logic covers only the single-IP brute-force pattern. Distributed attacks, credential stuffing, or slow-rate attempts are not detected.
- No authentication layer. Anyone with access to the local URL can view the dashboard.
- No persistent state. Filter selections reset on each page refresh.
- Designed for local execution only. Serving this publicly would require additional hardening.

---

## Path to a Production SOC Tool

To develop this prototype toward production use, the following would be needed:

- A live log ingestion pipeline (e.g. syslog, SIEM integration, or API connector)
- A persistent data store (database or log management system)
- Statistical or ML-based anomaly detection rather than fixed rules
- Role-based access control and dashboard authentication
- Alerting integrations (email, Slack, ticketing systems)
- Compliance and audit logging

---

## What This Project Demonstrates

- Translating a cybersecurity concept (SOC monitoring) into a working local tool
- Structuring and processing tabular security data with Pandas
- Implementing rule-based detection logic in Python
- Building an interactive, filterable dashboard interface with Streamlit
- Creating data visualisations appropriate for security analysis with Plotly
- Organising a project for public documentation and reproducibility

---

## Learning Outcomes

Working through this project developed practical understanding of:

- How security events are categorised by type and severity
- How threshold-based alerting works in practice
- How a SOC analyst might use filtering and visualisation to triage incidents
- How Python data tools (Pandas, Plotly) apply to a security domain problem
- The gap between a prototype and a production security tool

---

## Educational Use

This project was developed as a personal learning exercise during the IBM SkillsBuild Cyber Security Bootcamp 2026 (BharatCares). It is shared for portfolio and educational purposes. The dataset is entirely synthetic. This project must not be used as a real security monitoring tool.

---

All technical claims in this README have been verified against the source code in `Nithish_MiniSOCDashboard.py`. No test results are stated; the application has not been run as part of this documentation.
