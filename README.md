# Python-Based SIEM Log Analyzer for SSH Threat Detection

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

Enterprise-style SSH log analysis with SOC-ready detections, MITRE mappings, correlation, and threat intelligence enrichment. Lightweight, auditable, and designed for real-world SOC workflows.

---

## Project Overview
This project is a Python SIEM-style analyzer for SSH auth logs. It detects attacker behavior (brute force, off-hours access, privilege escalation), correlates events into incidents, enriches IPs with threat intelligence, maps detections to MITRE ATT&CK, and generates SOC-ready reports and dashboards.

Primary goals:
- Deliver actionable alerting with minimal dependencies.
- Keep the pipeline modular and testable.
- Provide recruiter-friendly, production-aligned output.

---

## Architecture
```
[auth.log]
    |
    v
[Parser + Detectors] ---> [Correlation Engine]
    |                          |
    v                          v
[Alerts (JSON)]         [Incident Report]
    |
    v
[Threat Intel Enrichment]
    |
    v
[SOC Console + Dashboard]
```

---

## Features
- SSH auth log parsing (failed, success, sudo/su events)
- Brute force success detection
- Failed login burst detection
- Privilege escalation detection
- Off-hours login detection
- Unknown user detection
- Correlated incident detection (Account Compromise)
- Severity-based alerting
- MITRE ATT&CK technique mapping
- Threat intelligence enrichment (AbuseIPDB + VirusTotal)
- JSON alert export and enterprise-grade incident reports
- Streamlit SOC dashboard

---

## Screenshots
Add screenshots to assets/ and link them here:
- Console output (colorized SOC summary)
- Incident report excerpt
- Streamlit dashboard overview

Suggested files:
- assets/console-output.png
- assets/incident-report.png
- assets/dashboard.png

---

## Installation
```
pip install -r requirements.txt
```

If you prefer manual install:
```
pip install requests colorama pandas plotly matplotlib streamlit
```

---

## Quick Start
Run the analyzer on sample data:
```
python analyze.py --log sample_logs/auth.log --no-enrich
```

Enable enrichment with API keys:
```
setx ABUSEIPDB_API_KEY "YOUR_KEY"
setx VIRUSTOTAL_API_KEY "YOUR_KEY"
python analyze.py --log sample_logs/auth.log
```

Run the dashboard:
```
streamlit run dashboard/app.py
```

---

## Configuration
Edit config.json to tune detection thresholds:
- max_attempts
- time_window_minutes
- summary_limit
- verbose_limit
- block_threshold
- monitor_threshold

Extended detection config:
- business_hours_start
- business_hours_end
- bruteforce_window_minutes
- known_users
- abuseipdb_enabled
- output_dir

---

## Usage (CLI)
```
python analyze.py --log /var/log/auth.log
python analyze.py --log /var/log/auth.log --no-enrich
python analyze.py --log /var/log/auth.log --output output
```

---

## Sample Output (Console)
```
[CRITICAL]  2026-05-26 02:13:13  OFF_HOURS_LOGIN      MITRE: T1078  IP: 185.72.33.10  USER: root
[HIGH    ]  2026-05-26 02:13:13  BRUTEFORCE_SUCCESS   MITRE: T1110  IP: 185.72.33.10  USER: root  TI: 92% RU ISP Malicious:Yes
[MEDIUM  ]  2026-05-26 09:30:08  FAILED_LOGIN_BURST   MITRE: N/A    IP: 45.33.32.156  USER: <multiple>
```

---

## MITRE ATT&CK Mapping
Mapped techniques (example):
- T1110 - Brute Force
- T1078 - Valid Accounts
- T1548 - Abuse Elevation Control Mechanism

Mappings are centralized in mitre.py to keep detections and reporting consistent.

---

## Outputs
Generated artifacts:
- output/alerts.json (machine-readable alert stream)
- output/incident_report.txt (SOC report)

The incident report includes:
- Incident ID and severity
- Detection type and MITRE ATT&CK technique
- IP, user, timestamp
- Threat intelligence summary
- Recommended actions per alert

---

## Dashboard
The Streamlit dashboard reads output/alerts.json and provides:
- Total alerts
- Severity counts
- Top attacker IPs
- Attack timeline
- Targeted usernames
- MITRE ATT&CK mapping table

---

## Project Structure
```
SSHVigil-Cybersecurity-Suite-main/
  analyze.py
  detectors.py
  enrichment.py
  reporter.py
  mitre.py
  dashboard/
    app.py
  output/
    alerts.json
    incident_report.txt
  sample_logs/
    auth.log
  tests/
```

---

## Future Improvements
- GeoIP and ASN enrichment
- Alert deduplication and case management
- Database backend for long-term analytics
- Additional correlation rules (persistence, lateral movement)
- SIEM integrations (Splunk, Sentinel, Elastic)

---

## Screenshot Suggestions
- SOC summary output (colorized)
- Incident report sample block
- Streamlit dashboard with charts

---

## GitHub Optimization Tips
- Add badges for build/tests and linting
- Pin a short demo GIF of the dashboard
- Include a short video walkthrough in the repo description
- Add a Release tag for each milestone

---

## License
MIT License. See LICENSE for details.
