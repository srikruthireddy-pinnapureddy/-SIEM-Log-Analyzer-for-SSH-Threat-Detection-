"""
reporter.py — Alert Export & Incident Report Generator
=======================================================
Takes the alerts list from detectors.py and produces:

  1. alerts.json        — machine-readable structured alert export (SIEM-style)
  2. incident_report.txt— human-readable report for escalation to L2 analyst

Usage (called by analyze.py):
    from reporter import generate_reports
    generate_reports(alerts, output_dir="output/")
"""

import json
import os
from datetime import datetime
from collections import Counter

from mitre import get_mitre_for_detection


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_EMOJI = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[ MED]", "LOW": "[ LOW]"}


def _severity_sort_key(alert):
    return SEVERITY_ORDER.get(alert.get("severity", "LOW"), 3)


def generate_json_report(alerts: list, output_path: str) -> str:
    """
    Export all alerts to a structured JSON file.
    Format mirrors common SIEM log schemas.
    """
    payload = {
        "report_metadata": {
            "generated_at":   datetime.now().isoformat(),
            "tool":           "siem-log-analyzer",
            "total_alerts":   len(alerts),
            "severity_counts": {
                sev: sum(1 for a in alerts if a["severity"] == sev)
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            }
        },
        "alerts": sorted(alerts, key=_severity_sort_key)
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return output_path


def generate_text_report(alerts: list, log_path: str, output_path: str) -> str:
    """
    Generate a plain-text incident report suitable for L2 escalation or ticketing.
    """
    now = datetime.now()
    incident_id = f"INC-{now.strftime('%Y%m%d-%H%M%S')}"
    severity_counts = Counter(a["severity"] for a in alerts)
    type_counts     = Counter(a["type"] for a in alerts)
    unique_ips      = set(a["ip"] for a in alerts if a["ip"] != "localhost")

    recommendations_by_type = {
        "BRUTEFORCE_SUCCESS": [
            "Rotate credentials for affected accounts.",
            "Block offending IPs at firewall/fail2ban.",
            "Review authentication logs for lateral movement.",
        ],
        "PRIVILEGE_ESCALATION": [
            "Review sudo/su logs for unauthorized privilege use.",
            "Verify sudoers configuration and least-privilege controls.",
            "Check for persistence or account misuse.",
        ],
        "OFF_HOURS_LOGIN": [
            "Validate off-hours access with account owners.",
            "Confirm change windows or approved maintenance.",
            "Enable MFA if not already in place.",
        ],
        "UNKNOWN_USER_LOGIN": [
            "Audit /etc/passwd for unauthorized accounts.",
            "Disable or lock suspicious accounts.",
            "Review recent account creation and access events.",
        ],
    }

    # Determine overall incident severity
    if severity_counts.get("CRITICAL", 0) > 0:
        overall = "CRITICAL"
    elif severity_counts.get("HIGH", 0) > 0:
        overall = "HIGH"
    elif severity_counts.get("MEDIUM", 0) > 0:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    lines = []
    lines.append("=" * 78)
    lines.append("                 ENTERPRISE SOC INCIDENT REPORT")
    lines.append("=" * 78)
    lines.append(f"  Incident ID     : {incident_id}")
    lines.append(f"  Generated At    : {now.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Log Source      : {os.path.abspath(log_path)}")
    lines.append(f"  Overall Severity: {overall}")
    lines.append(f"  Analyst         : [L1 SOC Analyst — Srikruthi Reddy]")
    lines.append(f"  Status          : Open — Pending L2 Review")
    lines.append("=" * 78)
    lines.append("")

    # Executive Summary
    lines.append("-- EXECUTIVE SUMMARY " + "-" * 56)
    lines.append(f"  Total Alerts   : {len(alerts)}")
    lines.append(f"  CRITICAL       : {severity_counts.get('CRITICAL', 0)}")
    lines.append(f"  HIGH           : {severity_counts.get('HIGH', 0)}")
    lines.append(f"  MEDIUM         : {severity_counts.get('MEDIUM', 0)}")
    lines.append(f"  LOW            : {severity_counts.get('LOW', 0)}")
    lines.append(f"  Unique IPs     : {len(unique_ips)}")
    lines.append("")
    lines.append("  Alert Types Detected:")
    for atype, count in type_counts.most_common():
        lines.append(f"    - {atype:<30} {count} alert(s)")
    lines.append("")

    # Flagged IPs
    if unique_ips:
        lines.append("-- FLAGGED IP ADDRESSES " + "-" * 51)
        for ip in sorted(unique_ips):
            ip_alerts = [a for a in alerts if a["ip"] == ip]
            sevs = Counter(a["severity"] for a in ip_alerts)
            sev_str = "  ".join(f"{s}:{c}" for s, c in sevs.most_common())
            lines.append(f"  {ip:<20} {sev_str}")
        lines.append("")

    # Alert Details — CRITICAL and HIGH first
    lines.append("-- ALERT DETAILS " + "-" * 60)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_alerts = [a for a in alerts if a["severity"] == sev]
        if not sev_alerts:
            continue
        emoji = SEVERITY_EMOJI.get(sev, "")
        lines.append(f"\n  {emoji} {sev} ({len(sev_alerts)} alert(s))")
        lines.append("  " + "-" * 72)
        for i, a in enumerate(sev_alerts, 1):
            mitre = get_mitre_for_detection(a["type"])
            mitre_id = mitre.get("technique_id", "N/A")
            mitre_name = mitre.get("technique_name", "Unknown")
            ti = a.get("threat_intel") or {}
            abuse = ti.get("abuseipdb") if isinstance(ti, dict) else ti
            vt = ti.get("virustotal") if isinstance(ti, dict) else None
            ti_score = abuse.get("abuse_confidence_score") if abuse else None
            ti_country = abuse.get("country_code") if abuse else None
            ti_isp = abuse.get("isp") if abuse else None
            ti_malicious = abuse.get("is_malicious") if abuse else None
            vt_mal = vt.get("malicious_detections") if vt else None
            vt_rep = vt.get("reputation") if vt else None
            vt_comm = vt.get("community_score") if vt else None
            lines.append(f"  [{i}] Incident ID    : {incident_id}-{i:03d}")
            lines.append(f"      Severity       : {a['severity']}")
            lines.append(f"      Detection Type : {a['type']}")
            lines.append(f"      MITRE ATT&CK   : {mitre_id} - {mitre_name}")
            lines.append(f"      Source IP      : {a['ip']}")
            lines.append(f"      Username       : {a['user']}")
            lines.append(f"      Timestamp      : {a['timestamp']}")
            if ti_score is None and vt_mal is None:
                lines.append("      Threat Intel  : N/A")
            else:
                if ti_score is not None:
                    lines.append(
                        "      Threat Intel  : "
                        f"AbuseIPDB Score {ti_score}%, Country {ti_country}, ISP {ti_isp}, "
                        f"Malicious {'Yes' if ti_malicious else 'No'}"
                    )
                if vt_mal is not None:
                    lines.append(
                        "      Threat Intel  : "
                        f"VirusTotal Malicious {vt_mal}, Reputation {vt_rep}, Community {vt_comm}"
                    )
            lines.append(f"      Analyst Notes  : {a['detail']}")
            lines.append("      Recommended Actions:")
            for action in recommendations_by_type.get(a["type"], ["Review alert context and validate user activity."]):
                lines.append(f"        - {action}")
            lines.append("")

    # Recommended Actions
    lines.append("-- RECOMMENDED ACTIONS (SUMMARY) " + "-" * 42)
    if severity_counts.get("CRITICAL", 0) > 0:
        lines.append("  [CRITICAL] Escalate immediately to L2 analyst.")
        lines.append("  [CRITICAL] Isolate affected systems if active breach is suspected.")
    if type_counts.get("BRUTEFORCE_SUCCESS", 0) > 0:
        lines.append("  [ACTION]   Rotate credentials for all users authenticated from flagged IPs.")
        lines.append("  [ACTION]   Block offending IPs at firewall/fail2ban.")
    if type_counts.get("PRIVILEGE_ESCALATION", 0) > 0:
        lines.append("  [ACTION]   Review sudo logs for unauthorized privilege use.")
        lines.append("  [ACTION]   Verify sudoers configuration and restrict where possible.")
    if type_counts.get("OFF_HOURS_LOGIN", 0) > 0:
        lines.append("  [ACTION]   Confirm off-hours sessions with account owners.")
    if type_counts.get("UNKNOWN_USER_LOGIN", 0) > 0:
        lines.append("  [ACTION]   Audit /etc/passwd for unauthorized accounts.")
    lines.append("")

    # Footer
    lines.append("=" * 78)
    lines.append("  Report generated by siem-log-analyzer | github.com/YOUR_USERNAME/siem-log-analyzer")
    lines.append("=" * 78)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return output_path


def generate_reports(alerts: list, log_path: str, output_dir: str = "output") -> dict:
    """
    Generate both JSON and text reports. Returns paths to both files.
    """
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "alerts.json")
    txt_path  = os.path.join(output_dir, "incident_report.txt")

    generate_json_report(alerts, json_path)
    generate_text_report(alerts, log_path, txt_path)

    return {"json": json_path, "text": txt_path}
