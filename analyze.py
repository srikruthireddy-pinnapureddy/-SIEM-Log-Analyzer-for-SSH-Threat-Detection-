"""
analyze.py — Extended SIEM Log Analyzer
========================================
Main CLI entry point for the extended detection suite.
Runs on top of the SSHVigil base to add:

  • Off-hours login detection
  • Brute-force success pattern detection
  • Privilege escalation (sudo/su) detection
  • Unknown user login detection
  • AbuseIPDB IP reputation enrichment
  • JSON alert export
  • Plain-text incident report for L2 escalation

Usage:
  python analyze.py --log sample_logs/auth.log
  python analyze.py --log /var/log/auth.log --api-key YOUR_KEY
  python analyze.py --log sample_logs/auth.log --no-enrich --output output/
"""

import argparse
import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init as colorama_init

from detectors  import run_all_detectors
from enrichment import enrich_alerts
from reporter   import generate_reports
from mitre      import get_mitre_for_detection


SEVERITY_COLOR = {
    "CRITICAL": Fore.RED,
    "HIGH":     Fore.YELLOW,
    "MEDIUM":   Fore.BLUE,
    "LOW":      Fore.GREEN,
}

colorama_init(autoreset=True)


def _colored(text, severity):
    if sys.stdout.isatty():
        return f"{Style.BRIGHT}{SEVERITY_COLOR.get(severity, '')}{text}{Style.RESET_ALL}"
    return text


def _load_config(config_path: str) -> dict:
    if os.path.exists(config_path):
        with open(config_path) as f:
            return json.load(f)
    return {}


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║          SIEM Log Analyzer — Extended Detection          ║
║    SSH Auth Log Analysis | SOC L1 Analyst Toolkit        ║
╚══════════════════════════════════════════════════════════╝
""")


def print_summary(alerts: list):
    """Print a color-coded alert summary table to the terminal."""
    from collections import Counter
    counts = Counter(a["severity"] for a in alerts)

    print("\n" + "─" * 60)
    print("  DETECTION SUMMARY")
    print("─" * 60)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = counts.get(sev, 0)
        bar = "█" * min(c, 30)
        label = _colored(f"{sev:<10}", sev)
        print(f"  {label}  {c:>3} alert(s)  {bar}")
    print("─" * 60)
    print(f"  TOTAL      : {len(alerts)} alert(s)")
    print(f"  UNIQUE IPs : {len(set(a['ip'] for a in alerts if a['ip'] != 'localhost'))}")
    print("─" * 60 + "\n")

    # Print top alerts
    for alert in sorted(alerts, key=lambda a: (["CRITICAL","HIGH","MEDIUM","LOW"].index(a["severity"]))):
        ts   = alert["timestamp"][:19].replace("T", " ")
        sev  = _colored(f"[{alert['severity']:<8}]", alert["severity"])
        mitre = get_mitre_for_detection(alert["type"])
        mitre_id = mitre.get("technique_id", "N/A")
        ti = alert.get("threat_intel") or {}
        abuse = ti.get("abuseipdb") if isinstance(ti, dict) else ti
        vt = ti.get("virustotal") if isinstance(ti, dict) else None
        ti_score = abuse.get("abuse_confidence_score") if abuse else None
        ti_country = abuse.get("country_code") if abuse else None
        ti_isp = abuse.get("isp") if abuse else None
        ti_malicious = abuse.get("is_malicious") if abuse else None
        vt_mal = vt.get("malicious_detections") if vt else None
        vt_rep = vt.get("reputation") if vt else None
        vt_comm = vt.get("community_score") if vt else None
        ti_suffix = ""
        if ti_score is not None:
            ti_suffix = (
                f"  TI: {ti_score}% {ti_country} {ti_isp} "
                f"Malicious:{'Yes' if ti_malicious else 'No'}"
            )
        if vt_mal is not None:
            ti_suffix += f"  VT: {vt_mal} Rep:{vt_rep} Comm:{vt_comm}"
        print(
            f"  {sev}  {ts}  {alert['type']:<25}  MITRE: {mitre_id:<6}  "
            f"IP: {alert['ip']}  USER: {alert['user']}{ti_suffix}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Extended SIEM Log Analyzer — SSH Auth Log Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze.py --log sample_logs/auth.log
  python analyze.py --log /var/log/auth.log --api-key YOUR_ABUSEIPDB_KEY
  python analyze.py --log sample_logs/auth.log --no-enrich
        """
    )
    parser.add_argument("--log",      required=True, help="Path to auth.log file")
    parser.add_argument("--api-key",  default=None,  help="AbuseIPDB API key for IP enrichment")
    parser.add_argument("--no-enrich",action="store_true", help="Skip AbuseIPDB enrichment")
    parser.add_argument("--output",   default="output", help="Output directory for reports (default: output/)")
    parser.add_argument("--config",   default="config.json", help="Path to config.json")
    args = parser.parse_args()

    print_banner()

    # Validate log file
    if not os.path.isfile(args.log):
        print(f"[ERROR] Log file not found: {args.log}")
        sys.exit(1)

    print(f"[*] Log file  : {args.log}")
    print(f"[*] Output dir: {args.output}")
    print(f"[*] Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Load config
    config = _load_config(args.config)

    # Run all detectors
    print("[*] Running detection modules...")
    alerts = run_all_detectors(args.log, config)
    print(f"[✓] Detection complete — {len(alerts)} alert(s) generated.\n")

    # Optional AbuseIPDB enrichment
    if not args.no_enrich:
        alerts = enrich_alerts(alerts, api_key=args.api_key)

    # Print terminal summary
    print_summary(alerts)

    # Generate reports
    print("[*] Generating reports...")
    paths = generate_reports(alerts, log_path=args.log, output_dir=args.output)
    print(f"[✓] JSON report     : {paths['json']}")
    print(f"[✓] Incident report : {paths['text']}")
    print("\n[✓] Analysis complete. Review incident_report.txt for L2 escalation.\n")


if __name__ == "__main__":
    main()
