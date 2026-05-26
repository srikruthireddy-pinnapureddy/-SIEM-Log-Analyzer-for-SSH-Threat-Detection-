"""
detectors.py — Extended Detection Rules for SIEM Log Analyzer
==============================================================
New detection modules added on top of SSHVigil base:

  1. Log Parser          — parses raw auth.log into structured events
  2. Off-Hours Detection — flags logins outside business hours
  3. BruteForce Success  — detects successful login after multiple failures (same IP)
  4. Privilege Escalation— detects sudo / su usage after login
  5. Unknown User Login  — flags logins from usernames not in known-good whitelist

Each detector returns a list of Alert dicts:
  {
    "type":      str,       # alert category
    "severity":  str,       # LOW / MEDIUM / HIGH / CRITICAL
    "ip":        str,
    "user":      str,
    "timestamp": str,       # ISO 8601
    "detail":    str        # human-readable explanation
  }
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict


# ── Known-good usernames (edit to match your environment) ─────────────────────
KNOWN_USERS = {"john", "developer", "ubuntu", "deploy", "git", "admin", "root"}

# ── Business hours window (24h clock) ─────────────────────────────────────────
BUSINESS_HOURS_START = 9   # 09:00
BUSINESS_HOURS_END   = 18  # 18:00

# ── Regex patterns for auth.log lines ─────────────────────────────────────────
PATTERNS = {
    "failed":  re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for (?:invalid user )?(\S+) from (\S+) port"
    ),
    "success": re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted (?:password|publickey) for (\S+) from (\S+) port"
    ),
    "sudo":    re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*sudo\[\d+\]:\s+(\S+)\s*:.*COMMAND=(.*)"
    ),
    "su":      re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*su\[.*\].*Successful su for (\S+) by (\S+)"
    ),
}

CURRENT_YEAR = datetime.now().year


def _parse_timestamp(raw: str) -> datetime:
    """Convert 'May 26 02:13:01' to datetime (assumes current year)."""
    try:
        return datetime.strptime(f"{raw} {CURRENT_YEAR}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


def parse_auth_log(log_path: str) -> dict:
    """
    Parse an auth.log file into structured event lists.

    Returns:
        {
          "failed":   [ {ip, user, timestamp}, ... ],
          "success":  [ {ip, user, timestamp}, ... ],
          "sudo":     [ {user, command, timestamp}, ... ],
        }
    """
    events = {"failed": [], "success": [], "sudo": []}

    with open(log_path, "r", errors="replace") as f:
        for line in f:
            # Failed login
            m = PATTERNS["failed"].search(line)
            if m:
                ts = _parse_timestamp(m.group(1))
                if ts:
                    events["failed"].append({
                        "ip": m.group(3), "user": m.group(2), "timestamp": ts
                    })
                continue

            # Successful login
            m = PATTERNS["success"].search(line)
            if m:
                ts = _parse_timestamp(m.group(1))
                if ts:
                    events["success"].append({
                        "ip": m.group(3), "user": m.group(2), "timestamp": ts
                    })
                continue

            # Sudo usage
            m = PATTERNS["sudo"].search(line)
            if m:
                ts = _parse_timestamp(m.group(1))
                if ts:
                    events["sudo"].append({
                        "user": m.group(2), "command": m.group(3).strip(), "timestamp": ts
                    })
                continue

            # su usage (treated same as sudo)
            m = PATTERNS["su"].search(line)
            if m:
                ts = _parse_timestamp(m.group(1))
                if ts:
                    events["sudo"].append({
                        "user": m.group(3),
                        "command": f"su to {m.group(2)}",
                        "timestamp": ts
                    })

    return events


# ── DETECTOR 1: Off-Hours Login ───────────────────────────────────────────────

def detect_off_hours_logins(events: dict) -> list:
    """
    Flag any SUCCESSFUL login that occurs outside business hours.
    Off-hours = before 09:00 or after 18:00.

    Severity:
      - Between midnight and 06:00 → CRITICAL
      - Between 18:00 and midnight, or 06:00-09:00 → HIGH
    """
    alerts = []
    for ev in events["success"]:
        hour = ev["timestamp"].hour
        is_off_hours = hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END

        if is_off_hours:
            if hour < 6 or hour >= 22:
                severity = "CRITICAL"
                window = "late night (22:00–06:00)"
            else:
                severity = "HIGH"
                window = f"outside business hours ({BUSINESS_HOURS_START}:00–{BUSINESS_HOURS_END}:00)"

            alerts.append({
                "type":      "OFF_HOURS_LOGIN",
                "severity":  severity,
                "ip":        ev["ip"],
                "user":      ev["user"],
                "timestamp": ev["timestamp"].isoformat(),
                "detail":    (
                    f"Successful login by '{ev['user']}' from {ev['ip']} at "
                    f"{ev['timestamp'].strftime('%H:%M:%S')} — {window}. "
                    "Investigate whether this is an authorized session."
                )
            })
    return alerts


# ── DETECTOR 2: Brute Force Success ──────────────────────────────────────────

def detect_bruteforce_success(events: dict, window_minutes: int = 30) -> list:
    """
    Detect a successful login that follows multiple failed attempts from the same IP.
    This is the hallmark pattern of a successful brute-force attack.

    Severity:
      - ≥10 failures before success → CRITICAL
      - ≥5  failures before success → HIGH
      - ≥2  failures before success → MEDIUM
    """
    alerts = []
    window = timedelta(minutes=window_minutes)

    # Group failures by IP
    failures_by_ip = defaultdict(list)
    for ev in events["failed"]:
        failures_by_ip[ev["ip"]].append(ev["timestamp"])

    for ev in events["success"]:
        ip = ev["ip"]
        success_time = ev["timestamp"]

        # Count failures from this IP within the window before success
        prior_failures = [
            t for t in failures_by_ip.get(ip, [])
            if success_time - window <= t < success_time
        ]

        if len(prior_failures) >= 2:
            count = len(prior_failures)
            if count >= 10:
                severity = "CRITICAL"
            elif count >= 5:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            alerts.append({
                "type":      "BRUTEFORCE_SUCCESS",
                "severity":  severity,
                "ip":        ip,
                "user":      ev["user"],
                "timestamp": success_time.isoformat(),
                "detail":    (
                    f"IP {ip} had {count} failed login attempt(s) before successfully "
                    f"authenticating as '{ev['user']}' at {success_time.strftime('%H:%M:%S')}. "
                    "This matches a credential brute-force success pattern. Escalate immediately."
                )
            })

    return alerts


# ── DETECTOR 3: Privilege Escalation ─────────────────────────────────────────

SENSITIVE_COMMANDS = {"/bin/bash", "/bin/sh", "/bin/su", "/usr/bin/passwd", "/usr/sbin/useradd",
                      "/usr/sbin/usermod", "/usr/bin/vi /etc/sudoers", "/bin/mount"}

def detect_privilege_escalation(events: dict) -> list:
    """
    Detect sudo / su usage. Flags:
      - Any sudo to a sensitive command → HIGH
      - Any sudo/su activity → MEDIUM (for audit trail)
    """
    alerts = []
    for ev in events["sudo"]:
        cmd = ev["command"].strip()
        is_sensitive = any(cmd.startswith(s) for s in SENSITIVE_COMMANDS)
        severity = "HIGH" if is_sensitive else "MEDIUM"

        alerts.append({
            "type":      "PRIVILEGE_ESCALATION",
            "severity":  severity,
            "ip":        "localhost",
            "user":      ev["user"],
            "timestamp": ev["timestamp"].isoformat(),
            "detail":    (
                f"User '{ev['user']}' executed elevated command: [{cmd}] at "
                f"{ev['timestamp'].strftime('%H:%M:%S')}. "
                + ("⚠ Sensitive command — verify authorization." if is_sensitive
                   else "Review for compliance.")
            )
        })
    return alerts


# ── DETECTOR 4: Unknown User Login ───────────────────────────────────────────

def detect_unknown_user_logins(events: dict, known_users: set = None) -> list:
    """
    Flag successful logins from usernames NOT in the known-good whitelist.
    Useful for detecting newly created backdoor accounts.
    """
    known = known_users or KNOWN_USERS
    alerts = []
    for ev in events["success"]:
        if ev["user"] not in known:
            alerts.append({
                "type":      "UNKNOWN_USER_LOGIN",
                "severity":  "HIGH",
                "ip":        ev["ip"],
                "user":      ev["user"],
                "timestamp": ev["timestamp"].isoformat(),
                "detail":    (
                    f"Successful login by unrecognized user '{ev['user']}' from {ev['ip']} "
                    f"at {ev['timestamp'].strftime('%H:%M:%S')}. "
                    "Verify if this account is legitimate. Could indicate backdoor account creation."
                )
            })
    return alerts


def detect_failed_login_bursts(events: dict, max_attempts: int = 5, window_minutes: int = 10) -> list:
    """
    Detect bursts of failed logins for visibility into active probing.
    """
    alerts = []
    window = timedelta(minutes=window_minutes)
    failures_by_ip = defaultdict(list)
    for ev in events["failed"]:
        failures_by_ip[ev["ip"]].append(ev["timestamp"])

    for ip, timestamps in failures_by_ip.items():
        timestamps.sort()
        burst = [t for t in timestamps if timestamps[-1] - t <= window]
        if len(burst) >= max_attempts:
            alerts.append({
                "type":      "FAILED_LOGIN_BURST",
                "severity":  "MEDIUM",
                "ip":        ip,
                "user":      "<multiple>",
                "timestamp": burst[-1].isoformat(),
                "detail":    f"{len(burst)} failed logins from {ip} within {window_minutes} minutes."
            })
    return alerts


# ── CORRELATION: Account Compromise ─────────────────────────────────────────-

def _score_account_compromise(failure_count: int, sensitive_sudo: bool, off_hours: bool) -> str:
    """Return a severity level based on correlated evidence."""
    score = 0
    if failure_count >= 5:
        score += 2
    elif failure_count >= 2:
        score += 1
    if sensitive_sudo:
        score += 2
    if off_hours:
        score += 1

    if score >= 4:
        return "CRITICAL"
    if score >= 2:
        return "HIGH"
    return "MEDIUM"


def correlate_account_compromise(events: dict, window_minutes: int = 30) -> list:
    """
    Correlate failed logins -> success -> privilege escalation into ACCOUNT_COMPROMISE.

    Timeline is included for downstream reporting/forensics.
    """
    alerts = []
    window = timedelta(minutes=window_minutes)

    failures_by_ip = defaultdict(list)
    for ev in events["failed"]:
        failures_by_ip[ev["ip"]].append(ev["timestamp"])

    sudo_by_user = defaultdict(list)
    for ev in events["sudo"]:
        sudo_by_user[ev["user"]].append(ev)

    for success in events["success"]:
        ip = success["ip"]
        user = success["user"]
        success_time = success["timestamp"]

        prior_failures = [
            t for t in failures_by_ip.get(ip, [])
            if success_time - window <= t < success_time
        ]
        if len(prior_failures) < 2:
            continue

        sudo_events = [
            s for s in sudo_by_user.get(user, [])
            if success_time <= s["timestamp"] <= success_time + window
        ]
        if not sudo_events:
            continue

        sudo_event = sudo_events[0]
        command = sudo_event["command"].strip()
        sensitive_sudo = any(command.startswith(s) for s in SENSITIVE_COMMANDS)
        off_hours = success_time.hour < BUSINESS_HOURS_START or success_time.hour >= BUSINESS_HOURS_END

        severity = _score_account_compromise(
            failure_count=len(prior_failures),
            sensitive_sudo=sensitive_sudo,
            off_hours=off_hours
        )

        timeline = [
            {
                "event": "FAILED_LOGIN_BURST",
                "count": len(prior_failures),
                "first_seen": min(prior_failures).isoformat(),
                "last_seen": max(prior_failures).isoformat()
            },
            {
                "event": "LOGIN_SUCCESS",
                "timestamp": success_time.isoformat(),
                "ip": ip,
                "user": user
            },
            {
                "event": "PRIVILEGE_ESCALATION",
                "timestamp": sudo_event["timestamp"].isoformat(),
                "command": command
            }
        ]

        alerts.append({
            "type":      "ACCOUNT_COMPROMISE",
            "severity":  severity,
            "ip":        ip,
            "user":      user,
            "timestamp": sudo_event["timestamp"].isoformat(),
            "detail":    (
                f"Correlation detected: {len(prior_failures)} failed login(s) from {ip} "
                f"followed by successful login and privilege escalation for '{user}'."
            ),
            "timeline":  timeline
        })

    return alerts


# ── RUN ALL DETECTORS ─────────────────────────────────────────────────────────

def run_all_detectors(log_path: str, config: dict = None) -> list:
    """
    Parse the log file and run all detectors.
    Returns a flat list of all alerts sorted by timestamp.
    """
    cfg = config or {}
    events = parse_auth_log(log_path)

    alerts = []
    alerts += detect_off_hours_logins(events)
    alerts += detect_bruteforce_success(events, window_minutes=cfg.get("time_window_minutes", 30))
    alerts += detect_privilege_escalation(events)
    alerts += detect_unknown_user_logins(events)
    alerts += detect_failed_login_bursts(
        events,
        max_attempts=cfg.get("max_attempts", 5),
        window_minutes=cfg.get("time_window_minutes", 10)
    )
    alerts += correlate_account_compromise(events, window_minutes=cfg.get("time_window_minutes", 30))

    # Sort by timestamp ascending
    alerts.sort(key=lambda a: a["timestamp"])
    return alerts
