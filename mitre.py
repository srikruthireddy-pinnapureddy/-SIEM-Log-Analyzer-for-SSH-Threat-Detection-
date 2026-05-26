"""
mitre.py - MITRE ATT&CK mapping for detection types.

Keep this mapping centralized so detectors and reporters can stay focused
on detection and presentation logic.
"""

MITRE_ATTACK_MAPPING = {
    "BRUTEFORCE_SUCCESS": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
    },
    "PRIVILEGE_ESCALATION": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
    },
    "OFF_HOURS_LOGIN": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    "UNKNOWN_USER_LOGIN": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    "ACCOUNT_COMPROMISE": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
}


def get_mitre_for_detection(detection_type: str) -> dict:
    """Return MITRE mapping for a detection type or an empty dict."""
    return MITRE_ATTACK_MAPPING.get(detection_type, {})
