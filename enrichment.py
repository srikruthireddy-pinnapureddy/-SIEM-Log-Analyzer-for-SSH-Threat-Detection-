"""
enrichment.py — Threat Intelligence Enrichment via AbuseIPDB
=============================================================
Checks flagged IPs against the AbuseIPDB API and appends
reputation data to each alert.

Free API key: https://www.abuseipdb.com/register
Rate limit  : 1,000 checks/day on free tier

Usage:
    from enrichment import enrich_alerts
    enriched = enrich_alerts(alerts, api_key="YOUR_KEY")

If no API key is set, enrichment is skipped gracefully with a warning.
"""

import os
import time
import ipaddress
import requests
from datetime import datetime

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
CACHE = {}   # In-session cache to avoid duplicate API calls
VT_CACHE = {}
ABUSE_MALICIOUS_THRESHOLD = 75
VT_RETRY_COUNT = 3
VT_RETRY_SLEEP_SECONDS = 1.0


def _is_public_ip(ip: str) -> bool:
    """Return True only for public, routable IPs."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _check_ip(ip: str, api_key: str) -> dict:
    """
    Query AbuseIPDB for a single IP. Returns reputation dict or None on failure.
    Result is cached per session to avoid redundant calls.
    """
    if ip in CACHE:
        return CACHE[ip]

    # Skip private/loopback IPs
    if ip in ("localhost",) or not _is_public_ip(ip):
        CACHE[ip] = None
        return None

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Key":    api_key,
                "Accept": "application/json"
            },
            params={
                "ipAddress":    ip,
                "maxAgeInDays": 90,
                "verbose":      ""
            },
            timeout=5
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            result = {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports":          data.get("totalReports", 0),
                "country_code":           data.get("countryCode", "Unknown"),
                "isp":                    data.get("isp", "Unknown"),
                "is_whitelisted":         data.get("isWhitelisted", False),
                "is_malicious":            data.get("abuseConfidenceScore", 0) >= ABUSE_MALICIOUS_THRESHOLD,
                "last_reported_at":       data.get("lastReportedAt", None),
                "queried_at":             datetime.now().isoformat()
            }
            CACHE[ip] = result
            return result

        elif response.status_code == 429:
            print("[enrichment] ⚠  AbuseIPDB rate limit hit. Stopping enrichment.")
            return None
        else:
            print(f"[enrichment] API error for {ip}: HTTP {response.status_code}")
            CACHE[ip] = None
            return None

    except requests.exceptions.Timeout:
        print(f"[enrichment] Timeout checking {ip}")
        CACHE[ip] = None
        return None
    except requests.exceptions.RequestException as e:
        print(f"[enrichment] Network error checking {ip}: {e}")
        CACHE[ip] = None
        return None


def _upgrade_severity(current: str, confidence: int) -> str:
    """
    Upgrade alert severity if AbuseIPDB confidence score is high.
    Score 90+ on a MEDIUM alert → upgrade to HIGH, etc.
    """
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx = order.index(current)

    if confidence >= 90 and idx < 3:
        return order[min(idx + 1, 3)]
    return current


def _check_ip_virustotal(ip: str, api_key: str) -> dict:
    """
    Query VirusTotal for a single IP. Returns reputation dict or None on failure.
    Result is cached per session to avoid redundant calls.
    """
    if ip in VT_CACHE:
        return VT_CACHE[ip]

    if ip in ("localhost",) or not _is_public_ip(ip):
        VT_CACHE[ip] = None
        return None

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    for attempt in range(1, VT_RETRY_COUNT + 1):
        try:
            response = requests.get(
                VT_URL.format(ip),
                headers=headers,
                timeout=5
            )

            if response.status_code == 200:
                attributes = response.json().get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                votes = attributes.get("total_votes", {})
                malicious = int(stats.get("malicious", 0))
                harmless = int(stats.get("harmless", 0))
                suspicious = int(stats.get("suspicious", 0))
                result = {
                    "malicious_detections": malicious + suspicious,
                    "reputation": attributes.get("reputation", 0),
                    "community_score": int(votes.get("malicious", 0)) - int(votes.get("harmless", 0)),
                    "queried_at": datetime.now().isoformat()
                }
                VT_CACHE[ip] = result
                return result

            if response.status_code == 429:
                print("[enrichment] ⚠  VirusTotal rate limit hit. Stopping VT enrichment.")
                VT_CACHE[ip] = None
                return None

            print(f"[enrichment] VT API error for {ip}: HTTP {response.status_code}")
            VT_CACHE[ip] = None
            return None

        except requests.exceptions.Timeout:
            print(f"[enrichment] VT timeout checking {ip} (attempt {attempt}/{VT_RETRY_COUNT})")
        except requests.exceptions.RequestException as e:
            print(f"[enrichment] VT network error checking {ip}: {e}")
            break

        time.sleep(VT_RETRY_SLEEP_SECONDS * attempt)

    VT_CACHE[ip] = None
    return None


def enrich_alerts(alerts: list, api_key: str = None, vt_api_key: str = None) -> list:
    """
    Append AbuseIPDB reputation data to each alert that has a public IP.
    Upgrades severity if the IP has a high abuse confidence score.

    Args:
        alerts:  List of alert dicts from detectors.run_all_detectors()
        api_key: AbuseIPDB API key. Falls back to ABUSEIPDB_API_KEY env var.

    Returns:
        The same alerts list with 'threat_intel' field added to each entry.
    """
    key = api_key or os.environ.get("ABUSEIPDB_API_KEY")
    vt_key = vt_api_key or os.environ.get("VIRUSTOTAL_API_KEY")

    if not key:
        print(
            "\n[enrichment] ⚠  No AbuseIPDB API key found.\n"
            "  Set env var ABUSEIPDB_API_KEY or pass --api-key to enable IP reputation checks.\n"
            "  Get a free key at: https://www.abuseipdb.com/register\n"
        )
        key = None

    if not vt_key:
        print(
            "\n[enrichment] ⚠  No VirusTotal API key found.\n"
            "  Set env var VIRUSTOTAL_API_KEY or pass vt_api_key to enable VT enrichment.\n"
            "  Get an API key at: https://www.virustotal.com/gui/join-us\n"
        )
        vt_key = None

    if not key and not vt_key:
        for alert in alerts:
            alert["threat_intel"] = None
        return alerts

    public_ips = [ip for ip in set(a["ip"] for a in alerts if a["ip"] != "localhost") if _is_public_ip(ip)]

    if key:
        print(f"\n[enrichment] Checking {len(public_ips)} unique IPs against AbuseIPDB...")
    if vt_key:
        print(f"[enrichment] Checking {len(public_ips)} unique IPs against VirusTotal...")

    for ip in public_ips:
        if key:
            reputation = _check_ip(ip, key)
            if reputation:
                score = reputation["abuse_confidence_score"]
                country = reputation["country_code"]
                isp = reputation["isp"]
                malicious = "Yes" if reputation.get("is_malicious") else "No"
                print(f"  {ip:<20} Score: {score:>3}%  Country: {country}  ISP: {isp}  Malicious: {malicious}")
            time.sleep(0.3)   # Respect rate limits — 0.3s between calls

        if vt_key:
            vt_rep = _check_ip_virustotal(ip, vt_key)
            if vt_rep:
                mal = vt_rep.get("malicious_detections", 0)
                rep = vt_rep.get("reputation", 0)
                comm = vt_rep.get("community_score", 0)
                print(f"  {ip:<20} VT Malicious: {mal:<3}  Reputation: {rep:<4}  Community: {comm}")
            time.sleep(0.3)

    # Attach reputation data to each alert
    for alert in alerts:
        ip = alert["ip"]
        rep = CACHE.get(ip)
        vt_rep = VT_CACHE.get(ip)
        alert["threat_intel"] = {
            "abuseipdb": rep,
            "virustotal": vt_rep
        }

        if rep:
            score = rep["abuse_confidence_score"]
            # Upgrade severity if IP is known malicious
            alert["severity"] = _upgrade_severity(alert["severity"], score)
            if score >= ABUSE_MALICIOUS_THRESHOLD:
                alert["detail"] += (
                    f" | AbuseIPDB: {score}% confidence malicious "
                    f"({rep['total_reports']} report(s), {rep['country_code']})."
                )

        if vt_rep and vt_rep.get("malicious_detections", 0) > 0:
            alert["detail"] += (
                " | VirusTotal: "
                f"{vt_rep.get('malicious_detections', 0)} engines flagged, "
                f"reputation {vt_rep.get('reputation', 0)}, "
                f"community {vt_rep.get('community_score', 0)}."
            )

    print("[enrichment] ✓ Enrichment complete.\n")
    return alerts
