"""
Streamlit SOC dashboard for SSHVigil SIEM alerts.
Reads output/alerts.json and renders SOC-style analytics.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st
import plotly.express as px
import matplotlib.pyplot as plt


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_ALERTS_PATH = ROOT_DIR / "output" / "alerts.json"

# Allow importing project modules (mitre.py) from repo root
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

try:
    from mitre import MITRE_ATTACK_MAPPING
except Exception:
    MITRE_ATTACK_MAPPING = {}


def load_alerts(alerts_path: Path) -> dict:
    """Load alerts.json payload."""
    with open(alerts_path, "r", encoding="utf-8") as f:
        return json.load(f)


def alerts_to_dataframe(alerts: list[dict]) -> pd.DataFrame:
    """Normalize alert list to a DataFrame."""
    df = pd.DataFrame(alerts)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def map_mitre(alert_type: str) -> dict:
    """Map detection type to MITRE technique info."""
    return MITRE_ATTACK_MAPPING.get(alert_type, {"technique_id": "N/A", "technique_name": "Unknown"})


def build_mitre_table(df: pd.DataFrame) -> pd.DataFrame:
    """Create MITRE mapping summary table."""
    if df.empty:
        return pd.DataFrame(columns=["technique_id", "technique_name", "count"])

    mapped = df["type"].apply(map_mitre)
    mitre_df = pd.DataFrame(list(mapped))
    mitre_df["count"] = 1
    summary = mitre_df.groupby(["technique_id", "technique_name"], as_index=False)["count"].sum()
    return summary.sort_values("count", ascending=False)


def plot_severity_bar(counts: pd.Series) -> plt.Figure:
    """Matplotlib bar chart for severity counts."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    values = [counts.get(k, 0) for k in order]
    colors = ["#c62828", "#f9a825", "#1565c0", "#2e7d32"]

    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.bar(order, values, color=colors)
    ax.set_title("Severity Distribution")
    ax.set_ylabel("Alert Count")
    ax.grid(axis="y", alpha=0.2)
    return fig


def main() -> None:
    st.set_page_config(page_title="SOC Dashboard", layout="wide")

    st.title("SOC Monitoring Console - SSHVigil")
    st.caption("Real-time style analytics for SSH auth detections")

    with st.sidebar:
        st.header("Data Source")
        alerts_path = st.text_input("alerts.json path", value=str(DEFAULT_ALERTS_PATH))
        st.markdown("Run the analyzer first to generate alerts.json.")

    path_obj = Path(alerts_path)
    if not path_obj.exists():
        st.error("alerts.json not found. Run analyze.py to generate output/alerts.json.")
        return

    payload = load_alerts(path_obj)
    alerts = payload.get("alerts", [])
    df = alerts_to_dataframe(alerts)

    total_alerts = len(df)
    severity_counts = df["severity"].value_counts() if not df.empty else pd.Series(dtype=int)

    # Top-level metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts", total_alerts)
    col2.metric("Critical", int(severity_counts.get("CRITICAL", 0)))
    col3.metric("High", int(severity_counts.get("HIGH", 0)))
    col4.metric("Unique IPs", int(df["ip"].nunique()) if "ip" in df.columns else 0)

    st.divider()

    # Charts row
    left, right = st.columns([1, 1])
    with left:
        st.subheader("Severity Overview")
        fig = plot_severity_bar(severity_counts)
        st.pyplot(fig, clear_figure=True)

    with right:
        st.subheader("Top Attacker IPs")
        if "ip" in df.columns and not df.empty:
            top_ips = df["ip"].value_counts().head(10).reset_index()
            top_ips.columns = ["ip", "count"]
            ip_chart = px.bar(top_ips, x="ip", y="count", height=300)
            st.plotly_chart(ip_chart, use_container_width=True)
        else:
            st.info("No IP data available.")

    st.divider()

    # Timeline
    st.subheader("Attack Timeline")
    if "timestamp" in df.columns and not df.empty:
        timeline = df.dropna(subset=["timestamp"]).copy()
        timeline["hour"] = timeline["timestamp"].dt.floor("H")
        timeline_counts = timeline.groupby("hour").size().reset_index(name="count")
        time_chart = px.line(timeline_counts, x="hour", y="count", markers=True, height=300)
        st.plotly_chart(time_chart, use_container_width=True)
    else:
        st.info("No timestamp data available.")

    st.divider()

    # Targeted usernames
    st.subheader("Targeted Usernames")
    if "user" in df.columns and not df.empty:
        top_users = df["user"].value_counts().head(10).reset_index()
        top_users.columns = ["user", "count"]
        user_chart = px.bar(top_users, x="user", y="count", height=300)
        st.plotly_chart(user_chart, use_container_width=True)
    else:
        st.info("No user data available.")

    st.divider()

    # MITRE table
    st.subheader("MITRE ATT&CK Mapping")
    mitre_summary = build_mitre_table(df) if not df.empty else pd.DataFrame()
    if not mitre_summary.empty:
        st.dataframe(mitre_summary, use_container_width=True, hide_index=True)
    else:
        st.info("No MITRE mapping available for the current dataset.")


if __name__ == "__main__":
    main()
