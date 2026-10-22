"""
Mini SOC Dashboard — Security Event Monitoring and Alert Analysis System
IBM SkillsBuild Cyber Security 2026 Project
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import io

# ──────────────────────────────────────────────
# 1.  SYNTHETIC LOG DATA
# ──────────────────────────────────────────────
RAW_LOGS = [
    # ── Failed Login attempts ──────────────────────────────────────────────
    {"timestamp": "2025-01-15 08:01:12", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.1",  "event_type": "Failed Login",    "protocol": "SSH",   "port": 22,  "username": "admin",    "status": "FAILURE", "country": "CN"},
    {"timestamp": "2025-01-15 08:01:45", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.1",  "event_type": "Failed Login",    "protocol": "SSH",   "port": 22,  "username": "admin",    "status": "FAILURE", "country": "CN"},
    {"timestamp": "2025-01-15 08:02:10", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.1",  "event_type": "Failed Login",    "protocol": "SSH",   "port": 22,  "username": "root",     "status": "FAILURE", "country": "CN"},
    {"timestamp": "2025-01-15 08:02:33", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.1",  "event_type": "Failed Login",    "protocol": "SSH",   "port": 22,  "username": "root",     "status": "FAILURE", "country": "CN"},
    {"timestamp": "2025-01-15 08:03:05", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.1",  "event_type": "Failed Login",    "protocol": "SSH",   "port": 22,  "username": "user1",    "status": "FAILURE", "country": "CN"},
    {"timestamp": "2025-01-15 08:03:40", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.1",  "event_type": "Failed Login",    "protocol": "SSH",   "port": 22,  "username": "user1",    "status": "FAILURE", "country": "CN"},
    {"timestamp": "2025-01-15 08:04:22", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.1",  "event_type": "Failed Login",    "protocol": "SSH",   "port": 22,  "username": "test",     "status": "FAILURE", "country": "CN"},
    {"timestamp": "2025-01-15 08:05:01", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.1",  "event_type": "Brute Force",     "protocol": "SSH",   "port": 22,  "username": "admin",    "status": "FAILURE", "country": "CN"},
    {"timestamp": "2025-01-15 08:05:55", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.1",  "event_type": "Brute Force",     "protocol": "SSH",   "port": 22,  "username": "admin",    "status": "FAILURE", "country": "CN"},
    {"timestamp": "2025-01-15 08:06:30", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.1",  "event_type": "Brute Force",     "protocol": "SSH",   "port": 22,  "username": "admin",    "status": "FAILURE", "country": "CN"},
    # ── Port Scans ──────────────────────────────────────────────────────────
    {"timestamp": "2025-01-15 09:10:00", "source_ip": "203.0.113.47",  "destination_ip": "10.0.0.5",  "event_type": "Port Scan",       "protocol": "TCP",   "port": 80,  "username": "-",        "status": "DETECTED","country": "RU"},
    {"timestamp": "2025-01-15 09:10:02", "source_ip": "203.0.113.47",  "destination_ip": "10.0.0.5",  "event_type": "Port Scan",       "protocol": "TCP",   "port": 443, "username": "-",        "status": "DETECTED","country": "RU"},
    {"timestamp": "2025-01-15 09:10:04", "source_ip": "203.0.113.47",  "destination_ip": "10.0.0.5",  "event_type": "Port Scan",       "protocol": "TCP",   "port": 8080,"username": "-",        "status": "DETECTED","country": "RU"},
    {"timestamp": "2025-01-15 09:10:06", "source_ip": "203.0.113.47",  "destination_ip": "10.0.0.5",  "event_type": "Port Scan",       "protocol": "TCP",   "port": 3306,"username": "-",        "status": "DETECTED","country": "RU"},
    {"timestamp": "2025-01-15 09:10:08", "source_ip": "203.0.113.47",  "destination_ip": "10.0.0.5",  "event_type": "Port Scan",       "protocol": "TCP",   "port": 5432,"username": "-",        "status": "DETECTED","country": "RU"},
    {"timestamp": "2025-01-15 09:15:30", "source_ip": "198.51.100.22", "destination_ip": "10.0.0.10", "event_type": "Port Scan",       "protocol": "UDP",   "port": 53,  "username": "-",        "status": "DETECTED","country": "BR"},
    {"timestamp": "2025-01-15 09:15:32", "source_ip": "198.51.100.22", "destination_ip": "10.0.0.10", "event_type": "Port Scan",       "protocol": "UDP",   "port": 161, "username": "-",        "status": "DETECTED","country": "BR"},
    # ── Firewall Blocks ─────────────────────────────────────────────────────
    {"timestamp": "2025-01-15 10:00:05", "source_ip": "203.0.113.47",  "destination_ip": "10.0.0.1",  "event_type": "Firewall Block",  "protocol": "TCP",   "port": 22,  "username": "-",        "status": "BLOCKED", "country": "RU"},
    {"timestamp": "2025-01-15 10:05:12", "source_ip": "198.51.100.55", "destination_ip": "10.0.0.2",  "event_type": "Firewall Block",  "protocol": "TCP",   "port": 3389,"username": "-",        "status": "BLOCKED", "country": "KP"},
    {"timestamp": "2025-01-15 10:07:44", "source_ip": "198.51.100.55", "destination_ip": "10.0.0.2",  "event_type": "Firewall Block",  "protocol": "TCP",   "port": 3389,"username": "-",        "status": "BLOCKED", "country": "KP"},
    {"timestamp": "2025-01-15 10:22:30", "source_ip": "172.16.0.99",   "destination_ip": "10.0.0.3",  "event_type": "Firewall Block",  "protocol": "ICMP",  "port": 0,   "username": "-",        "status": "BLOCKED", "country": "US"},
    {"timestamp": "2025-01-15 11:30:00", "source_ip": "10.10.10.10",   "destination_ip": "10.0.0.8",  "event_type": "Firewall Block",  "protocol": "TCP",   "port": 445, "username": "-",        "status": "BLOCKED", "country": "IN"},
    # ── Successful Logins ───────────────────────────────────────────────────
    {"timestamp": "2025-01-15 08:30:00", "source_ip": "10.0.0.50",     "destination_ip": "10.0.0.1",  "event_type": "Successful Login","protocol": "SSH",   "port": 22,  "username": "alice",    "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 09:00:00", "source_ip": "10.0.0.51",     "destination_ip": "10.0.0.2",  "event_type": "Successful Login","protocol": "RDP",   "port": 3389,"username": "bob",      "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 09:45:00", "source_ip": "10.0.0.52",     "destination_ip": "10.0.0.3",  "event_type": "Successful Login","protocol": "HTTP",  "port": 80,  "username": "charlie",  "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 11:00:00", "source_ip": "10.0.0.53",     "destination_ip": "10.0.0.4",  "event_type": "Successful Login","protocol": "HTTPS", "port": 443, "username": "diana",    "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 12:15:00", "source_ip": "10.0.0.54",     "destination_ip": "10.0.0.1",  "event_type": "Successful Login","protocol": "SSH",   "port": 22,  "username": "eve",      "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 13:20:00", "source_ip": "10.0.0.55",     "destination_ip": "10.0.0.5",  "event_type": "Successful Login","protocol": "SSH",   "port": 22,  "username": "frank",    "status": "SUCCESS", "country": "IN"},
    # ── Malware Detected ───────────────────────────────────────────────────
    {"timestamp": "2025-01-15 10:45:00", "source_ip": "10.0.0.77",     "destination_ip": "10.0.0.6",  "event_type": "Malware Detected","protocol": "HTTP",  "port": 80,  "username": "grace",    "status": "DETECTED","country": "IN"},
    {"timestamp": "2025-01-15 14:10:00", "source_ip": "10.0.0.78",     "destination_ip": "10.0.0.7",  "event_type": "Malware Detected","protocol": "HTTPS", "port": 443, "username": "henry",    "status": "DETECTED","country": "IN"},
    {"timestamp": "2025-01-15 16:30:00", "source_ip": "192.168.5.20",  "destination_ip": "10.0.0.9",  "event_type": "Malware Detected","protocol": "FTP",   "port": 21,  "username": "ivan",     "status": "DETECTED","country": "US"},
    # ── Privilege Escalation ───────────────────────────────────────────────
    {"timestamp": "2025-01-15 11:15:00", "source_ip": "10.0.0.60",     "destination_ip": "10.0.0.1",  "event_type": "Privilege Escalation","protocol":"SSH", "port": 22,  "username": "julia",    "status": "ALERT",   "country": "IN"},
    {"timestamp": "2025-01-15 15:20:00", "source_ip": "10.0.0.61",     "destination_ip": "10.0.0.2",  "event_type": "Privilege Escalation","protocol":"RDP", "port": 3389,"username": "kevin",    "status": "ALERT",   "country": "IN"},
    # ── Suspicious Traffic ─────────────────────────────────────────────────
    {"timestamp": "2025-01-15 12:00:00", "source_ip": "10.0.0.88",     "destination_ip": "8.8.8.8",   "event_type": "Suspicious Traffic","protocol":"DNS",  "port": 53,  "username": "-",        "status": "ALERT",   "country": "IN"},
    {"timestamp": "2025-01-15 13:45:00", "source_ip": "10.0.0.89",     "destination_ip": "1.1.1.1",   "event_type": "Suspicious Traffic","protocol":"DNS",  "port": 53,  "username": "-",        "status": "ALERT",   "country": "IN"},
    {"timestamp": "2025-01-15 17:00:00", "source_ip": "10.0.0.90",     "destination_ip": "10.0.0.20", "event_type": "Suspicious Traffic","protocol":"TCP",  "port": 4444,"username": "-",        "status": "ALERT",   "country": "IN"},
    # ── Normal Traffic ─────────────────────────────────────────────────────
    {"timestamp": "2025-01-15 08:20:00", "source_ip": "10.0.0.30",     "destination_ip": "10.0.0.100","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 08:45:00", "source_ip": "10.0.0.31",     "destination_ip": "10.0.0.100","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 09:30:00", "source_ip": "10.0.0.32",     "destination_ip": "10.0.0.100","event_type": "Normal Traffic",  "protocol": "HTTP",  "port": 80,  "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 10:15:00", "source_ip": "10.0.0.33",     "destination_ip": "10.0.0.101","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 10:30:00", "source_ip": "10.0.0.34",     "destination_ip": "10.0.0.101","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 11:05:00", "source_ip": "10.0.0.35",     "destination_ip": "10.0.0.102","event_type": "Normal Traffic",  "protocol": "DNS",   "port": 53,  "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 11:45:00", "source_ip": "10.0.0.36",     "destination_ip": "10.0.0.102","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 12:30:00", "source_ip": "10.0.0.37",     "destination_ip": "10.0.0.103","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 13:00:00", "source_ip": "10.0.0.38",     "destination_ip": "10.0.0.103","event_type": "Normal Traffic",  "protocol": "HTTP",  "port": 80,  "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 13:30:00", "source_ip": "10.0.0.39",     "destination_ip": "10.0.0.104","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 14:00:00", "source_ip": "10.0.0.40",     "destination_ip": "10.0.0.104","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 14:30:00", "source_ip": "10.0.0.41",     "destination_ip": "10.0.0.105","event_type": "Normal Traffic",  "protocol": "DNS",   "port": 53,  "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 15:00:00", "source_ip": "10.0.0.42",     "destination_ip": "10.0.0.105","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 15:30:00", "source_ip": "10.0.0.43",     "destination_ip": "10.0.0.106","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 16:00:00", "source_ip": "10.0.0.44",     "destination_ip": "10.0.0.106","event_type": "Normal Traffic",  "protocol": "HTTP",  "port": 80,  "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 16:30:00", "source_ip": "10.0.0.45",     "destination_ip": "10.0.0.107","event_type": "Normal Traffic",  "protocol": "HTTPS", "port": 443, "username": "-",        "status": "SUCCESS", "country": "IN"},
    {"timestamp": "2025-01-15 17:00:00", "source_ip": "10.0.0.46",     "destination_ip": "10.0.0.107","event_type": "Normal Traffic",  "protocol": "DNS",   "port": 53,  "username": "-",        "status": "SUCCESS", "country": "IN"},
    # ── Data Exfiltration ──────────────────────────────────────────────────
    {"timestamp": "2025-01-15 15:45:00", "source_ip": "10.0.0.75",     "destination_ip": "45.33.32.156","event_type":"Data Exfiltration","protocol":"FTP",  "port": 21,  "username": "lena",     "status": "ALERT",   "country": "IN"},
    {"timestamp": "2025-01-15 16:00:00", "source_ip": "10.0.0.75",     "destination_ip": "45.33.32.156","event_type":"Data Exfiltration","protocol":"FTP",  "port": 21,  "username": "lena",     "status": "ALERT",   "country": "IN"},
    # ── More Failed Logins (different IPs) ─────────────────────────────────
    {"timestamp": "2025-01-15 14:20:00", "source_ip": "172.16.5.10",   "destination_ip": "10.0.0.3",  "event_type": "Failed Login",    "protocol": "RDP",   "port": 3389,"username": "administrator","status":"FAILURE","country": "UA"},
    {"timestamp": "2025-01-15 14:21:00", "source_ip": "172.16.5.10",   "destination_ip": "10.0.0.3",  "event_type": "Failed Login",    "protocol": "RDP",   "port": 3389,"username": "administrator","status":"FAILURE","country": "UA"},
    {"timestamp": "2025-01-15 14:22:00", "source_ip": "172.16.5.10",   "destination_ip": "10.0.0.3",  "event_type": "Failed Login",    "protocol": "RDP",   "port": 3389,"username": "administrator","status":"FAILURE","country": "UA"},
    {"timestamp": "2025-01-15 14:23:00", "source_ip": "172.16.5.10",   "destination_ip": "10.0.0.3",  "event_type": "Failed Login",    "protocol": "RDP",   "port": 3389,"username": "guest",     "status": "FAILURE","country": "UA"},
    {"timestamp": "2025-01-15 14:24:00", "source_ip": "172.16.5.10",   "destination_ip": "10.0.0.3",  "event_type": "Failed Login",    "protocol": "RDP",   "port": 3389,"username": "guest",     "status": "FAILURE","country": "UA"},
    {"timestamp": "2025-01-15 17:30:00", "source_ip": "100.64.0.5",    "destination_ip": "10.0.0.4",  "event_type": "Failed Login",    "protocol": "HTTP",  "port": 80,  "username": "webadmin", "status": "FAILURE","country": "US"},
    {"timestamp": "2025-01-15 17:31:00", "source_ip": "100.64.0.5",    "destination_ip": "10.0.0.4",  "event_type": "Failed Login",    "protocol": "HTTP",  "port": 80,  "username": "webadmin", "status": "FAILURE","country": "US"},
    {"timestamp": "2025-01-15 17:32:00", "source_ip": "100.64.0.5",    "destination_ip": "10.0.0.4",  "event_type": "Failed Login",    "protocol": "HTTP",  "port": 80,  "username": "webadmin", "status": "FAILURE","country": "US"},
]

# ──────────────────────────────────────────────
# 2.  DATA PROCESSING
# ──────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5   # failed login attempts from same IP to flag as brute force

def load_data() -> pd.DataFrame:
    df = pd.DataFrame(RAW_LOGS)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour"] = df["timestamp"].dt.floor("h")
    df["date"] = df["timestamp"].dt.date
    df["severity"] = df.apply(assign_severity, axis=1)
    return df

def assign_severity(row: pd.Series) -> str:
    """Rule-based severity assignment for each event."""
    event = row["event_type"]
    if event in ("Data Exfiltration", "Privilege Escalation"):
        return "Critical"
    if event == "Brute Force":
        return "High"
    if event in ("Malware Detected", "Port Scan"):
        return "High"
    if event == "Failed Login":
        return "Medium"
    if event == "Firewall Block":
        return "Medium"
    if event == "Suspicious Traffic":
        return "Medium"
    if event == "Successful Login":
        return "Low"
    return "Low"   # Normal Traffic

def detect_brute_force(df: pd.DataFrame, threshold: int = BRUTE_FORCE_THRESHOLD) -> pd.DataFrame:
    """Return a summary of IPs that have exceeded the failed-login threshold."""
    failed = df[df["event_type"].isin(["Failed Login", "Brute Force"])]
    counts = (
        failed.groupby("source_ip")
        .agg(attempt_count=("event_type", "count"),
             first_seen=("timestamp", "min"),
             last_seen=("timestamp", "max"),
             destination=("destination_ip", "first"),
             country=("country", "first"))
        .reset_index()
    )
    return counts[counts["attempt_count"] >= threshold].sort_values("attempt_count", ascending=False)

# ──────────────────────────────────────────────
# 3.  STREAMLIT PAGE CONFIG
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="Mini SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────
# 4.  LOAD DATA
# ──────────────────────────────────────────────
df_full = load_data()

# ──────────────────────────────────────────────
# 5.  SIDEBAR — FILTERS
# ──────────────────────────────────────────────
st.sidebar.title("🔍 Filters")
st.sidebar.markdown("---")

# Severity filter
all_severities = ["Critical", "High", "Medium", "Low"]
selected_severities = st.sidebar.multiselect(
    "Severity Level",
    options=all_severities,
    default=all_severities,
)

# Event type filter
all_events = sorted(df_full["event_type"].unique().tolist())
selected_events = st.sidebar.multiselect(
    "Event Type",
    options=all_events,
    default=all_events,
)

# Source IP filter
all_ips = sorted(df_full["source_ip"].unique().tolist())
selected_ips = st.sidebar.multiselect(
    "Source IP",
    options=all_ips,
    default=all_ips,
)

st.sidebar.markdown("---")
brute_threshold = st.sidebar.slider(
    "Brute-Force Threshold (failed logins)",
    min_value=2,
    max_value=15,
    value=BRUTE_FORCE_THRESHOLD,
    help="Number of failed login attempts from one IP to trigger a brute-force alert.",
)

# ──────────────────────────────────────────────
# 6.  APPLY FILTERS
# ──────────────────────────────────────────────
df = df_full[
    df_full["severity"].isin(selected_severities) &
    df_full["event_type"].isin(selected_events) &
    df_full["source_ip"].isin(selected_ips)
].copy()

# ──────────────────────────────────────────────
# 7.  HEADER
# ──────────────────────────────────────────────
st.title("🛡️ Mini SOC Dashboard")
st.markdown("**Security Event Monitoring and Alert Analysis System** — IBM SkillsBuild Cyber Security 2026")
st.markdown("---")

# ──────────────────────────────────────────────
# 8.  KPI CARDS
# ──────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

total_events   = len(df)
critical_count = len(df[df["severity"] == "Critical"])
high_count     = len(df[df["severity"] == "High"])
medium_count   = len(df[df["severity"] == "Medium"])
failed_logins  = len(df[df["event_type"].isin(["Failed Login", "Brute Force"])])

col1.metric("Total Events",       total_events)
col2.metric("🔴 Critical",        critical_count)
col3.metric("🟠 High",            high_count)
col4.metric("🟡 Medium",          medium_count)
col5.metric("🔑 Failed Logins",   failed_logins)

st.markdown("---")

# ──────────────────────────────────────────────
# 9.  BRUTE-FORCE ALERTS
# ──────────────────────────────────────────────
st.subheader("🚨 Brute-Force / Repeated Failed Login Alerts")

bf_alerts = detect_brute_force(df, threshold=brute_threshold)
if not bf_alerts.empty:
    st.error(f"⚠️  {len(bf_alerts)} IP(s) exceeded the failed-login threshold of **{brute_threshold}** attempts.")
    st.dataframe(
        bf_alerts.rename(columns={
            "source_ip":      "Source IP",
            "attempt_count":  "Failed Attempts",
            "first_seen":     "First Seen",
            "last_seen":      "Last Seen",
            "destination":    "Target IP",
            "country":        "Country",
        }),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.success(f"✅  No IP has exceeded the threshold of {brute_threshold} failed login attempts.")

st.markdown("---")

# ──────────────────────────────────────────────
# 10.  SEVERITY-BASED ALERT TABLE
# ──────────────────────────────────────────────
st.subheader("📋 Security Event Log")

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
df_display = df.sort_values(
    by=["severity", "timestamp"],
    key=lambda col: col.map(SEVERITY_ORDER) if col.name == "severity" else col,
)

# Colour-coded severity column via styling
def colour_severity(val: str) -> str:
    colours = {
        "Critical": "background-color:#ff4b4b; color:white; font-weight:bold",
        "High":     "background-color:#ff914d; color:white; font-weight:bold",
        "Medium":   "background-color:#ffd166; color:black; font-weight:bold",
        "Low":      "background-color:#06d6a0; color:black",
    }
    return colours.get(val, "")

display_cols = ["timestamp", "source_ip", "destination_ip", "event_type",
                "protocol", "port", "username", "status", "country", "severity"]

styled_df = (
    df_display[display_cols]
   .style.map(colour_severity, subset=["severity"])
)

st.dataframe(styled_df, use_container_width=True, hide_index=True)
st.markdown("---")

# ──────────────────────────────────────────────
# 11.  CHARTS
# ──────────────────────────────────────────────
st.subheader("📊 Visual Analysis")

chart_col1, chart_col2 = st.columns(2)

# ── Chart 1: Event Type Distribution (Bar) ──────────────────────────────
with chart_col1:
    event_counts = df["event_type"].value_counts().reset_index()
    event_counts.columns = ["Event Type", "Count"]
    fig_bar = px.bar(
        event_counts,
        x="Event Type",
        y="Count",
        color="Event Type",
        title="Event Type Distribution",
        text="Count",
    )
    fig_bar.update_traces(textposition="outside")
    fig_bar.update_layout(showlegend=False, xaxis_tickangle=-30)
    st.plotly_chart(fig_bar, use_container_width=True)

# ── Chart 2: Severity Breakdown (Pie) ────────────────────────────────────
with chart_col2:
    severity_counts = df["severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]
    severity_colour_map = {
        "Critical": "#ff4b4b",
        "High":     "#ff914d",
        "Medium":   "#ffd166",
        "Low":      "#06d6a0",
    }
    fig_pie = px.pie(
        severity_counts,
        names="Severity",
        values="Count",
        title="Severity Breakdown",
        color="Severity",
        color_discrete_map=severity_colour_map,
    )
    fig_pie.update_traces(textinfo="percent+label")
    st.plotly_chart(fig_pie, use_container_width=True)

# ── Chart 3: Events Over Time (Line) ─────────────────────────────────────
hourly_counts = (
    df.groupby(["hour", "severity"])
    .size()
    .reset_index(name="count")
)
fig_line = px.line(
    hourly_counts,
    x="hour",
    y="count",
    color="severity",
    markers=True,
    title="Security Events Over Time (Hourly) — by Severity",
    labels={"hour": "Hour", "count": "Event Count", "severity": "Severity"},
    color_discrete_map={
        "Critical": "#ff4b4b",
        "High":     "#ff914d",
        "Medium":   "#ffd166",
        "Low":      "#06d6a0",
    },
)
fig_line.update_layout(xaxis_title="Time", yaxis_title="Number of Events")
st.plotly_chart(fig_line, use_container_width=True)

# ── Chart 4: Top Source IPs by Event Count (Horizontal Bar) ──────────────
top_ips = df["source_ip"].value_counts().head(10).reset_index()
top_ips.columns = ["Source IP", "Count"]
fig_ip = px.bar(
    top_ips,
    x="Count",
    y="Source IP",
    orientation="h",
    title="Top 10 Source IPs by Event Count",
    text="Count",
    color="Count",
    color_continuous_scale="Reds",
)
fig_ip.update_traces(textposition="outside")
fig_ip.update_layout(yaxis={"categoryorder": "total ascending"}, coloraxis_showscale=False)
st.plotly_chart(fig_ip, use_container_width=True)

st.markdown("---")

# ──────────────────────────────────────────────
# 12.  CSV EXPORT
# ──────────────────────────────────────────────
st.subheader("📥 Export Filtered Data")

export_df = df_display[display_cols].copy()
export_df["timestamp"] = export_df["timestamp"].astype(str)

csv_buffer = io.StringIO()
export_df.to_csv(csv_buffer, index=False)
csv_bytes = csv_buffer.getvalue().encode("utf-8")

st.download_button(
    label="⬇️  Download Filtered Events as CSV",
    data=csv_bytes,
    file_name="soc_filtered_events.csv",
    mime="text/csv",
)

st.markdown("---")
st.caption("Mini SOC Dashboard · IBM SkillsBuild Cyber Security 2026 · Built with Python, Streamlit, Pandas & Plotly")
