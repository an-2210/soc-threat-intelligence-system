"""Streamlit SOC Dashboard - Part 3.

Features:
- Live feed of ingested security alerts (distinguishing Live ML vs. Synthetic Test data)
- Telemetry charts: attack label breakdown, top attacker IPs, port distribution
- Incident Correlation Engine grouping alerts into actionable campaigns
- Interactive Security Check (Mode A: IP Analysis, Mode B: Submit Alert, Mode C: Log Analyzer)
- Deterministic SOC Incident Reports & Executive PDF Export via ReportLab
- In-dashboard mock alert dispatcher and multi-stage campaign triggers
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

# Setup python path to import part3 modules
ROOT_DIR = Path(__file__).parent.parent
sys.path.append(str(ROOT_DIR))

from part3.correlation import correlate_alerts
from part3.db import clear_alerts, get_alerts, get_stats, init_db
from part3.mock_alerts import generate_alert
from part3.report_generator import export_report_to_pdf, generate_incident_report
from part3.security_check import (
    analyze_ip_local,
    classify_ip_network,
    parse_network_log,
    submit_structured_alert,
)

st.set_page_config(
    page_title="Dell SOC Dashboard | NIDS-CTI Part 3",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize DB if needed
init_db()

# Custom CSS for dark/clean SOC styling
st.markdown(
    """
    <style>
    .metric-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 14px;
        border: 1px solid #334155;
    }
    .badge-critical { background-color: #ef4444; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
    .badge-high { background-color: #f97316; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
    .badge-medium { background-color: #eab308; color: black; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
    .badge-low { background-color: #22c55e; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
    .badge-synth { background-color: #64748b; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; }
    .badge-live { background-color: #0284c7; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; }
    .sec-card {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        padding: 16px;
        border-radius: 8px;
        margin-bottom: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Sidebar controls
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("SOC Control Panel")
st.sidebar.caption("NIDS & CTI Platform - Part 3")

# Check FastAPI status
api_online = False
try:
    health_resp = requests.get("http://127.0.0.1:8000/health", timeout=1)
    api_online = health_resp.status_code == 200
except Exception:
    api_online = False

if api_online:
    st.sidebar.success("🟢 Ingestion Server Active (:8000)")
else:
    st.sidebar.warning("🟡 Ingestion Server Offline (using direct DB)")

st.sidebar.divider()

# Security Check Shortcut
st.sidebar.subheader("Security Operations")
st.sidebar.info("💡 Use the **🔍 Interactive Security Check** tab below to investigate IPs, ingest alerts, or parse raw logs.")

st.sidebar.divider()

# Demo simulation controls
st.sidebar.subheader("Telemetry Simulation Controls")
sim_count = st.sidebar.slider("Mock Alert Count", min_value=5, max_value=50, value=15, step=5)
col_sim1, col_sim2 = st.sidebar.columns(2)

if col_sim1.button("Inject Random Alerts"):
    with st.spinner("Generating alerts..."):
        for _ in range(sim_count):
            alt = generate_alert()
            try:
                requests.post("http://127.0.0.1:8000/alert", json=alt, timeout=1)
            except Exception:
                from part3.db import insert_alert
                insert_alert(alt)
    st.sidebar.success(f"Dispatched {sim_count} mock alerts!")
    st.rerun()

if col_sim2.button("Run APT Campaign"):
    with st.spinner("Simulating multi-stage APT attack..."):
        camp_ip = "203.0.113.11"
        stages = ["portscan"] * 4 + ["bruteforce"] * 4 + ["anomaly"] * 2 + ["dos"] * 3
        for s in stages:
            alt = generate_alert(s, attacker_ip=camp_ip)
            try:
                requests.post("http://127.0.0.1:8000/alert", json=alt, timeout=1)
            except Exception:
                from part3.db import insert_alert
                insert_alert(alt)
    st.sidebar.success("Dispatched APT Campaign!")
    st.rerun()

st.sidebar.divider()

# Incident Analysis Configuration
st.sidebar.subheader("Incident Analysis Settings")
correlation_window = st.sidebar.slider("Correlation Window (Minutes)", min_value=5, max_value=60, value=15, step=5)

st.sidebar.divider()
st.sidebar.subheader("Maintenance")
confirm_purge = st.sidebar.checkbox("Confirm database reset", value=False)
if st.sidebar.button("Purge All Alerts", type="secondary"):
    if confirm_purge:
        deleted = clear_alerts()
        st.sidebar.info(f"Cleared {deleted} alerts from database.")
        st.rerun()
    else:
        st.sidebar.warning("Please check 'Confirm database reset' first.")

# Main Dashboard View
st.title("🛡️ Dell Security Operations Center (SOC)")
st.caption("Real-Time Telemetry Ingestion, Flow Correlation, Interactive Security Check & Incident Triage")

# Fetch data
stats = get_stats()
all_alerts = get_alerts(limit=500)
incidents = correlate_alerts(all_alerts, time_window_minutes=correlation_window)

# KPI row
col1, col2, col3, col4, col5 = st.columns(5)
total_count = stats.get("total_alerts", 0)
active_incidents = len(incidents)
critical_incidents = sum(1 for i in incidents if i["severity"] == "CRITICAL")
live_count = stats.get("live_count", 0)
synthetic_count = stats.get("synthetic_count", 0)

col1.metric("Total Alerts", total_count)
col2.metric("Correlated Incidents", active_incidents, delta=f"{critical_incidents} Critical" if critical_incidents else None, delta_color="inverse")
col3.metric("Live ML Detections", live_count, help="Real flow alerts from Part 1 & Part 2 models")
col4.metric("Synthetic Test Alerts", synthetic_count, help="Dispatched by mock simulation tools")
col5.metric("Unique Threat Actors", len(stats.get("top_ips", [])))

st.divider()

# Telemetry Visualizations
if total_count > 0:
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("📊 Attack Vector Distribution")
        labels_df = pd.DataFrame(
            list(stats["label_counts"].items()),
            columns=["Attack Vector", "Alert Count"],
        ).sort_values(by="Alert Count", ascending=False)
        st.bar_chart(labels_df.set_index("Attack Vector"), color="#0284c7")

    with chart_col2:
        st.subheader("🎯 Top Attacker Source IPs")
        if stats["top_ips"]:
            top_ips_df = pd.DataFrame(stats["top_ips"])
            st.bar_chart(top_ips_df.set_index("src_ip")["count"], color="#f97316")
else:
    st.info("No alert telemetry recorded yet. Use the sidebar controls to inject test alerts or run Part 1 / Part 2 detectors.")

st.divider()

# Tabbed Interface
tab_check, tab_incidents, tab_feed, tab_reports = st.tabs([
    "🔍 Interactive Security Check",
    "🚨 Correlated Security Incidents",
    "📡 Live Alert Telemetry Feed",
    "📋 Incident Reports & PDF Export",
])

# ----------------- TAB 1: SECURITY CHECK -----------------
with tab_check:
    st.subheader("🔍 Interactive Security Check & Local Incident Analysis")
    st.write(
        "Investigate suspicious IP entities against local telemetry, submit verified flow alerts into the ingestion receiver, "
        "or extract actionable IOCs from raw network logs and events."
    )

    check_mode = st.radio(
        "Select Investigation Mode:",
        ["Mode A: Analyze an IP Address", "Mode B: Submit Structured Security Alert", "Mode C: Analyze Network Log or Event"],
        horizontal=True,
    )

    # ---------- MODE A: ANALYZE IP ADDRESS ----------
    if check_mode == "Mode A: Analyze an IP Address":
        st.markdown("#### Mode A: Host Telemetry & Network Classification")
        st.caption(
            "Investigates an IP address strictly against local SOC telemetry and network facts. "
            "Note: An IP address alone cannot establish whether a host is malicious without telemetry or reputation feeds. "
            "This tool evaluates local observations and RFC network definitions without fabricating external internet lookups."
        )

        col_a1, col_a2 = st.columns(2)
        target_ip_input = col_a1.text_input("Source IP Address to Investigate *", value="203.0.113.11", help="Enter IPv4 or IPv6 address")
        target_dst_ip = col_a2.text_input("Target Internal IP (Optional Filter)", value="", placeholder="e.g. 192.168.10.5")

        col_a3, col_a4, col_a5 = st.columns(3)
        target_dst_port = col_a3.number_input("Target Port (Optional Filter)", min_value=0, max_value=65535, value=0, help="0 means any port")
        target_proto = col_a4.selectbox("Protocol (Optional)", ["ANY", "TCP", "UDP", "ICMP"])
        target_ctx = col_a5.text_input("Investigation Reason / Context (Optional)", placeholder="e.g. Spike in failed connections")

        if st.button("🔎 Run IP Security Investigation", type="primary"):
            res = analyze_ip_local(
                src_ip=target_ip_input.strip(),
                dst_ip=target_dst_ip.strip() or None,
                dst_port=int(target_dst_port) if target_dst_port > 0 else None,
                protocol=target_proto if target_proto != "ANY" else None,
                context=target_ctx.strip() or None,
            )

            if not res.get("success", False):
                st.error(res.get("error", "Investigation failed due to an unknown backend error."))
                st.session_state.pop("ip_analysis_result", None)
            else:
                st.session_state["ip_analysis_result"] = res

        if "ip_analysis_result" in st.session_state:
            res = st.session_state["ip_analysis_result"]
            if not isinstance(res, dict) or not res.get("success", False):
                st.session_state.pop("ip_analysis_result", None)
            else:
                net_info = res.get("network_info")
                if not isinstance(net_info, dict):
                    st.error("Invalid investigation response: Missing network classification metadata.")
                else:
                    src_ip = res.get("src_ip", target_ip_input.strip())
                    st.markdown("---")
                    st.markdown(f"### Investigation Report: `{src_ip}`")

                    # Extract total alerts using either total_alerts_for_ip or total_alerts_found
                    total_alerts = res.get("total_alerts_for_ip")
                    if total_alerts is None:
                        total_alerts = res.get("total_alerts_found")

                    if total_alerts is not None:
                        total_alerts_display = f"{total_alerts} flows"
                    else:
                        total_alerts_display = "Data Unavailable"

                    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                    col_m1.metric("Network Scope", net_info.get("category", "Unknown Scope"))
                    col_m2.metric("Total Sourced Alerts", total_alerts_display)

                    filter_applied = res.get("filter_applied", False)
                    target_filter_matches = res.get("target_filter_matches", res.get("target_hits"))
                    if filter_applied:
                        if target_filter_matches is not None:
                            col_m3.metric("Target Filter Matches", f"{target_filter_matches} flows")
                        else:
                            col_m3.metric("Target Filter Matches", "Data Unavailable")
                    else:
                        col_m3.metric("Target Filter Matches", "All (No Filter Active)")

                    corr_id = res.get("correlated_incident_id")
                    corr_score = res.get("correlated_risk_score")
                    corr_sev = res.get("correlated_severity")
                    if corr_id and corr_score is not None:
                        col_m4.metric("Correlated Incident Risk", f"{corr_score:.1f}/10 [{corr_sev or 'UNKNOWN'}]")
                    else:
                        col_m4.metric("Correlated Incident Risk", "None (No Incident)")

                    classification_note = net_info.get("classification_note", "No classification standard note available.")
                    st.caption(f"**Classification Standard:** {classification_note}")

                    soc_finding = res.get("soc_finding", res.get("assessment", "No SOC finding recorded."))
                    st.markdown(f"**SOC Finding:** {soc_finding}")

                    has_history = res.get("has_local_history", (total_alerts is not None and total_alerts > 0))
                    if has_history:
                        st.markdown("#### Risk Assessment & Incident Reconciliation")
                        r_col1, r_col2 = st.columns(2)
                        with r_col1:
                            st.markdown("**Correlated Incident Engine (Multi-Flow Session)**")
                            if corr_id:
                                st.write(f"- **Incident ID:** `{corr_id}`")
                                score_str = f"{corr_score:.1f}/10" if corr_score is not None else "N/A"
                                st.write(f"- **Assigned Severity:** `{corr_sev or 'UNKNOWN'}` (Deterministic Score: `{score_str}`)")
                                st.write(f"- **Verified Progression:** {res.get('correlated_threat_pattern', 'N/A')}")
                                st.caption(f"**Scoring Rationale:** {res.get('correlated_rationale', 'N/A')}")
                            else:
                                st.write("- No active correlated incident session formed for this IP.")
                        with r_col2:
                            st.markdown("**Host Telemetry Profile & Confidence Context**")
                            host_profile = res.get("host_threat_profile", res.get("local_risk_level", "Unknown Profile"))
                            st.write(f"- **Host Threat Profile:** `{host_profile}`")
                            peak_conf = res.get("peak_confidence", res.get("max_confidence"))
                            if peak_conf is not None:
                                st.write(f"- **Peak Model Confidence:** `{peak_conf * 100:.1f}%`")
                            else:
                                st.write("- **Peak Model Confidence:** `N/A`")
                            st.write(f"- **First Seen:** `{res.get('first_seen', 'N/A')}`")
                            st.write(f"- **Last Seen:** `{res.get('last_seen', 'N/A')}`")
                            st.caption("**Interpretation Note:** Model confidence represents classifier certainty on flow features, not a ground-truth probability that the host is actively malicious.")

                        st.markdown("#### Targeted Infrastructure Telemetry")
                        t_col1, t_col2 = st.columns(2)
                        dst_breakdown = res.get("destination_breakdown")
                        if dst_breakdown is None and res.get("target_ips_affected"):
                            dst_breakdown = {ip: 1 for ip in res.get("target_ips_affected")}
                        dst_breakdown = dst_breakdown or {}

                        port_breakdown = res.get("port_breakdown")
                        if port_breakdown is None and res.get("ports_targeted"):
                            port_breakdown = {port: 1 for port in res.get("ports_targeted")}
                        port_breakdown = port_breakdown or {}

                        with t_col1:
                            st.markdown("**Internal Hosts Targeted (dst_ip)**")
                            if dst_breakdown:
                                for h, cnt in dst_breakdown.items():
                                    st.write(f"- `{h}`: **{cnt}** alert flow(s)")
                            else:
                                st.write("- None recorded")
                        with t_col2:
                            st.markdown("**Destination Ports Targeted (dst_port)**")
                            if port_breakdown:
                                for p, cnt in port_breakdown.items():
                                    st.write(f"- Port `{p}`: **{cnt}** alert flow(s)")
                            else:
                                st.write("- None recorded")

                        if filter_applied and res.get("filter_summary"):
                            st.info(f"🔍 **Applied Target Filter:** {res['filter_summary']}")

                        recs = res.get("recommendations", [])
                        if recs:
                            st.markdown("#### Recommended SOC Actions")
                            for rec in recs:
                                st.write(f"- {rec}")

                        samples = res.get("sample_alerts", [])
                        if samples:
                            st.markdown("#### Recent Telemetry Samples from this Host")
                            samples_df = pd.DataFrame([
                                {
                                    "ID": a.get("id"),
                                    "Timestamp": a.get("timestamp"),
                                    "Target IP": a.get("dst_ip"),
                                    "Port": a.get("dst_port"),
                                    "Classification": a.get("label"),
                                    "Confidence": a.get("confidence"),
                                    "Source": a.get("source"),
                                }
                                for a in samples
                            ])
                            st.dataframe(samples_df, use_container_width=True)
                    else:
                        st.info(
                            f"No prior incident alerts found for `{src_ip}` in local SOC storage. "
                            "This host has not triggered any intrusion detection rules in the active database."
                        )

    # ---------- MODE B: SUBMIT STRUCTURED ALERT ----------
    elif check_mode == "Mode B: Submit Structured Security Alert":
        st.markdown("#### Mode B: Ingest Custom Security Flow Alert")
        st.caption("Submit a verified or observed network alert directly to the FastAPI ingestion receiver (:8000).")

        col_b1, col_b2, col_b3 = st.columns(3)
        b_src_ip = col_b1.text_input("Source IP Address *", value="198.51.100.77")
        b_dst_ip = col_b2.text_input("Destination Target IP *", value="192.168.10.5")
        b_dst_port = col_b3.number_input("Destination Port *", min_value=0, max_value=65535, value=22)

        col_b4, col_b5, col_b6 = st.columns(3)
        b_label = col_b4.selectbox("Threat Classification *", ["BruteForce", "DoS", "PortScan", "Anomaly"])
        b_conf = col_b5.slider("Detection Confidence *", min_value=0.0, max_value=1.0, value=0.98, step=0.01)
        b_source = col_b6.text_input("Ingestion Source ID", value="security_check_analyst")

        b_features_str = st.text_area(
            "Top Feature Metrics (JSON Format, Optional)",
            value='{"Destination Port": 22.0, "Init_Win_bytes_forward": 29200.0, "PSH Flag Count": 1.0}',
            height=70,
        )

        b_synthetic = st.checkbox("Mark as Synthetic Evaluation Alert", value=False)

        if st.button("📤 Submit Alert to Ingestion Receiver", type="primary"):
            try:
                feats = json.loads(b_features_str.strip()) if b_features_str.strip() else {}
            except Exception:
                feats = {"raw_metrics": b_features_str}

            payload = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source": b_source.strip() or "security_check",
                "src_ip": b_src_ip.strip(),
                "dst_ip": b_dst_ip.strip(),
                "dst_port": int(b_dst_port),
                "label": b_label,
                "confidence": float(b_conf),
                "top_features": feats,
                "is_synthetic": b_synthetic,
            }

            res = submit_structured_alert(payload)
            if res["success"]:
                dup_str = " (Duplicate detected: existing ID returned)" if res.get("is_duplicate") else ""
                st.success(f"Alert successfully ingested! Alert ID: #{res['alert_id']}{dup_str}")
                time.sleep(0.5)
                st.rerun()
            else:
                st.error(f"Submission failed: {res.get('error')}")

    # ---------- MODE C: ANALYZE RAW NETWORK LOG ----------
    elif check_mode == "Mode C: Analyze Network Log or Event":
        st.markdown("#### Mode C: Raw Network Log & Event Analyzer")
        st.caption("Paste a suspicious log string (syslog, web access log, firewall drop, or flow record) for IOC extraction and classification.")

        with st.expander("📋 View Sample Log Entries for Testing"):
            st.code("Oct 25 22:15:00 auth sshd[1234]: Failed password for root from 203.0.113.11 port 54321 ssh2", language="text")
            st.code("DROP IN=eth0 SRC=192.0.2.140 DST=192.168.10.5 PROTO=TCP SPT=49152 DPT=80 FLAGS=SYN", language="text")
            st.code("198.51.100.45 - - [25/Oct/2026:22:15:30 +0000] \"GET /admin/config.php HTTP/1.1\" 401 1234", language="text")

        sample_log = st.text_area(
            "Paste Log Entry / Network Event:",
            height=100,
            value="Oct 25 22:15:00 auth sshd[1234]: Failed password for root from 203.0.113.11 port 54321 ssh2",
        )

        if st.button("🔬 Parse and Analyze Log Entry", type="primary"):
            parsed = parse_network_log(sample_log)
            if not parsed["success"]:
                st.error(parsed["error"])
            else:
                st.session_state["parsed_log"] = parsed

        if "parsed_log" in st.session_state:
            p = st.session_state["parsed_log"]
            st.markdown("---")
            st.markdown("#### Extracted Indicators & Inferred Threat")

            col_p1, col_p2, col_p3 = st.columns(3)
            col_p1.metric("Identified Attacker IP", p["extracted_src_ip"])
            col_p2.metric("Target Endpoint", f"{p['extracted_dst_ip']}:{p['extracted_dst_port']}")
            col_p3.metric("Inferred Vector", p["inferred_label"], delta=f"{p['estimated_confidence']*100:.0f}% confidence")

            st.write("**Extracted Evidence Indicators:**")
            for ind in p["indicators"]:
                st.write(f"- {ind}")

            with st.expander("View Normalized Alert Payload"):
                st.json(p["suggested_payload"])

            if st.button("📥 Ingest Extracted Alert into SOC Database"):
                res = submit_structured_alert(p["suggested_payload"])
                if res["success"]:
                    st.success(f"Alert ingested from parsed log! Alert ID: #{res['alert_id']}")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error(f"Ingestion failed: {res.get('error')}")


# ----------------- TAB 2: INCIDENTS -----------------
with tab_incidents:
    st.subheader("Correlated Multi-Flow Security Incidents")
    st.write(
        "Alerts are correlated across time windows to detect multi-stage intrusion campaigns "
        "(Reconnaissance $\\to$ Credential Attack $\\to$ DoS $\\to$ Statistical Anomaly)."
    )

    if not incidents:
        st.warning("No correlated incidents detected.")
    else:
        inc_rows = []
        for inc in incidents:
            type_badge = "🧪 Synthetic" if inc.get("is_synthetic") else ("🔀 Mixed" if inc.get("is_mixed") else "⚡ Live")
            inc_rows.append({
                "Incident ID": inc["incident_id"],
                "Severity": inc["severity"],
                "Risk Score": f"{inc['risk_score']:.1f}/10",
                "Attacker IP": inc["src_ip"],
                "Type": type_badge,
                "Progression / Threat Pattern": inc["threat_pattern"],
                "Target Ports": ", ".join(str(p) for p in inc["target_ports"]),
                "Alerts": inc["alert_count"],
                "Max Conf": f"{inc['max_confidence']*100:.1f}%",
                "Last Seen": inc["last_seen"],
            })

        df_inc = pd.DataFrame(inc_rows)
        st.dataframe(df_inc, use_container_width=True)

        st.markdown("#### Incident Investigation & Triage")
        selected_inc_id = st.selectbox(
            "Select Incident to Inspect:",
            options=[inc["incident_id"] for inc in incidents],
            format_func=lambda x: f"{x} - {next((i['src_ip'] + ' [' + i['severity'] + ' - ' + str(i['risk_score']) + '/10]' for i in incidents if i['incident_id'] == x), '')}",
        )

        selected_inc = next((i for i in incidents if i["incident_id"] == selected_inc_id), None)
        if selected_inc:
            subcol1, subcol2, subcol3 = st.columns(3)
            subcol1.write(f"**Attacker:** `{selected_inc['src_ip']}`")
            subcol2.write(f"**Severity:** `{selected_inc['severity']}` (Risk: `{selected_inc['risk_score']}/10`)")
            subcol3.write(f"**Duration:** `{selected_inc['duration_seconds']}s` ({selected_inc['alert_count']} alerts)")

            st.write(f"**Verified Progression:** {selected_inc['threat_pattern']}")
            st.write(f"**Vector Breakdown:** {json.dumps(selected_inc['label_breakdown'])}")
            st.caption(f"**Scoring Rationale:** {selected_inc['scoring_rationale']}")

            with st.expander("Inspect Raw Telemetry in Incident"):
                st.json(selected_inc["alerts"])


# ----------------- TAB 3: LIVE FEED -----------------
with tab_feed:
    st.subheader("Raw Ingested Alert Stream")

    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
    filter_label = filter_col1.selectbox("Filter by Vector", ["All"] + list(stats.get("label_counts", {}).keys()))
    filter_source = filter_col2.selectbox("Filter by Source", ["All"] + list(stats.get("source_counts", {}).keys()))
    filter_type = filter_col3.selectbox("Filter by Telemetry Type", ["All", "Live ML Only", "Synthetic Only"])
    search_ip = filter_col4.text_input("Search IP Address", "")

    filtered = all_alerts
    if filter_label != "All":
        filtered = [a for a in filtered if a.get("label") == filter_label]
    if filter_source != "All":
        filtered = [a for a in filtered if a.get("source") == filter_source]
    if filter_type == "Live ML Only":
        filtered = [a for a in filtered if not a.get("is_synthetic")]
    elif filter_type == "Synthetic Only":
        filtered = [a for a in filtered if a.get("is_synthetic")]
    if search_ip.strip():
        filtered = [a for a in filtered if search_ip.strip() in str(a.get("src_ip", "")) or search_ip.strip() in str(a.get("dst_ip", ""))]

    if filtered:
        feed_df = pd.DataFrame([
            {
                "ID": a["id"],
                "Timestamp": a["timestamp"],
                "Source": a["source"],
                "Type": "🧪 Synthetic" if a.get("is_synthetic") else "⚡ Live ML",
                "Attacker (Src IP)": a["src_ip"],
                "Target IP": a["dst_ip"],
                "Port": a["dst_port"],
                "Classification": a["label"],
                "Confidence": a["confidence"],
                "Top Features": json.dumps(a.get("top_features", {})),
            }
            for a in filtered
        ])
        st.dataframe(feed_df, use_container_width=True, height=450)
    else:
        st.info("No alerts match the active filter criteria.")


# ----------------- TAB 4: INCIDENT REPORTS & PDF -----------------
with tab_reports:
    st.subheader("📋 Incident Reports & PDF Export")
    st.write(
        "Generate automated incident reports analyzing attack narratives, technical evidence, "
        "deterministic severity ratings, and actionable containment playbooks."
    )

    if not incidents:
        st.info("Ingest alerts to enable incident reporting.")
    else:
        report_inc_id = st.selectbox(
            "Choose Target Incident for Investigation:",
            options=[inc["incident_id"] for inc in incidents],
            key="report_selector",
        )
        report_inc = next((i for i in incidents if i["incident_id"] == report_inc_id), incidents[0])

        if st.button("🚀 Generate Incident Report", type="primary"):
            with st.spinner("Synthesizing incident analysis and containment playbooks..."):
                report_data = generate_incident_report(report_inc)
                st.session_state[f"report_{report_inc_id}"] = report_data

        if f"report_{report_inc_id}" in st.session_state:
            rep = st.session_state[f"report_{report_inc_id}"]
            meta = rep.get("metadata", {})

            # Display engine source badge
            gen_name = meta.get("generator", "SOC Analyst Engine")
            if meta.get("fallback_used"):
                st.warning(f"Engine Notice: Fallback used ({meta.get('error_category')}). Switched to {gen_name}.")
            else:
                st.success(f"Report Generated via: {gen_name}")

            rep_col1, rep_col2 = st.columns([3, 1])
            with rep_col1:
                st.markdown("### 1. What Happened (Attack Narrative)")
                st.write(rep.get("what", "N/A"))

                st.markdown("### 2. Evidence & Telemetry")
                st.text(rep.get("evidence", "N/A"))

                st.markdown("### 3. Severity & Impact Assessment")
                st.write(rep.get("severity", "N/A"))

                st.markdown("### 4. Recommended Action & Containment Playbook")
                st.code(rep.get("action", "N/A"), language="bash")

            with rep_col2:
                st.markdown("### Export Artifact")
                st.write("Compile this verified SOC incident report into an executive PDF:")

                pdf_bytes = export_report_to_pdf(report_inc, rep)
                st.download_button(
                    label="📄 Download Incident Report (PDF)",
                    data=pdf_bytes,
                    file_name=f"Incident_Report_{report_inc_id}_{report_inc['src_ip']}.pdf",
                    mime="application/pdf",
                )

                st.markdown("---")
                st.write("**Incident Quick Profile**")
                st.write(f"- Attacker: `{report_inc['src_ip']}`")
                st.write(f"- Risk Score: `{report_inc.get('risk_score', 'N/A')}/10` ({report_inc['severity']})")
                st.write(f"- Targeted Ports: `{', '.join(str(p) for p in report_inc['target_ports'])}`")
                st.write(f"- Telemetry Type: `{'Synthetic Mock' if report_inc.get('is_synthetic') else 'Live ML'}`")
