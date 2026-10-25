"""Alert correlation and incident clustering engine for SOC.

Groups raw atomic alerts into structured security incidents based on:
- Attacker source IP
- Temporal clustering (configurable sliding time windows)
- Chronological sequence tracking (verifying actual timestamps before inferring attack order)
- Deterministic, evidence-based risk scoring (1.0 to 10.0) with documented rationale
- Synthetic vs. Live data tracking
"""
import math
from datetime import datetime
from typing import Any, Dict, List, Optional
import dateutil.parser


def parse_iso_time(ts_str: str) -> datetime:
    """Parse ISO 8601 timestamp string into a datetime object with timezone awareness."""
    try:
        return dateutil.parser.isoparse(ts_str)
    except Exception:
        clean_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_str)


def calculate_deterministic_risk_score(
    labels: List[str],
    alert_count: int,
    max_confidence: float,
    unique_target_ips: int,
    unique_target_ports: int,
) -> Dict[str, Any]:
    """Computes a transparent, deterministic risk score on a 1.0 - 10.0 scale.

    Factors:
    1. Base Vector Weight: Maximum intrinsic risk among observed attack types.
    2. Multi-Vector Synergy: Compounding risk when multiple techniques combine.
    3. Volume Escalation: Scaling for repeated flow volume.
    4. Target Scope: Breadth of internal infrastructure targeted.
    5. Model Confidence: Scaling factor based on detection certainty.
    """
    vector_weights = {
        "DoS": 3.5,
        "BruteForce": 3.0,
        "Anomaly": 2.0,
        "PortScan": 1.2,
    }
    unique_labels = set(labels)
    base_weight = max((vector_weights.get(lbl, 1.0) for lbl in unique_labels), default=1.0)

    # Multi-vector synergy
    synergy = 0.0
    if "PortScan" in unique_labels and "BruteForce" in unique_labels:
        synergy += 1.5
    if "BruteForce" in unique_labels and "DoS" in unique_labels:
        synergy += 1.5
    if "Anomaly" in unique_labels and len(unique_labels) > 1:
        synergy += 0.8

    # Volume escalation
    if alert_count >= 25:
        volume_mod = 1.8
    elif alert_count >= 10:
        volume_mod = 1.2
    elif alert_count >= 4:
        volume_mod = 0.6
    else:
        volume_mod = 0.0

    # Scope modifier
    scope_mod = 0.0
    if unique_target_ips > 1:
        scope_mod += 0.5
    if unique_target_ports > 3:
        scope_mod += 0.5

    raw_score = (base_weight + synergy + volume_mod + scope_mod) * (0.7 + 0.3 * max_confidence)
    risk_score = min(10.0, max(1.0, round(raw_score, 1)))

    if risk_score >= 8.0:
        severity = "CRITICAL"
    elif risk_score >= 6.0:
        severity = "HIGH"
    elif risk_score >= 3.5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    rationale = (
        f"Base vector weight {base_weight:.1f} ({', '.join(sorted(unique_labels))}), "
        f"multi-vector synergy +{synergy:.1f}, volume modifier +{volume_mod:.1f} ({alert_count} alerts), "
        f"scope modifier +{scope_mod:.1f} ({unique_target_ips} targets, {unique_target_ports} ports), "
        f"scaled by confidence {max_confidence:.2f} -> Risk Score {risk_score:.1f}/10."
    )

    return {
        "risk_score": risk_score,
        "severity": severity,
        "scoring_rationale": rationale,
    }


def analyze_chronological_sequence(session_alerts: List[Dict[str, Any]]) -> str:
    """Analyzes the verified chronological progression of alerts using actual timestamps."""
    first_seen_per_label: Dict[str, datetime] = {}
    for a in session_alerts:
        lbl = a["label"]
        try:
            ts = parse_iso_time(a["timestamp"])
        except Exception:
            continue
        if lbl not in first_seen_per_label or ts < first_seen_per_label[lbl]:
            first_seen_per_label[lbl] = ts

    unique_labels = set(a["label"] for a in session_alerts)

    if len(unique_labels) == 1:
        lbl = list(unique_labels)[0]
        if lbl == "PortScan":
            return "Isolated network scanning and port enumeration activity."
        elif lbl == "BruteForce":
            return "Repeated authentication / credential brute-forcing activity."
        elif lbl == "DoS":
            return "Denial of service traffic pattern matching known DoS signatures."
        elif lbl == "Anomaly":
            return "Statistical flow anomaly departing from normal baseline distribution."
        return f"Sustained alerts classified as {lbl}."

    # Check temporal ordering for multi-stage attacks
    has_scan = "PortScan" in first_seen_per_label
    has_brute = "BruteForce" in first_seen_per_label
    has_dos = "DoS" in first_seen_per_label
    has_anomaly = "Anomaly" in first_seen_per_label

    if has_scan and has_brute:
        t_scan = first_seen_per_label["PortScan"]
        t_brute = first_seen_per_label["BruteForce"]
        if t_scan < t_brute:
            return (
                f"Multi-stage intrusion: Port scanning observed at {t_scan.strftime('%H:%M:%S')} UTC "
                f"strictly preceded credential brute-force at {t_brute.strftime('%H:%M:%S')} UTC."
            )
        elif t_brute < t_scan:
            return (
                f"Multi-vector intrusion: Credential brute-force at {t_brute.strftime('%H:%M:%S')} UTC "
                f"preceded subsequent port scanning at {t_scan.strftime('%H:%M:%S')} UTC."
            )
        else:
            return "Concurrent reconnaissance and credential brute-force activity observed within the same second."

    if has_scan and has_dos:
        t_scan = first_seen_per_label["PortScan"]
        t_dos = first_seen_per_label["DoS"]
        if t_scan <= t_dos:
            return f"Probing followed by DoS disruption (Scan at {t_scan.strftime('%H:%M:%S')}, DoS at {t_dos.strftime('%H:%M:%S')})."
        return "Concurrent or interleaved PortScan and DoS alerts."

    if has_anomaly and (has_brute or has_dos or has_scan):
        return f"Hybrid detection: Supervised vectors ({', '.join(sorted(unique_labels - {'Anomaly'}))}) detected alongside deep learning flow anomalies."

    return f"Multi-vector traffic pattern encompassing: {', '.join(sorted(unique_labels))}."


def correlate_alerts(
    raw_alerts: List[Dict[str, Any]],
    time_window_minutes: int = 15,
) -> List[Dict[str, Any]]:
    """Cluster alerts into correlated incidents.

    Parameters:
    - raw_alerts: list of alert dictionaries from SQLite or API.
    - time_window_minutes: maximum gap between successive alerts from the same IP to be grouped.
    """
    if not raw_alerts:
        return []

    # Sort alerts chronologically
    sorted_alerts = []
    for a in raw_alerts:
        try:
            dt_obj = parse_iso_time(a["timestamp"])
            sorted_alerts.append((dt_obj, a))
        except Exception:
            continue

    sorted_alerts.sort(key=lambda x: x[0])

    # Group by source IP with sliding time-window
    ip_groups: Dict[str, List[List[Dict[str, Any]]]] = {}

    for dt_obj, alert in sorted_alerts:
        ip = alert.get("src_ip", "0.0.0.0")
        if ip not in ip_groups:
            ip_groups[ip] = [[alert]]
            continue

        last_session = ip_groups[ip][-1]
        try:
            last_alert_time = parse_iso_time(last_session[-1]["timestamp"])
            time_diff_secs = (dt_obj - last_alert_time).total_seconds()
        except Exception:
            time_diff_secs = 0

        if time_diff_secs <= (time_window_minutes * 60):
            last_session.append(alert)
        else:
            ip_groups[ip].append([alert])

    # Build incident records
    incidents = []
    inc_counter = 1

    for ip, sessions in ip_groups.items():
        for session in sessions:
            first_ts = session[0]["timestamp"]
            last_ts = session[-1]["timestamp"]
            first_dt = parse_iso_time(first_ts)
            last_dt = parse_iso_time(last_ts)
            duration_sec = max(0, int((last_dt - first_dt).total_seconds()))

            labels = [a.get("label", "Unknown") for a in session]
            unique_labels = sorted(list(set(labels)))
            label_breakdown = {lbl: labels.count(lbl) for lbl in unique_labels}
            dst_ports = sorted(list(set(int(a.get("dst_port", 0)) for a in session)))
            target_ips = sorted(list(set(a.get("dst_ip", "0.0.0.0") for a in session)))
            sources = sorted(list(set(a.get("source", "unknown") for a in session)))
            max_conf = max((float(a.get("confidence", 0.0)) for a in session), default=0.0)

            # Synthetic tracking
            synthetic_count = sum(1 for a in session if a.get("is_synthetic") or a.get("source") in ["mock", "mock_part1", "mock_part2"])
            live_count = len(session) - synthetic_count
            is_synthetic_incident = synthetic_count > 0 and live_count == 0
            is_mixed = synthetic_count > 0 and live_count > 0

            # Deterministic scoring
            score_data = calculate_deterministic_risk_score(
                labels=labels,
                alert_count=len(session),
                max_confidence=max_conf,
                unique_target_ips=len(target_ips),
                unique_target_ports=len(dst_ports),
            )
            threat_pattern = analyze_chronological_sequence(session)

            incidents.append({
                "incident_id": f"INC-{inc_counter:04d}",
                "src_ip": ip,
                "target_ips": target_ips,
                "target_ports": dst_ports,
                "first_seen": first_ts,
                "last_seen": last_ts,
                "duration_seconds": duration_sec,
                "alert_count": len(session),
                "labels": unique_labels,
                "label_breakdown": label_breakdown,
                "sources": sources,
                "max_confidence": round(max_conf, 4),
                "risk_score": score_data["risk_score"],
                "severity": score_data["severity"],
                "scoring_rationale": score_data["scoring_rationale"],
                "threat_pattern": threat_pattern,
                "is_synthetic": is_synthetic_incident,
                "is_mixed": is_mixed,
                "synthetic_alert_count": synthetic_count,
                "live_alert_count": live_count,
                "alerts": session,
            })
            inc_counter += 1

    # Order incidents by highest risk score, then most recent last_seen
    incidents.sort(key=lambda x: (x["risk_score"], x["last_seen"]), reverse=True)

    return incidents
