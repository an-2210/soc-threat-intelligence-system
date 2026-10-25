"""Interactive Security Check and Local Incident Analysis Engine.

Provides three local investigation capabilities:
1. Mode A: Analyze an IP address using local telemetry history, RFC network classification,
   and documented SOC observations (without fabricating internet reputation lookups).
2. Mode B: Validate and submit structured security alerts to the FastAPI ingestion receiver.
3. Mode C: Parse and analyze raw network logs/events (syslog, web server access, firewall drops,
   flow records) into normalized threat indicators with an optional direct ingestion pathway.
"""
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dateutil.parser
import requests

from part3.correlation import correlate_alerts
from part3.db import get_alerts, get_connection


def classify_ip_network(ip_str: str) -> Dict[str, Any]:
    """Classifies an IP address into standardized RFC categories without conflating documentation ranges with RFC 1918."""
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)

        # 1. Loopback (RFC 1122)
        if ip_obj.is_loopback:
            return {
                "valid": True,
                "ip": str(ip_obj),
                "version": f"IPv{ip_obj.version}",
                "category": "Loopback (RFC 1122)",
                "scope": "Host-Only Interface",
                "is_private": False,
                "is_private_rfc1918": False,
                "is_documentation_rfc5737": False,
                "classification_note": "Local host loopback interface (127.0.0.0/8). Not routable on any network.",
            }

        # 2. Documentation / Test Ranges (RFC 5737 for IPv4, RFC 3849 for IPv6)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            if ip_obj in ipaddress.IPv4Network("192.0.2.0/24"):
                return {
                    "valid": True,
                    "ip": str(ip_obj),
                    "version": "IPv4",
                    "category": "Documentation Range (TEST-NET-1, RFC 5737)",
                    "scope": "Documentation / Non-Routable",
                    "is_private": False,
                    "is_private_rfc1918": False,
                    "is_documentation_rfc5737": True,
                    "classification_note": "Reserved exclusively for documentation, manuals, and test examples (192.0.2.0/24, RFC 5737). Not RFC 1918 private space.",
                }
            if ip_obj in ipaddress.IPv4Network("198.51.100.0/24"):
                return {
                    "valid": True,
                    "ip": str(ip_obj),
                    "version": "IPv4",
                    "category": "Documentation Range (TEST-NET-2, RFC 5737)",
                    "scope": "Documentation / Non-Routable",
                    "is_private": False,
                    "is_private_rfc1918": False,
                    "is_documentation_rfc5737": True,
                    "classification_note": "Reserved exclusively for documentation, manuals, and test examples (198.51.100.0/24, RFC 5737). Not RFC 1918 private space.",
                }
            if ip_obj in ipaddress.IPv4Network("203.0.113.0/24"):
                return {
                    "valid": True,
                    "ip": str(ip_obj),
                    "version": "IPv4",
                    "category": "Documentation Range (TEST-NET-3, RFC 5737)",
                    "scope": "Documentation / Non-Routable",
                    "is_private": False,
                    "is_private_rfc1918": False,
                    "is_documentation_rfc5737": True,
                    "classification_note": "Reserved exclusively for documentation, manuals, and test examples (203.0.113.0/24, RFC 5737). Not RFC 1918 private space.",
                }
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj in ipaddress.IPv6Network("2001:db8::/32"):
                return {
                    "valid": True,
                    "ip": str(ip_obj),
                    "version": "IPv6",
                    "category": "Documentation Range (RFC 3849)",
                    "scope": "Documentation / Non-Routable",
                    "is_private": False,
                    "is_private_rfc1918": False,
                    "is_documentation_rfc5737": True,
                    "classification_note": "Reserved for IPv6 documentation and examples (2001:db8::/32, RFC 3849).",
                }

        # 3. Link-Local (RFC 3927 for IPv4, RFC 4291 for IPv6)
        if ip_obj.is_link_local:
            return {
                "valid": True,
                "ip": str(ip_obj),
                "version": f"IPv{ip_obj.version}",
                "category": "Link-Local (RFC 3927 / RFC 4291)",
                "scope": "Local Subnet Only",
                "is_private": False,
                "is_private_rfc1918": False,
                "is_documentation_rfc5737": False,
                "classification_note": "Auto-configured link-local address (169.254.0.0/16). Non-routable beyond the local physical link.",
            }

        # 4. RFC 1918 Private Network (IPv4) or Unique Local (IPv6)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            for priv_net in [ipaddress.IPv4Network("10.0.0.0/8"), ipaddress.IPv4Network("172.16.0.0/12"), ipaddress.IPv4Network("192.168.0.0/16")]:
                if ip_obj in priv_net:
                    return {
                        "valid": True,
                        "ip": str(ip_obj),
                        "version": "IPv4",
                        "category": "Private Network (RFC 1918)",
                        "scope": "Internal Organizational Network",
                        "is_private": True,
                        "is_private_rfc1918": True,
                        "is_documentation_rfc5737": False,
                        "classification_note": "Internal non-public address space reserved for private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, RFC 1918).",
                    }
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj in ipaddress.IPv6Network("fc00::/7"):
                return {
                    "valid": True,
                    "ip": str(ip_obj),
                    "version": "IPv6",
                    "category": "Unique Local Address (RFC 4193)",
                    "scope": "Internal Organizational Network",
                    "is_private": True,
                    "is_private_rfc1918": True,
                    "is_documentation_rfc5737": False,
                    "classification_note": "IPv6 Unique Local Address space for private network routing (fc00::/7, RFC 4193).",
                }

        # 5. Benchmarking (RFC 2544)
        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in ipaddress.IPv4Network("198.18.0.0/15"):
            return {
                "valid": True,
                "ip": str(ip_obj),
                "version": "IPv4",
                "category": "Benchmarking Range (RFC 2544)",
                "scope": "Inter-Network Testing",
                "is_private": False,
                "is_private_rfc1918": False,
                "is_documentation_rfc5737": False,
                "classification_note": "Reserved for inter-network benchmark testing (198.18.0.0/15, RFC 2544).",
            }

        # 6. Public Internet
        return {
            "valid": True,
            "ip": str(ip_obj),
            "version": f"IPv{ip_obj.version}",
            "category": "Public Internet (Routable)",
            "scope": "Globally Routable",
            "is_private": False,
            "is_private_rfc1918": False,
            "is_documentation_rfc5737": False,
            "classification_note": "Globally routable public unicast IP address allocated by regional internet registries.",
        }
    except ValueError as e:
        return {
            "valid": False,
            "error": f"Invalid IP address format: {str(e)}",
        }


def analyze_ip_local(
    src_ip: str,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    context: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Investigates an IP address strictly against local SOC telemetry and network facts.

    Reconciles Target Hit Count semantics, local host threat profile, and correlated incident scores.
    """
    ip_info = classify_ip_network(src_ip)
    if not ip_info["valid"]:
        return {
            "success": False,
            "error": ip_info["error"],
        }

    conn = get_connection(db_path)

    # 1. Fetch ALL alerts sourced from this IP
    all_source_alerts = [
        dict(r) for r in conn.execute(
            "SELECT * FROM alerts WHERE src_ip = ? ORDER BY id DESC", (src_ip,)
        ).fetchall()
    ]

    # 2. Fetch destination records (how many times this IP was targeted as a destination)
    targeted_as_dst_count = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE dst_ip = ?", (src_ip,)
    ).fetchone()[0]

    conn.close()

    total_alerts_for_ip = len(all_source_alerts)
    has_history = total_alerts_for_ip > 0

    # Destination and port breakdowns from actual historical records for this src_ip
    dst_counts: Dict[str, int] = {}
    port_counts: Dict[int, int] = {}
    label_counts: Dict[str, int] = {}

    for a in all_source_alerts:
        d = a["dst_ip"]
        p = int(a["dst_port"])
        l = a["label"]
        dst_counts[d] = dst_counts.get(d, 0) + 1
        port_counts[p] = port_counts.get(p, 0) + 1
        label_counts[l] = label_counts.get(l, 0) + 1

    labels_observed = sorted(list(label_counts.keys()))
    destination_hosts = sorted(list(dst_counts.keys()))
    destination_ports = sorted(list(port_counts.keys()))

    # 3. Target Filter Matches Semantics:
    # If the user specified an optional target filter (dst_ip and/or dst_port), calculate matches against that filter.
    filter_applied = bool((dst_ip and dst_ip.strip()) or (dst_port is not None and dst_port > 0))
    if filter_applied:
        filtered_matches = []
        for a in all_source_alerts:
            if dst_ip and dst_ip.strip() and a["dst_ip"] != dst_ip.strip():
                continue
            if dst_port is not None and dst_port > 0 and int(a["dst_port"]) != dst_port:
                continue
            filtered_matches.append(a)
        target_filter_matches = len(filtered_matches)
        filter_summary = (
            f"Filter active: dst_ip={dst_ip.strip() if dst_ip and dst_ip.strip() else 'ANY'}, "
            f"dst_port={dst_port if dst_port and dst_port > 0 else 'ANY'} -> {target_filter_matches} matching alert(s)"
        )
    else:
        filtered_matches = all_source_alerts
        target_filter_matches = total_alerts_for_ip
        filter_summary = "All targets included (no target filter supplied)"

    # 4. Telemetry aggregation timestamps & confidence
    if has_history:
        first_seen = min(a["timestamp"] for a in all_source_alerts)
        last_seen = max(a["timestamp"] for a in all_source_alerts)
        peak_confidence = max(float(a["confidence"]) for a in all_source_alerts)
    else:
        first_seen = None
        last_seen = None
        peak_confidence = 0.0

    # 5. Correlated Incident Lookup & Risk Reconciliation:
    # Look up existing Correlated Incident for this IP from the correlation engine
    raw_db_alerts = get_alerts(limit=1000, db_path=db_path)
    correlated_incidents = correlate_alerts(raw_db_alerts)
    matching_incidents = [i for i in correlated_incidents if i["src_ip"] == src_ip]

    if matching_incidents:
        matched_inc = matching_incidents[0]
        correlated_incident_id = matched_inc["incident_id"]
        correlated_severity = matched_inc["severity"]
        correlated_risk_score = matched_inc["risk_score"]
        correlated_rationale = matched_inc["scoring_rationale"]
        correlated_threat_pattern = matched_inc["threat_pattern"]
    else:
        correlated_incident_id = None
        correlated_severity = None
        correlated_risk_score = None
        correlated_rationale = "No active correlated multi-flow incident session formed."
        correlated_threat_pattern = "No active correlated incident pattern."

    # Host-level profile based strictly on observed telemetry facts (not IP address type)
    if not has_history:
        host_threat_profile = "Clean / No Recorded Local Activity"
        soc_finding = (
            f"No historical security alerts have been logged for host {src_ip} in local SOC telemetry. "
            f"Address classification: {ip_info['category']}. "
            f"Note: An IP address alone cannot establish whether a host is malicious without telemetry or reputation feeds. "
            f"No local attack patterns or policy violations have been observed from this address."
        )
    elif len(labels_observed) > 1:
        host_threat_profile = "Active Multi-Vector Threat Actor"
        soc_finding = (
            f"Host {src_ip} ({ip_info['category']}) has recorded {total_alerts_for_ip} security alert(s) "
            f"across {len(labels_observed)} distinct attack categories ({', '.join(labels_observed)}). "
            f"Targeted internal endpoints: {', '.join(destination_hosts)} across ports {', '.join(str(p) for p in destination_ports)}."
        )
    else:
        host_threat_profile = f"Single-Vector Threat Actor ({labels_observed[0]})"
        soc_finding = (
            f"Host {src_ip} ({ip_info['category']}) has recorded {total_alerts_for_ip} alert(s) "
            f"classified as {labels_observed[0]} targeting {', '.join(destination_hosts)} on ports {', '.join(str(p) for p in destination_ports)}."
        )

    recommendations = []
    if has_history:
        recommendations.append(f"Audit firewall and access logs on targeted ports {destination_ports} for sessions from {src_ip}.")
        if "BruteForce" in labels_observed:
            recommendations.append("Inspect host authentication daemon logs on targeted servers to verify whether any attempts succeeded.")
        if "DoS" in labels_observed:
            recommendations.append("Ensure rate-limiting policies and connection drop thresholds are enforced on perimeter firewalls.")
        if "PortScan" in labels_observed:
            recommendations.append("Review perimeter ACLs to ensure non-essential ports are filtered from external observation.")
    else:
        recommendations.append("Continue routine network monitoring; no containment action required based on local telemetry.")

    return {
        "success": True,
        "src_ip": src_ip,
        "network_info": ip_info,
        "investigation_context": context or "Routine SOC verification",
        "has_local_history": has_history,
        "total_alerts_for_ip": total_alerts_for_ip,
        "total_alerts_found": total_alerts_for_ip,
        "filter_applied": filter_applied,
        "target_filter_matches": target_filter_matches,
        "target_hits": target_filter_matches,
        "filter_summary": filter_summary,
        "was_targeted_as_destination_count": targeted_as_dst_count,
        "labels_observed": labels_observed,
        "label_breakdown": label_counts,
        "destination_hosts": destination_hosts,
        "target_ips_affected": destination_hosts,
        "destination_breakdown": dst_counts,
        "destination_ports": destination_ports,
        "ports_targeted": destination_ports,
        "port_breakdown": port_counts,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "peak_confidence": peak_confidence,
        "max_confidence": peak_confidence,
        "host_threat_profile": host_threat_profile,
        "local_risk_level": host_threat_profile,
        "correlated_incident_id": correlated_incident_id,
        "correlated_severity": correlated_severity,
        "correlated_risk_score": correlated_risk_score,
        "correlated_rationale": correlated_rationale,
        "correlated_threat_pattern": correlated_threat_pattern,
        "soc_finding": soc_finding,
        "assessment": soc_finding,
        "recommendations": recommendations,
        "sample_alerts": (filtered_matches if filter_applied else all_source_alerts)[:5],
    }


def submit_structured_alert(
    alert_payload: Dict[str, Any],
    receiver_url: str = "http://127.0.0.1:8000/alert",
) -> Dict[str, Any]:
    """Validates and posts a structured alert into the FastAPI receiver."""
    payload = {
        "timestamp": alert_payload.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": alert_payload.get("source", "security_check"),
        "src_ip": str(alert_payload.get("src_ip", "")).strip(),
        "dst_ip": str(alert_payload.get("dst_ip", "")).strip(),
        "dst_port": int(alert_payload.get("dst_port", 80)),
        "label": str(alert_payload.get("label", "Anomaly")).strip(),
        "confidence": float(alert_payload.get("confidence", 0.95)),
        "top_features": alert_payload.get("top_features", {}),
        "is_synthetic": bool(alert_payload.get("is_synthetic", False)),
    }

    # Validate IP addresses
    for field in ["src_ip", "dst_ip"]:
        ip_check = classify_ip_network(payload[field])
        if not ip_check["valid"]:
            return {"success": False, "error": f"Invalid {field}: {ip_check['error']}"}

    # Validate port
    if not (0 <= payload["dst_port"] <= 65535):
        return {"success": False, "error": f"Port out of range [0, 65535]: {payload['dst_port']}"}

    # Validate confidence
    if not (0.0 <= payload["confidence"] <= 1.0):
        return {"success": False, "error": f"Confidence out of range [0.0, 1.0]: {payload['confidence']}"}

    try:
        resp = requests.post(receiver_url, json=payload, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "success": True,
                "alert_id": data.get("id"),
                "is_duplicate": data.get("duplicate", False),
                "payload": payload,
            }
        else:
            return {
                "success": False,
                "error": f"Receiver returned status {resp.status_code}: {resp.text}",
            }
    except Exception as e:
        # Direct DB fallback if receiver is momentarily unreachable
        from part3.db import insert_alert
        try:
            aid, is_dup = insert_alert(payload)
            return {
                "success": True,
                "alert_id": aid,
                "is_duplicate": is_dup,
                "fallback_db": True,
                "payload": payload,
            }
        except Exception as db_err:
            return {"success": False, "error": f"Connection error: {e} (DB fallback error: {db_err})"}


def parse_network_log(raw_text: str) -> Dict[str, Any]:
    """Parses arbitrary log lines (syslog, web logs, firewall logs, flow records) for IOCs."""
    text = raw_text.strip()
    if not text:
        return {"success": False, "error": "Log input is empty."}

    # Extract all IPv4 addresses
    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    valid_ips = [ip for ip in ip_matches if classify_ip_network(ip)["valid"]]

    if not valid_ips:
        return {"success": False, "error": "No valid IP addresses found in log input."}

    src_ip = valid_ips[0]
    dst_ip = valid_ips[1] if len(valid_ips) > 1 else "192.168.10.5"

    # Extract destination service ports
    port = 80
    text_lower = text.lower()
    if "sshd" in text_lower or "ssh2" in text_lower:
        port = 22
    elif "ftpd" in text_lower or "vsftpd" in text_lower or "proftpd" in text_lower:
        port = 21
    else:
        # Check explicit destination port flags (e.g. DPT=80, dst_port=443)
        port_match = re.search(r"\b(?:dpt|dst_port|DPT)[=:\s]+(\d{1,5})\b", text, re.IGNORECASE)
        if not port_match:
            port_match = re.search(r"\b(?:port)[=:\s]+(\d{1,5})\b", text, re.IGNORECASE)
        if port_match:
            try:
                p_val = int(port_match.group(1))
                if 0 <= p_val <= 65535:
                    port = p_val
            except Exception:
                pass
        elif "443" in text or "https" in text_lower:
            port = 443
        elif "8080" in text:
            port = 8080

    # Threat classification heuristic based on observed log indicators
    inferred_label = "Anomaly"
    confidence = 0.92
    evidence_points = []

    if any(k in text_lower for k in ["failed password", "authentication failure", "invalid user", "brute force", "login failed"]):
        inferred_label = "BruteForce"
        confidence = 0.98
        evidence_points.append("Authentication failure keywords detected in log stream.")
        if port in [21, 22]:
            evidence_points.append(f"Targeted authentication service port {port}.")
    elif any(k in text_lower for k in ["syn flood", "dos", "flood", "connection timeout", "resource exhausted", "503 service unavailable"]):
        inferred_label = "DoS"
        confidence = 0.97
        evidence_points.append("Denial of service / resource exhaustion pattern identified.")
    elif any(k in text_lower for k in ["portscan", "port scan", "nmap", "scan", "enumeration", "closed port"]):
        inferred_label = "PortScan"
        confidence = 0.96
        evidence_points.append("Scanning / port enumeration indicators identified.")
    elif any(k in text_lower for k in ["drop", "blocked", "deny", "unauthorized", "403 forbidden", "401 unauthorized"]):
        inferred_label = "Anomaly"
        confidence = 0.93
        evidence_points.append("Firewall drop or access denial event recorded.")
    else:
        evidence_points.append("Unclassified event requiring anomaly inspection.")

    return {
        "success": True,
        "raw_log": text,
        "extracted_src_ip": src_ip,
        "extracted_dst_ip": dst_ip,
        "extracted_dst_port": port,
        "inferred_label": inferred_label,
        "estimated_confidence": confidence,
        "indicators": evidence_points,
        "suggested_payload": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": "log_analyzer",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": port,
            "label": inferred_label,
            "confidence": confidence,
            "top_features": {"Log Parser": 1.0, "Target Port": float(port)},
            "is_synthetic": False,
        },
    }
