"""Comprehensive test suite for SOC / Cyberthreat NIDS-CTI Project (Part 3).

Covers:
1. API tests (health, ingestion, validation, rejection of malformed alerts, listing, filtering, pagination, stats, delete).
2. Incident correlation tests (grouping, temporal windows, sequence verification, deterministic scoring, synthetic tagging).
3. Report generator tests (Gemini mocked, heuristic fallback, error handling, metadata, required sections).
4. PDF export tests (valid binary, XML safety with special characters, long text handling, missing sections).
5. End-to-end integration test.
"""
import io
import json
import sqlite3
import sys
import unittest.mock as mock
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure part3 is in path
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from part3.correlation import (
    analyze_chronological_sequence,
    calculate_deterministic_risk_score,
    correlate_alerts,
    parse_iso_time,
)
from part3.db import (
    clear_alerts,
    get_alerts,
    get_alerts_count,
    get_connection,
    get_stats,
    init_db,
    insert_alert,
)
from part3.report_generator import (
    check_ollama_status,
    export_report_to_pdf,
    generate_heuristic_report,
    generate_incident_report,
    generate_llm_report_with_gemini,
    generate_llm_report_with_ollama,
    parse_llm_markdown_sections,
)
from part3.server import app


# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def isolated_test_db(tmp_path):
    """Run every test against an isolated temporary SQLite database."""
    test_db = tmp_path / "test_alerts.db"
    init_db(test_db)
    # Patch DB_PATH in db module
    with mock.patch("part3.db.DB_PATH", test_db), mock.patch("part3.server.get_stats", lambda: get_stats(test_db)):
        yield test_db


@pytest.fixture
def api_client(isolated_test_db):
    """FastAPI TestClient using the isolated database."""
    with mock.patch("part3.server.insert_alert", lambda data, allow_duplicate=False: insert_alert(data, isolated_test_db, allow_duplicate)), \
         mock.patch("part3.server.get_alerts", lambda **kwargs: get_alerts(db_path=isolated_test_db, **kwargs)), \
         mock.patch("part3.server.get_alerts_count", lambda **kwargs: get_alerts_count(db_path=isolated_test_db, **kwargs)), \
         mock.patch("part3.server.get_stats", lambda: get_stats(isolated_test_db)), \
         mock.patch("part3.server.clear_alerts", lambda: clear_alerts(isolated_test_db)):
        client = TestClient(app)
        yield client


# ---------------------------------------------------------------------------
# 1. API TESTS
# ---------------------------------------------------------------------------
def test_api_health(api_client):
    response = api_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_api_ingest_valid_alert(api_client):
    payload = {
        "timestamp": "2026-10-25T17:30:00Z",
        "source": "part1",
        "src_ip": "198.51.100.45",
        "dst_ip": "192.168.10.5",
        "dst_port": 22,
        "label": "BruteForce",
        "confidence": 0.99,
        "top_features": {"Destination Port": 22.0, "Init_Win_bytes_forward": 29200.0},
        "is_synthetic": False,
    }
    response = api_client.post("/alert", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["status"] == "ok"
    assert res_data["id"] > 0
    assert res_data["duplicate"] is False
    assert res_data["is_synthetic"] is False


def test_api_deduplication(api_client):
    payload = {
        "timestamp": "2026-10-25T17:30:00Z",
        "source": "part1",
        "src_ip": "198.51.100.45",
        "dst_ip": "192.168.10.5",
        "dst_port": 22,
        "label": "BruteForce",
        "confidence": 0.99,
        "top_features": {},
        "is_synthetic": False,
    }
    # First post
    r1 = api_client.post("/alert", json=payload)
    assert r1.status_code == 200
    first_id = r1.json()["id"]

    # Duplicate post (same timestamp, src, dst, port, label)
    r2 = api_client.post("/alert", json=payload)
    assert r2.status_code == 200
    assert r2.json()["duplicate"] is True
    assert r2.json()["id"] == first_id

    # Verify only 1 alert in db
    alerts = api_client.get("/alerts").json()
    assert len(alerts) == 1


def test_api_reject_malformed_timestamp(api_client):
    bad_payload = {
        "timestamp": "not-a-valid-timestamp",
        "source": "part1",
        "src_ip": "198.51.100.45",
        "dst_ip": "192.168.10.5",
        "dst_port": 80,
        "label": "DoS",
        "confidence": 0.99,
    }
    response = api_client.post("/alert", json=bad_payload)
    assert response.status_code == 422


def test_api_reject_invalid_port(api_client):
    bad_payload = {
        "timestamp": "2026-10-25T17:30:00Z",
        "source": "part1",
        "src_ip": "198.51.100.45",
        "dst_ip": "192.168.10.5",
        "dst_port": 999999,  # Port > 65535
        "label": "DoS",
        "confidence": 0.99,
    }
    response = api_client.post("/alert", json=bad_payload)
    assert response.status_code == 422


def test_api_reject_invalid_confidence(api_client):
    bad_payload = {
        "timestamp": "2026-10-25T17:30:00Z",
        "source": "part1",
        "src_ip": "198.51.100.45",
        "dst_ip": "192.168.10.5",
        "dst_port": 80,
        "label": "DoS",
        "confidence": 1.5,  # Confidence > 1.0
    }
    response = api_client.post("/alert", json=bad_payload)
    assert response.status_code == 422


def test_api_filtering_and_pagination(api_client):
    for i in range(5):
        api_client.post("/alert", json={
            "timestamp": f"2026-10-25T17:30:0{i}Z",
            "source": "part1",
            "src_ip": "203.0.113.10",
            "dst_ip": "192.168.10.5",
            "dst_port": 80,
            "label": "DoS",
            "confidence": 0.98,
            "is_synthetic": False,
        })
    for i in range(3):
        api_client.post("/alert", json={
            "timestamp": f"2026-10-25T17:31:0{i}Z",
            "source": "part2",
            "src_ip": "198.51.100.7",
            "dst_ip": "192.168.10.15",
            "dst_port": 443,
            "label": "Anomaly",
            "confidence": 0.995,
            "is_synthetic": True,
        })

    # Test filtering by label
    r_dos = api_client.get("/alerts?label=DoS")
    assert len(r_dos.json()) == 5
    assert r_dos.headers["X-Total-Count"] == "5"

    # Test filtering by is_synthetic
    r_synth = api_client.get("/alerts?is_synthetic=true")
    assert len(r_synth.json()) == 3

    # Test pagination
    r_page = api_client.get("/alerts?limit=3&offset=0")
    assert len(r_page.json()) == 3
    assert r_page.headers["X-Total-Count"] == "8"


def test_api_stats_reconciliation_and_delete(api_client):
    api_client.post("/alert", json={
        "timestamp": "2026-10-25T17:30:00Z",
        "source": "part1",
        "src_ip": "203.0.113.11",
        "dst_ip": "192.168.10.5",
        "dst_port": 22,
        "label": "BruteForce",
        "confidence": 0.99,
        "is_synthetic": False,
    })
    api_client.post("/alert", json={
        "timestamp": "2026-10-25T17:30:01Z",
        "source": "mock_part1",
        "src_ip": "192.0.2.140",
        "dst_ip": "192.168.10.5",
        "dst_port": 80,
        "label": "DoS",
        "confidence": 0.95,
        "is_synthetic": True,
    })

    stats = api_client.get("/stats").json()
    assert stats["total_alerts"] == 2
    assert stats["live_count"] == 1
    assert stats["synthetic_count"] == 1
    assert stats["label_counts"]["BruteForce"] == 1
    assert stats["label_counts"]["DoS"] == 1

    # Delete alerts
    del_resp = api_client.delete("/alerts")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] == 2

    # Verify zero stats
    empty_stats = api_client.get("/stats").json()
    assert empty_stats["total_alerts"] == 0
    assert empty_stats["live_count"] == 0
    assert empty_stats["synthetic_count"] == 0


# ---------------------------------------------------------------------------
# 2. INCIDENT CORRELATION TESTS
# ---------------------------------------------------------------------------
def test_correlation_temporal_grouping():
    alerts = [
        # Session 1: 10:00 to 10:05
        {"timestamp": "2026-10-25T10:00:00Z", "source": "part1", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.5", "dst_port": 80, "label": "PortScan", "confidence": 0.99},
        {"timestamp": "2026-10-25T10:05:00Z", "source": "part1", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.5", "dst_port": 22, "label": "BruteForce", "confidence": 1.0},
        # Session 2: 11:00 (more than 15 mins gap)
        {"timestamp": "2026-10-25T11:00:00Z", "source": "part1", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.5", "dst_port": 80, "label": "DoS", "confidence": 0.98},
    ]
    incidents = correlate_alerts(alerts, time_window_minutes=15)
    assert len(incidents) == 2, "Expected 2 separate incidents due to time gap > 15m"


def test_correlation_chronological_sequence_verification():
    # Scenario A: PortScan strictly precedes BruteForce
    seq_alerts_a = [
        {"timestamp": "2026-10-25T10:00:00Z", "label": "PortScan"},
        {"timestamp": "2026-10-25T10:02:00Z", "label": "BruteForce"},
    ]
    pattern_a = analyze_chronological_sequence(seq_alerts_a)
    assert "Port scanning" in pattern_a and "strictly preceded" in pattern_a

    # Scenario B: BruteForce precedes PortScan
    seq_alerts_b = [
        {"timestamp": "2026-10-25T10:00:00Z", "label": "BruteForce"},
        {"timestamp": "2026-10-25T10:02:00Z", "label": "PortScan"},
    ]
    pattern_b = analyze_chronological_sequence(seq_alerts_b)
    assert "Credential brute-force" in pattern_b and "preceded subsequent port scanning" in pattern_b

    # Scenario C: Concurrent
    seq_alerts_c = [
        {"timestamp": "2026-10-25T10:00:00Z", "label": "PortScan"},
        {"timestamp": "2026-10-25T10:00:00Z", "label": "BruteForce"},
    ]
    pattern_c = analyze_chronological_sequence(seq_alerts_c)
    assert "Concurrent" in pattern_c


def test_correlation_deterministic_risk_scoring():
    # Critical multi-vector scenario
    score_data = calculate_deterministic_risk_score(
        labels=["PortScan", "BruteForce", "DoS"],
        alert_count=30,
        max_confidence=1.0,
        unique_target_ips=2,
        unique_target_ports=4,
    )
    assert score_data["severity"] == "CRITICAL"
    assert score_data["risk_score"] >= 8.0
    assert "Base vector weight" in score_data["scoring_rationale"]

    # Low severity scenario
    score_low = calculate_deterministic_risk_score(
        labels=["PortScan"],
        alert_count=1,
        max_confidence=0.90,
        unique_target_ips=1,
        unique_target_ports=1,
    )
    assert score_low["severity"] == "LOW"
    assert score_low["risk_score"] < 3.5


def test_correlation_synthetic_tagging():
    alerts = [
        {"timestamp": "2026-10-25T10:00:00Z", "source": "mock_part1", "src_ip": "10.0.0.99", "dst_ip": "192.168.10.5", "dst_port": 80, "label": "DoS", "confidence": 0.99, "is_synthetic": True},
        {"timestamp": "2026-10-25T10:01:00Z", "source": "mock_part1", "src_ip": "10.0.0.99", "dst_ip": "192.168.10.5", "dst_port": 80, "label": "DoS", "confidence": 0.99, "is_synthetic": True},
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert incidents[0]["is_synthetic"] is True
    assert incidents[0]["synthetic_alert_count"] == 2
    assert incidents[0]["live_alert_count"] == 0


# ---------------------------------------------------------------------------
# 3. REPORT GENERATOR & LLM FALLBACK TESTS
# ---------------------------------------------------------------------------
def test_report_generation_no_key_uses_heuristic():
    incident = {
        "incident_id": "INC-0001",
        "src_ip": "203.0.113.11",
        "target_ips": ["192.168.10.5"],
        "target_ports": [22],
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:02:00Z",
        "duration_seconds": 120,
        "alert_count": 5,
        "labels": ["BruteForce"],
        "label_breakdown": {"BruteForce": 5},
        "sources": ["part1"],
        "max_confidence": 0.99,
        "severity": "HIGH",
        "risk_score": 6.8,
        "scoring_rationale": "Rule-based score",
        "threat_pattern": "Repeated authentication brute-force",
        "is_synthetic": False,
        "alerts": [{"top_features": {"Destination Port": 22.0}}],
    }

    report = generate_incident_report(incident, api_key=None)
    assert "what" in report and len(report["what"]) > 20
    assert "evidence" in report and len(report["evidence"]) > 20
    assert "severity" in report and len(report["severity"]) > 10
    assert "action" in report and "iptables" in report["action"]
    assert report["metadata"]["generator"] == "Deterministic SOC Analyst Engine (Offline)"
    assert report["metadata"]["fallback_used"] is False


def test_report_generation_gemini_failure_triggers_fallback():
    incident = {
        "incident_id": "INC-0002",
        "src_ip": "198.51.100.45",
        "target_ips": ["192.168.10.5"],
        "target_ports": [80],
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:00:00Z",
        "duration_seconds": 0,
        "alert_count": 2,
        "labels": ["DoS"],
        "label_breakdown": {"DoS": 2},
        "sources": ["part1"],
        "max_confidence": 0.98,
        "severity": "MEDIUM",
        "risk_score": 4.5,
        "is_synthetic": True,
        "alerts": [],
    }

    # Mock google.generativeai failure
    with mock.patch("part3.report_generator.generate_llm_report_with_gemini", side_effect=RuntimeError("QuotaExceeded")):
        report = generate_incident_report(incident, api_key="fake-key")
        assert report["metadata"]["fallback_used"] is True
        assert "QuotaExceeded" in report["metadata"]["error_category"]
        assert "what" in report
        assert "action" in report


def test_ollama_status_offline():
    """Ensure check_ollama_status handles unreachable local host gracefully."""
    with mock.patch("urllib.request.urlopen", side_effect=OSError("Connection refused")):
        status = check_ollama_status("http://127.0.0.1:11434")
        assert status["available"] is False
        assert status["models"] == []
        assert status["default_model"] is None
        assert "refused" in status["error"].lower() or status["error"] is not None


def test_ollama_status_online_mocked():
    """Ensure check_ollama_status parses installed models correctly."""
    mock_response = mock.MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = json.dumps({
        "models": [
            {"name": "mistral:latest"},
            {"name": "llama3:latest"},
            {"name": "phi3:latest"},
        ]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with mock.patch("urllib.request.urlopen", return_value=mock_response):
        status = check_ollama_status("http://127.0.0.1:11434")
        assert status["available"] is True
        assert "llama3:latest" in status["models"]
        # Preferred order prefers llama3 over mistral/phi3
        assert status["default_model"] == "llama3:latest"


def test_report_generation_with_ollama_mocked():
    """Ensure generate_llm_report_with_ollama parses model output into structured sections."""
    incident = {
        "incident_id": "INC-0001",
        "src_ip": "198.51.100.45",
        "target_ips": ["192.168.10.5"],
        "target_ports": [22],
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:02:00Z",
        "duration_seconds": 120,
        "alert_count": 5,
        "labels": ["BruteForce"],
        "label_breakdown": {"BruteForce": 5},
        "sources": ["part1"],
        "max_confidence": 0.99,
        "severity": "HIGH",
        "risk_score": 7.5,
        "scoring_rationale": "High score",
        "threat_pattern": "Brute force sequence",
        "is_synthetic": False,
        "alerts": [],
    }

    mock_ollama_output = """### WHAT HAPPENED
Ollama observed systematic SSH brute-force attempts from 198.51.100.45 targeting 192.168.10.5.

### EVIDENCE
5 anomalous flows detected by Random Forest model with 0.99 confidence on port 22.

### SEVERITY
HIGH. Service credentials are under attack.

### RECOMMENDED ACTION
iptables -I INPUT -s 198.51.100.45 -j DROP
Audit auth.log immediately."""

    mock_response = mock.MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = json.dumps({"response": mock_ollama_output}).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with mock.patch("urllib.request.urlopen", return_value=mock_response):
        sections, meta = generate_llm_report_with_ollama(incident, model="llama3")
        assert "SSH brute-force" in sections["what"]
        assert "port 22" in sections["evidence"]
        assert "HIGH" in sections["severity"]
        assert "iptables" in sections["action"]
        assert meta["generator"] == "ollama/llama3"
        assert meta["fallback_used"] is False


def test_report_generation_ollama_failure_triggers_fallback():
    """Ensure generate_incident_report falls back to heuristic if Ollama errors out."""
    incident = {
        "incident_id": "INC-0001",
        "src_ip": "198.51.100.45",
        "target_ips": ["192.168.10.5"],
        "target_ports": [22],
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:02:00Z",
        "duration_seconds": 120,
        "alert_count": 5,
        "labels": ["BruteForce"],
        "label_breakdown": {"BruteForce": 5},
        "sources": ["part1"],
        "max_confidence": 0.99,
        "severity": "HIGH",
        "risk_score": 7.5,
        "scoring_rationale": "High score",
        "threat_pattern": "Brute force sequence",
        "is_synthetic": False,
        "alerts": [],
    }

    with mock.patch("part3.report_generator.generate_llm_report_with_ollama", side_effect=RuntimeError("Ollama timeout")):
        report = generate_incident_report(incident, engine="ollama")
        assert report["metadata"]["fallback_used"] is True
        assert "Ollama timeout" in report["metadata"]["error_category"]
        assert "what" in report
        assert "action" in report



def test_markdown_section_parser_robustness():
    # Test lowercase, strange markdown, missing colons
    raw = """
Here is my analysis:
what happened:
The attacker attempted a brute force login.
### Evidence
Found Destination Port 22 and high SYN flags.
severity:
High due to exposed administrative port.
RECOMMENDED ACTIONS:
Block the IP immediately.
"""
    sections = parse_llm_markdown_sections(raw)
    assert "brute force login" in sections["what"]
    assert "Destination Port 22" in sections["evidence"]
    assert "High" in sections["severity"]
    assert "Block the IP" in sections["action"]


# ---------------------------------------------------------------------------
# 4. PDF EXPORT TESTS
# ---------------------------------------------------------------------------
def test_pdf_export_validity():
    incident = {
        "incident_id": "INC-0003",
        "src_ip": "203.0.113.11",
        "target_ips": ["192.168.10.5"],
        "target_ports": [21, 22],
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:05:00Z",
        "duration_seconds": 300,
        "alert_count": 8,
        "severity": "HIGH",
        "risk_score": 7.2,
        "is_synthetic": False,
    }
    report_content = {
        "what": "Test attack narrative.",
        "evidence": "- Flow alert telemetry\n- Destination Port 22",
        "severity": "HIGH risk.",
        "action": "iptables -I INPUT -s 203.0.113.11 -j DROP",
        "metadata": {"generator": "Test Engine", "fallback_used": False},
    }

    pdf_bytes = export_report_to_pdf(incident, report_content)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF"), "Output must begin with %PDF magic header"


def test_pdf_export_xml_escaping_special_characters():
    """Ensure characters like <, >, &, and quotes do NOT crash ReportLab Paragraph parsing."""
    incident = {
        "incident_id": "INC-0004",
        "src_ip": "<script>alert('xss')</script> & 203.0.113.99",
        "target_ips": ["192.168.10.5", "10.0.0.1 <internal>"],
        "target_ports": [80],
        "first_seen": "2026-10-25T10:00:00Z",
        "last_seen": "2026-10-25T10:00:00Z",
        "duration_seconds": 0,
        "alert_count": 1,
        "severity": "LOW",
        "risk_score": 2.0,
        "is_synthetic": False,
    }
    report_content = {
        "what": "Threat actor targeted <dell-ip>:8000 & performed 'injection' with <b>bold</b> syntax.",
        "evidence": "Value < 100 & Value > 50 with characters like &amp; and <tag>",
        "severity": "LOW < 3.0",
        "action": "curl -X POST 'http://127.0.0.1:8000/alert?x=1&y=2'",
        "metadata": {"generator": "Heuristic Engine <v1.1> & Test", "fallback_used": True},
    }

    # If XML escaping is broken, this will raise a ReportLab XML parsing exception
    pdf_bytes = export_report_to_pdf(incident, report_content)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 1000


# ---------------------------------------------------------------------------
# 5. INTEGRATION TEST
# ---------------------------------------------------------------------------
def test_full_pipeline_integration(api_client, isolated_test_db):
    """End-to-end integration: Ingest -> Query -> Correlate -> Report -> PDF."""
    # 1. Ingest sequence
    for p in [80, 21, 22]:
        resp = api_client.post("/alert", json={
            "timestamp": "2026-10-25T12:00:00Z",
            "source": "part1",
            "src_ip": "198.51.100.99",
            "dst_ip": "192.168.10.5",
            "dst_port": p,
            "label": "PortScan",
            "confidence": 0.98,
            "top_features": {"Destination Port": float(p)},
            "is_synthetic": False,
        })
        assert resp.status_code == 200

    api_client.post("/alert", json={
        "timestamp": "2026-10-25T12:01:00Z",
        "source": "part1",
        "src_ip": "198.51.100.99",
        "dst_ip": "192.168.10.5",
        "dst_port": 22,
        "label": "BruteForce",
        "confidence": 1.0,
        "top_features": {"Destination Port": 22.0},
        "is_synthetic": False,
    })

    # 2. Query alerts
    stored_alerts = get_alerts(db_path=isolated_test_db)
    assert len(stored_alerts) == 4

    # 3. Correlate
    incidents = correlate_alerts(stored_alerts, time_window_minutes=15)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["src_ip"] == "198.51.100.99"
    assert inc["alert_count"] == 4
    assert "PortScan" in inc["labels"] and "BruteForce" in inc["labels"]

    # 4. Generate Report
    report = generate_incident_report(inc)
    assert all(k in report for k in ["what", "evidence", "severity", "action"])

    # 5. Export PDF
    pdf = export_report_to_pdf(inc, report)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 2000


# ---------------------------------------------------------------------------
# 6. SECURITY CHECK TESTS (Mode A, Mode B, Mode C)
# ---------------------------------------------------------------------------
from part3.security_check import (
    analyze_ip_local,
    classify_ip_network,
    parse_network_log,
    submit_structured_alert,
)


def test_security_check_mode_a_ip_classification_and_history(isolated_test_db):
    # Test invalid IP
    bad_res = analyze_ip_local("999.999.999.999", db_path=isolated_test_db)
    assert bad_res["success"] is False
    assert "Invalid IP" in bad_res["error"]

    # Test clean IP with no prior history
    clean_res = analyze_ip_local("192.168.1.50", db_path=isolated_test_db)
    assert clean_res["success"] is True
    assert clean_res["has_local_history"] is False
    assert clean_res["network_info"]["is_private"] is True
    assert "No local attack patterns" in clean_res["assessment"]

    # Ingest an alert for an IP, then verify it is discovered in investigation
    insert_alert({
        "timestamp": "2026-10-25T15:00:00Z",
        "source": "part1",
        "src_ip": "203.0.113.11",
        "dst_ip": "192.168.10.5",
        "dst_port": 22,
        "label": "BruteForce",
        "confidence": 0.99,
        "is_synthetic": False,
    }, db_path=isolated_test_db)

    found_res = analyze_ip_local("203.0.113.11", db_path=isolated_test_db)
    assert found_res["success"] is True
    assert found_res["has_local_history"] is True
    assert found_res["total_alerts_found"] == 1
    assert "BruteForce" in found_res["labels_observed"]
    assert 22 in found_res["ports_targeted"]


def test_security_check_mode_b_submit_alert(isolated_test_db):
    # Invalid IP
    err_ip = submit_structured_alert({"src_ip": "not-an-ip", "dst_ip": "192.168.10.5", "dst_port": 80})
    assert err_ip["success"] is False

    # Out of range port
    err_port = submit_structured_alert({"src_ip": "198.51.100.1", "dst_ip": "192.168.10.5", "dst_port": 70000})
    assert err_port["success"] is False

    # Out of range confidence
    err_conf = submit_structured_alert({"src_ip": "198.51.100.1", "dst_ip": "192.168.10.5", "dst_port": 80, "confidence": 2.5})
    assert err_conf["success"] is False

    # Valid alert submission
    with mock.patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"id": 999, "duplicate": False}
        ok_res = submit_structured_alert({
            "src_ip": "198.51.100.77",
            "dst_ip": "192.168.10.5",
            "dst_port": 80,
            "label": "DoS",
            "confidence": 0.99,
        })
        assert ok_res["success"] is True
        assert ok_res["alert_id"] == 999


def test_security_check_mode_c_log_parsing():
    # 1. SSH syslog
    ssh_log = "Oct 25 22:15:00 auth sshd[1234]: Failed password for root from 203.0.113.11 port 54321 ssh2"
    p1 = parse_network_log(ssh_log)
    assert p1["success"] is True
    assert p1["extracted_src_ip"] == "203.0.113.11"
    assert p1["extracted_dst_port"] == 22
    assert p1["inferred_label"] == "BruteForce"

    # 2. Firewall drop
    fw_log = "DROP IN=eth0 SRC=192.0.2.140 DST=192.168.10.5 PROTO=TCP SPT=49152 DPT=80 FLAGS=SYN"
    p2 = parse_network_log(fw_log)
    assert p2["success"] is True
    assert p2["extracted_src_ip"] == "192.0.2.140"
    assert p2["extracted_dst_ip"] == "192.168.10.5"
    assert p2["extracted_dst_port"] == 80

    # 3. Web server log
    web_log = '198.51.100.45 - - [25/Oct/2026:22:15:30 +0000] "GET /admin/config.php HTTP/1.1" 401 1234'
    p3 = parse_network_log(web_log)
    assert p3["success"] is True
    assert p3["extracted_src_ip"] == "198.51.100.45"


def test_security_check_ip_classification_rfc5737_vs_rfc1918():
    """Requirement 1: Verify correct IP network classification distinguishing RFC 5737 documentation space from RFC 1918."""
    # 1. TEST-NET-3 (203.0.113.11)
    doc3 = classify_ip_network("203.0.113.11")
    assert doc3["valid"] is True
    assert doc3["category"] == "Documentation Range (TEST-NET-3, RFC 5737)"
    assert doc3["scope"] == "Documentation / Non-Routable"
    assert doc3["is_documentation_rfc5737"] is True
    assert doc3["is_private_rfc1918"] is False
    assert doc3["is_private"] is False
    assert "Not RFC 1918 private space" in doc3["classification_note"]

    # 2. TEST-NET-1 and TEST-NET-2
    doc1 = classify_ip_network("192.0.2.1")
    assert doc1["category"] == "Documentation Range (TEST-NET-1, RFC 5737)"
    assert doc1["is_documentation_rfc5737"] is True
    assert doc1["is_private_rfc1918"] is False

    doc2 = classify_ip_network("198.51.100.25")
    assert doc2["category"] == "Documentation Range (TEST-NET-2, RFC 5737)"
    assert doc2["is_documentation_rfc5737"] is True
    assert doc2["is_private_rfc1918"] is False

    # 3. RFC 1918 Private Ranges (10.0.0.99, 172.16.5.1, 192.168.1.1)
    priv_10 = classify_ip_network("10.0.0.99")
    assert priv_10["valid"] is True
    assert priv_10["category"] == "Private Network (RFC 1918)"
    assert priv_10["scope"] == "Internal Organizational Network"
    assert priv_10["is_private_rfc1918"] is True
    assert priv_10["is_private"] is True
    assert priv_10["is_documentation_rfc5737"] is False

    priv_172 = classify_ip_network("172.16.5.1")
    assert priv_172["category"] == "Private Network (RFC 1918)"
    assert priv_172["is_private_rfc1918"] is True

    priv_192 = classify_ip_network("192.168.1.1")
    assert priv_192["category"] == "Private Network (RFC 1918)"
    assert priv_192["is_private_rfc1918"] is True

    # 4. Public Internet (Routable)
    pub = classify_ip_network("8.8.8.8")
    assert pub["category"] == "Public Internet (Routable)"
    assert pub["is_private_rfc1918"] is False
    assert pub["is_documentation_rfc5737"] is False

    # 5. Loopback & Link-Local
    loop = classify_ip_network("127.0.0.1")
    assert loop["category"] == "Loopback (RFC 1122)"
    assert loop["is_private_rfc1918"] is False

    link = classify_ip_network("169.254.10.20")
    assert link["category"] == "Link-Local (RFC 3927 / RFC 4291)"
    assert link["is_private_rfc1918"] is False


def test_security_check_mode_a_target_filter_omitted_vs_specified(isolated_test_db):
    """Requirement 2: Verify Target Hit Count semantics when filter is omitted vs specified."""
    # Seed 3 distinct alerts for 203.0.113.11
    alerts_data = [
        {"timestamp": "2026-10-25T17:00:00Z", "source": "part1", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.5", "dst_port": 22, "label": "BruteForce", "confidence": 0.99, "is_synthetic": False},
        {"timestamp": "2026-10-25T17:05:00Z", "source": "part1", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.5", "dst_port": 80, "label": "DoS", "confidence": 0.98, "is_synthetic": False},
        {"timestamp": "2026-10-25T17:10:00Z", "source": "part2", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.15", "dst_port": 443, "label": "Anomaly", "confidence": 0.97, "is_synthetic": True},
    ]
    for a in alerts_data:
        insert_alert(a, db_path=isolated_test_db)

    # 1. Filter omitted: both dst_ip and dst_port None
    res_unfiltered = analyze_ip_local("203.0.113.11", db_path=isolated_test_db)
    assert res_unfiltered["success"] is True
    assert res_unfiltered["filter_applied"] is False
    assert res_unfiltered["total_alerts_for_ip"] == 3
    assert res_unfiltered["target_filter_matches"] == 3
    assert "All targets included (no target filter supplied)" in res_unfiltered["filter_summary"]
    assert sorted(res_unfiltered["destination_hosts"]) == ["192.168.10.15", "192.168.10.5"]
    assert res_unfiltered["destination_breakdown"]["192.168.10.5"] == 2
    assert res_unfiltered["destination_breakdown"]["192.168.10.15"] == 1
    assert res_unfiltered["port_breakdown"][22] == 1
    assert res_unfiltered["port_breakdown"][80] == 1
    assert res_unfiltered["port_breakdown"][443] == 1

    # 2. Filter specified by port: dst_port=22
    res_port = analyze_ip_local("203.0.113.11", dst_port=22, db_path=isolated_test_db)
    assert res_port["filter_applied"] is True
    assert res_port["total_alerts_for_ip"] == 3
    assert res_port["target_filter_matches"] == 1
    assert "dst_port=22" in res_port["filter_summary"]

    # 3. Filter specified by destination IP: dst_ip="192.168.10.5"
    res_dst = analyze_ip_local("203.0.113.11", dst_ip="192.168.10.5", db_path=isolated_test_db)
    assert res_dst["filter_applied"] is True
    assert res_dst["total_alerts_for_ip"] == 3
    assert res_dst["target_filter_matches"] == 2
    assert "dst_ip=192.168.10.5" in res_dst["filter_summary"]

    # 4. Filter specified with zero matches
    res_zero = analyze_ip_local("203.0.113.11", dst_port=8080, db_path=isolated_test_db)
    assert res_zero["filter_applied"] is True
    assert res_zero["total_alerts_for_ip"] == 3
    assert res_zero["target_filter_matches"] == 0


def test_security_check_mode_a_correlated_incident_and_risk_reconciliation(isolated_test_db):
    """Requirement 3 & 4: Verify correlated incident risk reconciliation vs host telemetry profile."""
    # Seed multi-flow alert sequence to trigger correlation engine
    alerts_data = [
        {"timestamp": "2026-10-25T17:00:00Z", "source": "part1", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.5", "dst_port": 22, "label": "PortScan", "confidence": 0.95, "is_synthetic": False},
        {"timestamp": "2026-10-25T17:05:00Z", "source": "part1", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.5", "dst_port": 22, "label": "BruteForce", "confidence": 0.99, "is_synthetic": False},
        {"timestamp": "2026-10-25T17:10:00Z", "source": "part1", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.5", "dst_port": 80, "label": "DoS", "confidence": 1.0, "is_synthetic": False},
    ]
    for a in alerts_data:
        insert_alert(a, db_path=isolated_test_db)

    # 1. Correlate directly to verify expected incident values
    stored = get_alerts(db_path=isolated_test_db)
    incidents = correlate_alerts(stored, time_window_minutes=30)
    assert len(incidents) == 1
    expected_inc = incidents[0]

    # 2. Perform Mode A investigation
    inv = analyze_ip_local("203.0.113.11", db_path=isolated_test_db)
    assert inv["success"] is True

    # Reconciled correlated incident fields
    assert inv["correlated_incident_id"] == expected_inc["incident_id"]
    assert inv["correlated_severity"] == expected_inc["severity"]
    assert inv["correlated_risk_score"] == expected_inc["risk_score"]
    assert inv["correlated_threat_pattern"] == expected_inc["threat_pattern"]
    assert inv["correlated_rationale"] == expected_inc["scoring_rationale"]

    # Host-level telemetry profile is distinct from incident risk score and model confidence
    assert inv["host_threat_profile"] == "Active Multi-Vector Threat Actor"
    assert inv["peak_confidence"] == 1.0
    assert "TEST-NET-3, RFC 5737" in inv["soc_finding"]

    # 3. Clean IP with no activity has no fabricated risk score or false maliciousness
    clean_inv = analyze_ip_local("10.0.0.99", db_path=isolated_test_db)
    assert clean_inv["success"] is True
    assert clean_inv["correlated_incident_id"] is None
    assert clean_inv["correlated_risk_score"] is None
    assert clean_inv["host_threat_profile"] == "Clean / No Recorded Local Activity"
    assert "No historical security alerts have been logged" in clean_inv["soc_finding"]
    assert "An IP address alone cannot establish whether a host is malicious without telemetry" in clean_inv["soc_finding"]


def test_api_new_endpoints_for_react_frontend(api_client, isolated_test_db):
    """Verify new additive endpoints for React frontend: /stats/overview, /incidents, /security-check/*, /pdf."""
    # Seed alerts
    alerts_data = [
        {"timestamp": "2026-10-25T17:00:00Z", "source": "part1", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.5", "dst_port": 22, "label": "PortScan", "confidence": 0.95, "is_synthetic": False},
        {"timestamp": "2026-10-25T17:05:00Z", "source": "part1", "src_ip": "203.0.113.11", "dst_ip": "192.168.10.5", "dst_port": 22, "label": "BruteForce", "confidence": 0.99, "is_synthetic": False},
    ]
    for a in alerts_data:
        insert_alert(a, db_path=isolated_test_db)

    # 1. /stats/overview
    r_ov = api_client.get("/stats/overview")
    assert r_ov.status_code == 200
    ov_data = r_ov.json()
    assert ov_data["total_alerts"] == 2
    assert ov_data["correlated_incidents"] == 1
    assert "top_destinations" in ov_data
    assert "severity_distribution" in ov_data

    # 2. /incidents
    r_inc = api_client.get("/incidents?time_window_minutes=15")
    assert r_inc.status_code == 200
    inc_list = r_inc.json()
    assert len(inc_list) == 1
    inc_id = inc_list[0]["incident_id"]

    # 3. /incidents/{incident_id}
    r_single = api_client.get(f"/incidents/{inc_id}")
    assert r_single.status_code == 200
    assert r_single.json()["src_ip"] == "203.0.113.11"

    # 4. /security-check/analyze-ip
    with mock.patch("part3.security_check.get_connection", lambda db=None: get_connection(isolated_test_db)):
        r_mode_a = api_client.post("/security-check/analyze-ip", json={"src_ip": "203.0.113.11"})
        assert r_mode_a.status_code == 200
        assert r_mode_a.json()["total_alerts_for_ip"] == 2
        assert r_mode_a.json()["network_info"]["is_documentation_rfc5737"] is True

    # 5. /security-check/parse-log
    r_mode_c = api_client.post("/security-check/parse-log", json={"raw_log": "Failed password for root from 203.0.113.11 port 22 ssh2"})
    assert r_mode_c.status_code == 200
    assert r_mode_c.json()["extracted_src_ip"] == "203.0.113.11"

    # 6. /incidents/{incident_id}/report
    r_rep = api_client.post(f"/incidents/{inc_id}/report")
    assert r_rep.status_code == 200
    assert all(k in r_rep.json() for k in ["what", "evidence", "severity", "action"])

    # 7. /incidents/{incident_id}/pdf
    r_pdf = api_client.get(f"/incidents/{inc_id}/pdf")
    assert r_pdf.status_code == 200
    assert r_pdf.content.startswith(b"%PDF")
    assert "Content-Disposition" in r_pdf.headers


def test_api_llm_status_and_report_with_engine(api_client, isolated_test_db):
    """Verify /llm/status endpoint and report generation with engine query parameter."""
    # Ingest test alert
    api_client.post("/alert", json={
        "timestamp": "2026-10-25T14:00:00Z",
        "source": "part1",
        "src_ip": "198.51.100.77",
        "dst_ip": "192.168.10.5",
        "dst_port": 80,
        "label": "DoS",
        "confidence": 0.99,
        "is_synthetic": False,
    })

    # Test /llm/status
    r_status = api_client.get("/llm/status")
    assert r_status.status_code == 200
    status_data = r_status.json()
    assert "active_default" in status_data
    assert "ollama" in status_data
    assert "gemini" in status_data
    assert "available" in status_data["ollama"]

    # Retrieve incident ID
    r_inc = api_client.get("/incidents")
    assert r_inc.status_code == 200
    inc_id = r_inc.json()[0]["incident_id"]

    # Test report with explicit heuristic engine
    r_rep = api_client.post(f"/incidents/{inc_id}/report?engine=heuristic")
    assert r_rep.status_code == 200
    rep_data = r_rep.json()
    assert rep_data["metadata"]["generator"] == "Deterministic SOC Analyst Engine (Offline)"
    assert rep_data["metadata"]["fallback_used"] is False

    # Test report with explicit ollama engine (mocked)
    with mock.patch("part3.report_generator.generate_llm_report_with_ollama", return_value=(
        {"what": "Ollama What", "evidence": "Ollama Evidence", "severity": "HIGH", "action": "Block"},
        {"generator": "ollama/llama3", "model": "llama3", "fallback_used": False, "error_category": None, "risk_score": 7.0, "is_synthetic": False}
    )):
        r_ollama = api_client.post(f"/incidents/{inc_id}/report?engine=ollama&model=llama3")
        assert r_ollama.status_code == 200
        assert r_ollama.json()["metadata"]["generator"] == "ollama/llama3"




