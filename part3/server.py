"""FastAPI ingestion server for Part 3 SOC Dashboard.

Exposes:
- POST /alert: Ingests, validates, deduplicates, and stores flow alerts.
- GET /alerts: Retrieves alerts with filtering (label, source, src_ip, is_synthetic) and pagination.
- GET /stats: Returns aggregated telemetry metrics.
- DELETE /alerts: Clears alert history with deleted count confirmation.
- GET /health: Service health and readiness probe.
"""
import ipaddress
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import dateutil.parser
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

# Ensure part3 is in python path
sys.path.append(str(Path(__file__).parent.parent))
from part3.db import clear_alerts, get_alerts, get_alerts_count, get_stats, init_db, insert_alert
from part3.correlation import correlate_alerts
from part3.security_check import analyze_ip_local, parse_network_log, submit_structured_alert
from part3.report_generator import generate_incident_report, export_report_to_pdf, check_ollama_status

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="SOC Alert Receiver",
    description="Part 3: Receives, stores, and serves alerts from IDS detectors (Part 1 & Part 2).",
    version="1.1.0",
    lifespan=lifespan,
)

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8501",
    "http://127.0.0.1:8501",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count", "X-Limit", "X-Offset", "Content-Disposition"],
)


class AlertPayload(BaseModel):
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp (e.g. 2026-10-25T17:30:00Z)")
    source: str = Field(..., min_length=1, max_length=50, description="Detector identifier: 'part1', 'part2', 'mock', etc.")
    src_ip: str = Field(..., min_length=3, max_length=50, description="Attacker IPv4 or IPv6 address")
    dst_ip: str = Field(..., min_length=3, max_length=50, description="Destination target IP address")
    dst_port: int = Field(..., ge=0, le=65535, description="Target destination port (0-65535)")
    label: str = Field(..., min_length=1, max_length=50, description="Threat classification label")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence or percentile score (0.0 to 1.0)")
    top_features: Dict[str, Any] = Field(default_factory=dict, description="Top anomalous feature contributions")
    is_synthetic: bool = Field(default=False, description="True if alert was generated synthetically by mock tools")
    src_port: Optional[int] = Field(default=None, description="Optional source port")
    protocol: Optional[str] = Field(default=None, description="Optional network protocol")
    severity: Optional[str] = Field(default=None, description="Optional severity indicator")

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        try:
            dateutil.parser.isoparse(v)
            return v
        except Exception:
            raise ValueError(f"Invalid ISO 8601 timestamp format: {v}")

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        # Validate that it is either a valid IP address or standard host identifier
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            # Allow placeholder simulation hostnames if valid regex
            if re.match(r"^[a-zA-Z0-9.-]+$", v):
                return v
            raise ValueError(f"Invalid IP address format: {v}")


@app.get("/health")
def health():
    return {"status": "healthy", "service": "soc-alert-receiver", "version": "1.1.0"}


@app.post("/alert", status_code=status.HTTP_200_OK)
@app.post("/alerts", status_code=status.HTTP_200_OK)
def receive_alert(alert: AlertPayload, allow_duplicate: bool = Query(False)):
    try:
        alert_dict = alert.model_dump() if hasattr(alert, "model_dump") else alert.dict()
        alert_id, is_duplicate = insert_alert(alert_dict, allow_duplicate=allow_duplicate)
        return {
            "status": "ok",
            "id": alert_id,
            "duplicate": is_duplicate,
            "is_synthetic": alert.is_synthetic or alert.source == "mock",
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to ingest alert: {str(e)}")


@app.get("/alerts")
def list_alerts(
    response: Response,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    label: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    is_synthetic: Optional[bool] = Query(None),
):
    total = get_alerts_count(label=label, source=source, src_ip=src_ip, is_synthetic=is_synthetic)
    alerts = get_alerts(
        limit=limit,
        offset=offset,
        label=label,
        source=source,
        src_ip=src_ip,
        is_synthetic=is_synthetic,
    )
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Limit"] = str(limit)
    response.headers["X-Offset"] = str(offset)
    return alerts


@app.get("/stats")
def stats():
    return get_stats()


@app.delete("/alerts")
def reset_alerts():
    deleted_count = clear_alerts()
    return {"status": "ok", "deleted": deleted_count, "message": f"Cleared {deleted_count} alerts"}


class IPAnalysisRequest(BaseModel):
    src_ip: str
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    context: Optional[str] = None


class LogParseRequest(BaseModel):
    raw_log: str


@app.get("/stats/overview")
def stats_overview(time_window_minutes: int = Query(15, ge=1, le=120)):
    """Aggregated stats for React SOC Overview dashboard with correlated incident context."""
    base_stats = get_stats()
    alerts = get_alerts(limit=1000)
    incidents = correlate_alerts(alerts, time_window_minutes=time_window_minutes)

    critical_count = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
    high_count = sum(1 for i in incidents if i.get("severity") == "HIGH")
    medium_count = sum(1 for i in incidents if i.get("severity") == "MEDIUM")
    low_count = sum(1 for i in incidents if i.get("severity") == "LOW")

    # Severity distribution dictionary for charts
    severity_distribution = {
        "CRITICAL": critical_count,
        "HIGH": high_count,
        "MEDIUM": medium_count,
        "LOW": low_count,
    }

    return {
        **base_stats,
        "live_ml_alerts": base_stats.get("live_count", 0),
        "synthetic_alerts": base_stats.get("synthetic_count", 0),
        "label_distribution": base_stats.get("label_counts", {}),
        "top_sources": base_stats.get("top_ips", []),
        "correlated_incidents": len(incidents),
        "critical_incidents": critical_count,
        "high_incidents": high_count,
        "medium_incidents": medium_count,
        "low_incidents": low_count,
        "severity_distribution": severity_distribution,
        "incident_severity_distribution": severity_distribution,
        "correlation_window_minutes": time_window_minutes,
        "recent_incidents": [
            {
                "incident_id": i["incident_id"],
                "src_ip": i["src_ip"],
                "severity": i["severity"],
                "risk_score": i["risk_score"],
                "alert_count": i["alert_count"],
                "threat_pattern": i["threat_pattern"],
                "sequence_description": i["threat_pattern"],
                "labels": i.get("labels", []),
                "target_count": len(i.get("target_ips", [])),
                "is_synthetic": i.get("is_synthetic", False),
                "last_seen": i["last_seen"],
            }
            for i in incidents[:5]
        ],
    }


@app.get("/incidents")
def list_incidents(time_window_minutes: int = Query(15, ge=1, le=120)):
    """Retrieve correlated multi-flow security incidents clustered by configurable time window."""
    alerts = get_alerts(limit=1000)
    incidents = correlate_alerts(alerts, time_window_minutes=time_window_minutes)
    return incidents


@app.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: str, time_window_minutes: int = Query(15, ge=1, le=120)):
    """Retrieve details, threat progression, and raw alert flows for a specific correlated incident."""
    alerts = get_alerts(limit=1000)
    incidents = correlate_alerts(alerts, time_window_minutes=time_window_minutes)
    incident = next((i for i in incidents if i["incident_id"] == incident_id), None)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found.")
    return incident


@app.post("/security-check/analyze-ip")
def api_analyze_ip(req: IPAnalysisRequest):
    """Mode A: Investigates an IP address strictly against local SOC telemetry and network facts."""
    res = analyze_ip_local(
        src_ip=req.src_ip.strip(),
        dst_ip=req.dst_ip.strip() if req.dst_ip and req.dst_ip.strip() else None,
        dst_port=req.dst_port if req.dst_port and req.dst_port > 0 else None,
        protocol=req.protocol if req.protocol and req.protocol != "ANY" else None,
        context=req.context.strip() if req.context and req.context.strip() else None,
    )
    if not res.get("success", False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res.get("error", "IP investigation failed."))
    return res


@app.post("/security-check/parse-log")
def api_parse_log(req: LogParseRequest):
    """Mode C: Parses arbitrary network log strings for IOCs and inferred threat classifications."""
    res = parse_network_log(req.raw_log)
    if not res.get("success", False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res.get("error", "Log parsing failed."))
    return res


@app.get("/llm/status")
def api_llm_status():
    """Inspect availability of local Ollama instance and Google Gemini API."""
    import os
    ollama_info = check_ollama_status()
    gemini_key = os.getenv("GEMINI_API_KEY")
    gemini_available = bool(gemini_key and gemini_key.strip())

    active_default = "heuristic"
    if ollama_info.get("available"):
        active_default = "ollama"
    elif gemini_available:
        active_default = "gemini"

    return {
        "active_default": active_default,
        "ollama": ollama_info,
        "gemini": {
            "available": gemini_available,
            "model": "gemini-1.5-flash",
        },
    }


@app.post("/incidents/{incident_id}/report")
def api_generate_report(
    incident_id: str,
    time_window_minutes: int = Query(15, ge=1, le=120),
    engine: Optional[str] = Query("auto", description="LLM Engine: auto, ollama, gemini, heuristic"),
    model: Optional[str] = Query(None, description="Model identifier (e.g. llama3, llama3.2)"),
):
    """Generates structured SOC incident report (What, Evidence, Severity, Action)."""
    alerts = get_alerts(limit=1000)
    incidents = correlate_alerts(alerts, time_window_minutes=time_window_minutes)
    incident = next((i for i in incidents if i["incident_id"] == incident_id), None)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found.")
    report_data = generate_incident_report(incident, engine=engine, model=model)
    if "incident_id" not in report_data:
        report_data["incident_id"] = incident_id
    return report_data


@app.get("/incidents/{incident_id}/pdf")
def api_export_pdf(
    incident_id: str,
    time_window_minutes: int = Query(15, ge=1, le=120),
    engine: Optional[str] = Query("auto", description="LLM Engine: auto, ollama, gemini, heuristic"),
    model: Optional[str] = Query(None, description="Model identifier (e.g. llama3, llama3.2)"),
):
    """Compiles and streams executive PDF document for the correlated incident."""
    alerts = get_alerts(limit=1000)
    incidents = correlate_alerts(alerts, time_window_minutes=time_window_minutes)
    incident = next((i for i in incidents if i["incident_id"] == incident_id), None)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found.")
    report_data = generate_incident_report(incident, engine=engine, model=model)
    pdf_bytes = export_report_to_pdf(incident, report_data)
    filename = f"Incident_Report_{incident_id}_{incident['src_ip']}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )



if __name__ == "__main__":
    init_db()
    print("Starting SOC Alert Receiver on http://0.0.0.0:8000 ...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
