# Part 3: Dell Security Operations Center (SOC) + AI Incident Reporting

Central Security Operations Center (SOC) receiver, telemetry dashboard, incident correlation engine, and automated AI incident report generator.

Receives real-time alerts from:
- **Part 1**: Supervised Classifier (Random Forest: DoS, PortScan, BruteForce)
- **Part 2**: Zero-Day Anomaly Detector (Deep Autoencoder / Isolation Forest)
- **Mock Generator**: Simulated threat campaigns and live telemetry testing

---

## Modern React.js Architecture

The SOC dashboard has been modernized into a high-performance **React.js + Vite** single-page application located in `part3/frontend/`, backed by the asynchronous FastAPI service (`part3/server.py`) and SQLite telemetry storage (`part3/alerts.db`).

### Project Structure
- `frontend/`: Modern React.js Single-Page Application (Vite, React Router DOM, Recharts, Lucide React, Axios).
  - `src/pages/Overview.jsx`: Executive SOC Dashboard with 6 KPI metrics, 4 Recharts (Vector distribution, Top sources, Top targets, Incident severity), and recent incidents preview.
  - `src/pages/SecurityCheck.jsx`: Interactive Security Check featuring Mode A (Threat Actor IP deep analysis with RFC classification note and infrastructure breakdown), Mode B (Alert ingestion & validation), and Mode C (Syslog parser).
  - `src/pages/Incidents.jsx`: Multi-stage temporal incident correlation with configurable windows (5m, 15m, 30m, 60m), search, sortable table, and expandable evidence drawer.
  - `src/pages/Telemetry.jsx`: Paginated flow feed with multi-parameter filtering (Source IP, Vector, Detection Origin).
  - `src/pages/Reports.jsx`: 4-section executive incident briefing with ReportLab PDF binary export.
- `server.py`: FastAPI backend server exposing REST endpoints.
- `db.py`: SQLite persistence layer storing alert telemetry and metadata.
- `correlation.py`: Multi-stage attack correlation engine clustering alerts by IP and time window.
- `security_check.py`: RFC address classification and deep IP history analysis heuristics.
- `report_generator.py`: AI Incident Report Engine (What, Evidence, Severity, Action) + ReportLab PDF Exporter.
- `dashboard.py`: Streamlit legacy dashboard (preserved for backwards compatibility).
- `mock_alerts.py`: Testing CLI simulating reconnaissance, brute force, DoS, and zero-day anomaly bursts.
- `tests/test_soc_cti.py`: Pytest suite with 25 unit and end-to-end integration tests.

---

## Quick Start Guide

### 1. Start the FastAPI Core Backend
From the root repository directory or `part3/`:

```bash
cd part3
python server.py
```
Backend API will be running on `http://127.0.0.1:8000`.

### 2. Start the React.js SOC Dashboard
In a separate terminal:

```bash
cd part3/frontend
npm install
npm run dev
```
Open your browser at:
`http://localhost:5173`

*(Optional)* To compile a production build:
```bash
npm run build
```

---

## API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check and telemetry database connectivity |
| `GET` | `/stats` | Aggregate alert counts and distributions |
| `GET` | `/stats/overview?time_window_minutes=15` | Overview bundle: KPIs, top destinations, incident severity |
| `GET` | `/alerts` | Paginated alert feed with limit, offset, and filters |
| `POST` | `/alerts` | Structured alert ingestion and deduplication |
| `DELETE` | `/alerts` | Purge telemetry database |
| `GET` | `/incidents?time_window_minutes=15` | Dynamic incident clustering by temporal window |
| `GET` | `/incidents/{id}?time_window_minutes=15` | Single incident details and correlated alert evidence |
| `POST` | `/security-check/analyze-ip` | Mode A deep threat actor analysis and RFC classification |
| `POST` | `/security-check/parse-log` | Mode C syslog and network flow parser |
| `POST` | `/incidents/{id}/report` | Generate 4-section executive incident report |
| `GET` | `/incidents/{id}/pdf` | Stream binary ReportLab PDF executive report |

---

## Running Test Suite

Run all 25 comprehensive unit, API, and integration tests:

```bash
pytest part3/tests/test_soc_cti.py -v
```

All 25 tests cover:
- API health, ingestion, deduplication, schema validation, and pagination.
- Correlation temporal grouping, chronological progression, and deterministic scoring.
- RFC 5737 vs RFC 1918 address classification and telemetry hit reconciliation.
- Gemini LLM fallback to local heuristic report generator.
- ReportLab XML safety and binary PDF generation.
- All new REST endpoints serving the React frontend.
