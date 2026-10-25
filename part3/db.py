"""SQLite storage and query layer for SOC alerts.

Supports:
- Schema initialization and auto-migration (adding columns like is_synthetic)
- Deduplication of identical incoming alerts
- Filtering, offset-based pagination, and total count queries
- Aggregated telemetry statistics (labels, sources, top IPs, top ports, synthetic vs live)
- Clean resets and transaction safety
"""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DB_PATH = Path(__file__).parent / "alerts.db"


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize alerts table and indexes with auto-migration."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER NOT NULL,
                label TEXT NOT NULL,
                confidence REAL NOT NULL,
                top_features TEXT NOT NULL,
                is_synthetic INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        # Auto-migrate if table existed without is_synthetic
        cursor = conn.execute("PRAGMA table_info(alerts)")
        columns = [row["name"] for row in cursor.fetchall()]
        if "is_synthetic" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN is_synthetic INTEGER DEFAULT 0")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_label ON alerts (label)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts (source)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_synthetic ON alerts (is_synthetic)")
    conn.close()


def find_duplicate_alert(
    alert_data: Dict[str, Any],
    conn: sqlite3.Connection,
) -> Optional[int]:
    """Check if an identical alert was already ingested (same timestamp, source, src_ip, dst_ip, dst_port, label)."""
    cursor = conn.execute(
        """
        SELECT id FROM alerts
        WHERE timestamp = ? AND source = ? AND src_ip = ? AND dst_ip = ? AND dst_port = ? AND label = ?
        LIMIT 1
        """,
        (
            alert_data.get("timestamp"),
            alert_data.get("source"),
            alert_data.get("src_ip"),
            alert_data.get("dst_ip"),
            int(alert_data.get("dst_port", 0)),
            alert_data.get("label"),
        ),
    )
    row = cursor.fetchone()
    return row["id"] if row else None


def insert_alert(
    alert_data: Dict[str, Any],
    db_path: Optional[Path] = None,
    allow_duplicate: bool = False,
) -> Tuple[int, bool]:
    """Insert a single alert dictionary and return (alert_id, is_duplicate)."""
    conn = get_connection(db_path)
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    top_features = alert_data.get("top_features", {})
    if isinstance(top_features, (dict, list)):
        top_features_json = json.dumps(top_features)
    else:
        top_features_json = str(top_features)

    is_synth = 1 if alert_data.get("is_synthetic") or alert_data.get("source") == "mock" else 0

    existing_id = None
    with conn:
        if not allow_duplicate:
            existing_id = find_duplicate_alert(alert_data, conn)

        if existing_id is None:
            cursor = conn.execute(
                """
                INSERT INTO alerts (timestamp, source, src_ip, dst_ip, dst_port, label, confidence, top_features, is_synthetic, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_data.get("timestamp", created_at),
                    alert_data.get("source", "unknown"),
                    alert_data.get("src_ip", "0.0.0.0"),
                    alert_data.get("dst_ip", "0.0.0.0"),
                    int(alert_data.get("dst_port", 0)),
                    alert_data.get("label", "Unknown"),
                    float(alert_data.get("confidence", 1.0)),
                    top_features_json,
                    is_synth,
                    created_at,
                ),
            )
            alert_id = cursor.lastrowid
            is_dup = False
        else:
            alert_id = existing_id
            is_dup = True

    conn.close()
    return alert_id, is_dup


def get_alerts(
    limit: int = 100,
    offset: int = 0,
    label: Optional[str] = None,
    source: Optional[str] = None,
    src_ip: Optional[str] = None,
    is_synthetic: Optional[bool] = None,
    db_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Retrieve alerts ordered by timestamp descending with optional filters."""
    conn = get_connection(db_path)
    query = "SELECT * FROM alerts WHERE 1=1"
    params: List[Any] = []

    if label:
        query += " AND label = ?"
        params.append(label)
    if source:
        query += " AND source = ?"
        params.append(source)
    if src_ip:
        query += " AND src_ip = ?"
        params.append(src_ip)
    if is_synthetic is not None:
        query += " AND is_synthetic = ?"
        params.append(1 if is_synthetic else 0)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor = conn.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        item = dict(row)
        item["is_synthetic"] = bool(item.get("is_synthetic", 0))
        try:
            item["top_features"] = json.loads(item["top_features"])
        except Exception:
            item["top_features"] = {}
        alerts.append(item)
    return alerts


def get_alerts_count(
    label: Optional[str] = None,
    source: Optional[str] = None,
    src_ip: Optional[str] = None,
    is_synthetic: Optional[bool] = None,
    db_path: Optional[Path] = None,
) -> int:
    """Retrieve total matching alert count for pagination calculation."""
    conn = get_connection(db_path)
    query = "SELECT COUNT(*) FROM alerts WHERE 1=1"
    params: List[Any] = []

    if label:
        query += " AND label = ?"
        params.append(label)
    if source:
        query += " AND source = ?"
        params.append(source)
    if src_ip:
        query += " AND src_ip = ?"
        params.append(src_ip)
    if is_synthetic is not None:
        query += " AND is_synthetic = ?"
        params.append(1 if is_synthetic else 0)

    count = conn.execute(query, params).fetchone()[0]
    conn.close()
    return count


def get_stats(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Calculate aggregated stats for SOC dashboard."""
    conn = get_connection(db_path)

    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    label_counts = {
        row[0]: row[1]
        for row in conn.execute("SELECT label, COUNT(*) FROM alerts GROUP BY label").fetchall()
    }

    source_counts = {
        row[0]: row[1]
        for row in conn.execute("SELECT source, COUNT(*) FROM alerts GROUP BY source").fetchall()
    }

    synthetic_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE is_synthetic = 1").fetchone()[0]
    live_count = total_alerts - synthetic_count

    top_ips = [
        {"src_ip": row[0], "count": row[1], "labels": row[2]}
        for row in conn.execute(
            """
            SELECT src_ip, COUNT(*) as count, GROUP_CONCAT(DISTINCT label) as labels
            FROM alerts
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 10
            """
        ).fetchall()
    ]

    top_ports = [
        {"dst_port": row[0], "count": row[1]}
        for row in conn.execute(
            """
            SELECT dst_port, COUNT(*) as count
            FROM alerts
            GROUP BY dst_port
            ORDER BY count DESC
            LIMIT 10
            """
        ).fetchall()
    ]

    top_destinations = [
        {"dst_ip": row[0], "count": row[1]}
        for row in conn.execute(
            """
            SELECT dst_ip, COUNT(*) as count
            FROM alerts
            GROUP BY dst_ip
            ORDER BY count DESC
            LIMIT 10
            """
        ).fetchall()
    ]

    conn.close()
    return {
        "total_alerts": total_alerts,
        "synthetic_count": synthetic_count,
        "live_count": live_count,
        "label_counts": label_counts,
        "source_counts": source_counts,
        "top_ips": top_ips,
        "top_ports": top_ports,
        "top_destinations": top_destinations,
    }


def clear_alerts(db_path: Optional[Path] = None) -> int:
    """Clear all alerts from table and return the number of cleared rows."""
    conn = get_connection(db_path)
    with conn:
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        conn.execute("DELETE FROM alerts")
    conn.close()
    return count
