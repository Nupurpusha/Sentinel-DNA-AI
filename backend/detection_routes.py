"""
SentinelDNA — Step 2 detection API routes.
All routes are prefixed with /sentinel-api and registered on the main app.
"""

import json
from typing import Optional

import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from fastapi import APIRouter, HTTPException, Query

from database import get_connection
from detector import run_detection

router = APIRouter(prefix="/sentinel-api")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _detection_row(r) -> dict:
    d = dict(r)
    d["auth_success"] = bool(d.get("auth_success", 0))
    try:
        d["reasons"] = json.loads(d.get("reasons", "[]"))
    except Exception:
        d["reasons"] = []
    return d


def _detection_exists(conn) -> int:
    try:
        row = conn.execute("SELECT COUNT(*) AS n FROM detection_results").fetchone()
        return row["n"] if row else 0
    except Exception:
        return 0


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.post("/detection/run")
def run_detection_endpoint(force: bool = Query(False)):
    """Train Isolation Forest model and score all events. Safe to call repeatedly."""
    try:
        result = run_detection(force=force)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/detection/status")
def detection_status():
    """Check whether detection results exist."""
    conn = get_connection()
    try:
        count = _detection_exists(conn)
    finally:
        conn.close()
    return {"has_results": count > 0, "scored_events": count}


@router.get("/detection/summary")
def detection_summary():
    """High-level detection statistics for the SOC Overview dashboard."""
    conn = get_connection()
    try:
        count = _detection_exists(conn)
        if count == 0:
            return {"has_results": False}

        detected = conn.execute(
            "SELECT COUNT(*) AS n FROM detection_results WHERE predicted_anomaly = 1"
        ).fetchone()["n"]

        high_critical = conn.execute(
            "SELECT COUNT(*) AS n FROM detection_results WHERE risk_level IN ('High', 'Critical')"
        ).fetchone()["n"]

        avg_row = conn.execute(
            "SELECT AVG(risk_score) AS avg FROM detection_results"
        ).fetchone()
        avg_risk = avg_row["avg"] if avg_row and avg_row["avg"] is not None else 0

        by_level_rows = conn.execute(
            "SELECT risk_level, COUNT(*) AS cnt FROM detection_results GROUP BY risk_level ORDER BY cnt DESC"
        ).fetchall()
    finally:
        conn.close()

    return {
        "has_results": True,
        "total_scored": count,
        "detected_anomalies": detected,
        "high_critical_count": high_critical,
        "avg_risk_score": round(float(avg_risk), 1),
        "by_risk_level": {r["risk_level"]: r["cnt"] for r in by_level_rows},
    }


@router.get("/detection/events")
def detection_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    risk_level: Optional[str] = None,
    predicted_anomaly: Optional[bool] = None,
    entity_id: Optional[str] = None,
):
    """Paginated scored events joined with raw event data."""
    conn = get_connection()
    try:
        if _detection_exists(conn) == 0:
            return {"total": 0, "page": page, "page_size": page_size, "total_pages": 0, "events": []}

        where: list = []
        params: list = []
        if risk_level:
            where.append("dr.risk_level = ?")
            params.append(risk_level)
        if predicted_anomaly is not None:
            where.append("dr.predicted_anomaly = ?")
            params.append(1 if predicted_anomaly else 0)
        if entity_id:
            where.append("dr.entity_id = ?")
            params.append(entity_id)

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        total = conn.execute(
            f"SELECT COUNT(*) AS n FROM detection_results dr {where_sql}", params
        ).fetchone()["n"]

        offset = (page - 1) * page_size
        rows = conn.execute(
            f"""
            SELECT dr.*, e.timestamp, e.source_ip, e.geo_location, e.resource_accessed,
                   e.auth_method, e.auth_success, e.session_duration, e.device_fingerprint,
                   e.entity_type, e.department, e.label
            FROM detection_results dr
            JOIN events e ON dr.event_id = e.event_id
            {where_sql}
            ORDER BY dr.risk_score DESC, e.timestamp DESC
            LIMIT ? OFFSET ?
            """,
            params + [page_size, offset],
        ).fetchall()
    finally:
        conn.close()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "events": [_detection_row(r) for r in rows],
    }


@router.get("/detection/high-risk")
def detection_high_risk(limit: int = Query(20, ge=1, le=100)):
    """Top High and Critical risk events for the SOC Overview recent-events table."""
    conn = get_connection()
    try:
        if _detection_exists(conn) == 0:
            return {"events": []}

        rows = conn.execute(
            """
            SELECT dr.*, e.timestamp, e.source_ip, e.geo_location, e.resource_accessed,
                   e.auth_method, e.auth_success, e.session_duration, e.device_fingerprint,
                   e.entity_type, e.department, e.label
            FROM detection_results dr
            JOIN events e ON dr.event_id = e.event_id
            WHERE dr.risk_level IN ('High', 'Critical')
            ORDER BY dr.risk_score DESC, e.timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()

    return {"events": [_detection_row(r) for r in rows]}


@router.get("/detection/metrics")
def detection_metrics():
    """
    Model evaluation using ground-truth labels.
    Labels are used ONLY here, after predictions — never during training or scoring.
    """
    conn = get_connection()
    try:
        if _detection_exists(conn) == 0:
            return {"has_results": False}

        rows = conn.execute(
            """
            SELECT dr.predicted_anomaly, dr.risk_score, e.label
            FROM detection_results dr
            JOIN events e ON dr.event_id = e.event_id
            """
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return {"has_results": False}

    y_true = np.array([0 if r["label"] == "normal" else 1 for r in rows])
    y_pred = np.array([r["predicted_anomaly"] for r in rows])
    y_scores = np.array([r["risk_score"] for r in rows])

    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall    = float(recall_score(y_true, y_pred, zero_division=0))
    f1        = float(f1_score(y_true, y_pred, zero_division=0))
    cm        = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    try:
        roc_auc: Optional[float] = float(roc_auc_score(y_true, y_scores))
    except Exception:
        roc_auc = None

    return {
        "has_results": True,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_negatives": int(tn),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "total_true_anomalies": int(y_true.sum()),
        "total_predicted_anomalies": int(y_pred.sum()),
        "note": (
            "Ground-truth attack labels are used ONLY for this offline evaluation "
            "and are NOT inputs to the model."
        ),
    }


@router.get("/detection/top-identities")
def detection_top_identities(limit: int = Query(10, ge=1, le=50)):
    """Highest-risk identities by average risk score."""
    conn = get_connection()
    try:
        if _detection_exists(conn) == 0:
            return {"identities": []}

        rows = conn.execute(
            """
            SELECT dr.entity_id,
                   i.entity_type,
                   i.department,
                   ROUND(AVG(dr.risk_score), 1)  AS avg_risk_score,
                   MAX(dr.risk_score)             AS max_risk_score,
                   SUM(dr.predicted_anomaly)      AS detected_anomalies,
                   COUNT(*)                       AS total_events,
                   MAX(dr.risk_level)             AS max_risk_level
            FROM detection_results dr
            JOIN identities i ON dr.entity_id = i.entity_id
            GROUP BY dr.entity_id
            ORDER BY avg_risk_score DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()

    return {"identities": [dict(r) for r in rows]}


@router.get("/detection/risk-trend")
def detection_risk_trend():
    """Anomaly counts and average risk score grouped by day for the trend chart."""
    conn = get_connection()
    try:
        if _detection_exists(conn) == 0:
            return {"trend": []}

        rows = conn.execute(
            """
            SELECT substr(e.timestamp, 1, 10)   AS day,
                   COUNT(*)                     AS total_events,
                   SUM(dr.predicted_anomaly)    AS anomalies,
                   ROUND(AVG(dr.risk_score), 1) AS avg_risk_score
            FROM detection_results dr
            JOIN events e ON dr.event_id = e.event_id
            GROUP BY day
            ORDER BY day ASC
            """
        ).fetchall()
    finally:
        conn.close()

    return {"trend": [dict(r) for r in rows]}


@router.get("/identities/{entity_id}/risk")
def identity_risk(entity_id: str):
    """ML-derived risk summary for a specific identity."""
    conn = get_connection()
    try:
        ident_row = conn.execute(
            "SELECT entity_id FROM identities WHERE entity_id = ?", (entity_id,)
        ).fetchone()
        if not ident_row:
            raise HTTPException(status_code=404, detail=f"Identity '{entity_id}' not found")

        if _detection_exists(conn) == 0:
            return {"has_results": False, "entity_id": entity_id}

        risk_rows = conn.execute(
            """
            SELECT dr.*, e.timestamp, e.source_ip, e.geo_location,
                   e.resource_accessed, e.auth_method, e.auth_success, e.session_duration
            FROM detection_results dr
            JOIN events e ON dr.event_id = e.event_id
            WHERE dr.entity_id = ?
            ORDER BY dr.risk_score DESC
            """,
            (entity_id,),
        ).fetchall()
    finally:
        conn.close()

    if not risk_rows:
        return {"has_results": False, "entity_id": entity_id}

    scores = [r["risk_score"] for r in risk_rows]
    avg_risk = round(sum(scores) / len(scores), 1)
    max_risk = max(scores)
    detected = sum(1 for r in risk_rows if r["predicted_anomaly"])

    def _level(s: int) -> str:
        if s >= 76: return "Critical"
        if s >= 51: return "High"
        if s >= 26: return "Medium"
        return "Low"

    recent_anomalies = [_detection_row(dict(r)) for r in risk_rows if r["predicted_anomaly"]][:5]

    return {
        "has_results": True,
        "entity_id": entity_id,
        "avg_risk_score": avg_risk,
        "max_risk_score": max_risk,
        "risk_level": _level(max_risk),
        "detected_anomalies": detected,
        "total_events": len(risk_rows),
        "recent_anomalies": recent_anomalies,
    }
