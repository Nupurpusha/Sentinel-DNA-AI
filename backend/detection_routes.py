"""
SentinelDNA — Step 2 + Step 3 detection API routes.
All routes are prefixed with /sentinel-api and registered on the main app.

Step 3 additions:
  GET  /detection/priority-alerts   — Top-1% alert queue (ranked by final_risk_score)
  GET  /detection/alert-budget      — 0.5/1/2/5% budget analysis (post-hoc ground truth)
  GET  /detection/attack-coverage   — Detection coverage by attack type at Top-1%
  GET  /detection/top1-metrics      — Top-1% KPI: precision, attack coverage, count
  GET  /detection/status            — Now includes label_leakage_test_passed

All existing Step 2 endpoints preserved without modification.
"""

import json
import math
from typing import Optional

import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from fastapi import APIRouter, HTTPException, Query

from database import get_connection
from detector import run_detection, compute_alert_budget
from temporal import calculate_temporal_drift

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


def _get_meta(conn, key: str, default=None):
    """Retrieve a value from detection_meta table."""
    try:
        row = conn.execute("SELECT value FROM detection_meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    except Exception:
        return default


@router.get("/detection/temporal/{entity_id}")
def detection_temporal(entity_id: str):
    """Return explainable temporal drift intelligence for one identity."""
    conn = get_connection()
    try:
        result = calculate_temporal_drift(conn, entity_id)
    finally:
        conn.close()
    if result is None:
        raise HTTPException(status_code=404, detail=f"Identity '{entity_id}' not found")
    return result


# ─── Step 2 routes (preserved) ───────────────────────────────────────────────

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
    """Check whether detection results exist, and label leakage test result."""
    conn = get_connection()
    try:
        count   = _detection_exists(conn)
        leakage = _get_meta(conn, "label_leakage_test_passed", "false")
    finally:
        conn.close()
    return {
        "has_results": count > 0,
        "scored_events": count,
        "label_leakage_test_passed": leakage == "true",
    }


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
        "has_results":       True,
        "total_scored":      count,
        "detected_anomalies": detected,
        "high_critical_count": high_critical,
        "avg_risk_score":    round(float(avg_risk), 1),
        "by_risk_level":     {r["risk_level"]: r["cnt"] for r in by_level_rows},
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

        where: list  = []
        params: list = []
        if risk_level:
            where.append("dr.risk_level = ?"); params.append(risk_level)
        if predicted_anomaly is not None:
            where.append("dr.predicted_anomaly = ?"); params.append(1 if predicted_anomaly else 0)
        if entity_id:
            where.append("dr.entity_id = ?"); params.append(entity_id)

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
        "total":       total,
        "page":        page,
        "page_size":   page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "events":      [_detection_row(r) for r in rows],
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
    Original model evaluation metrics (Step 2 output, preserved).
    Labels used ONLY here, after predictions — never during training or scoring.
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

    y_true  = np.array([0 if r["label"] == "normal" else 1 for r in rows])
    y_pred  = np.array([r["predicted_anomaly"] for r in rows])
    y_score = np.array([r["risk_score"] for r in rows])

    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall    = float(recall_score(y_true, y_pred, zero_division=0))
    f1        = float(f1_score(y_true, y_pred, zero_division=0))
    cm        = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    try:
        roc_auc: Optional[float] = float(roc_auc_score(y_true, y_score))
    except Exception:
        roc_auc = None

    return {
        "has_results":               True,
        "precision":                 round(precision, 4),
        "recall":                    round(recall, 4),
        "f1_score":                  round(f1, 4),
        "true_positives":            int(tp),
        "false_positives":           int(fp),
        "false_negatives":           int(fn),
        "true_negatives":            int(tn),
        "roc_auc":                   round(roc_auc, 4) if roc_auc is not None else None,
        "total_true_anomalies":      int(y_true.sum()),
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
    """ML-derived risk summary for a specific identity (Step 2 + Step 3 fields)."""
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

    scores   = [r["risk_score"] for r in risk_rows]
    avg_risk = round(sum(scores) / len(scores), 1)
    max_risk = max(scores)
    detected = sum(1 for r in risk_rows if r["predicted_anomaly"])

    # Step 3 aggregate behavioral stats
    beh_scores = [r["behavioral_deviation_score"] for r in risk_rows if "behavioral_deviation_score" in r.keys()]
    avg_behavioral = round(sum(beh_scores) / len(beh_scores), 1) if beh_scores else None
    ev_counts = [r["evidence_count"] for r in risk_rows if "evidence_count" in r.keys()]
    avg_evidence = round(sum(ev_counts) / len(ev_counts), 1) if ev_counts else None

    def _level(s: int) -> str:
        if s >= 80: return "Critical"
        if s >= 65: return "High"
        if s >= 45: return "Medium"
        return "Low"

    recent_anomalies = [_detection_row(dict(r)) for r in risk_rows if r["predicted_anomaly"]][:5]

    return {
        "has_results":                 True,
        "entity_id":                   entity_id,
        "avg_risk_score":              avg_risk,
        "max_risk_score":              max_risk,
        "risk_level":                  _level(max_risk),
        "detected_anomalies":          detected,
        "total_events":                len(risk_rows),
        "avg_behavioral_deviation":    avg_behavioral,
        "avg_evidence_count":          avg_evidence,
        "recent_anomalies":            recent_anomalies,
    }


# ─── Step 3 routes (new) ─────────────────────────────────────────────────────

@router.get("/detection/priority-alerts")
def detection_priority_alerts(budget_pct: float = Query(1.0, ge=0.1, le=10.0)):
    """
    Priority Alert Queue: top-N% of events ranked by final_risk_score (DESC).

    Events are ranked using unsupervised behavioral risk only.
    Ground-truth labels are NOT used for ranking — they are included in the
    response payload for display context only.

    budget_pct: percentage of total events to include (default 1.0 = Top 1%).
    """
    conn = get_connection()
    try:
        if _detection_exists(conn) == 0:
            return {"alerts": [], "total_events": 0, "alert_count": 0, "budget_pct": budget_pct}

        total_row = conn.execute("SELECT COUNT(*) AS n FROM detection_results").fetchone()
        total     = total_row["n"] if total_row else 0
        n_alerts  = max(1, int(round(total * budget_pct / 100)))

        rows = conn.execute(
            """
            SELECT dr.event_id, dr.entity_id, dr.risk_score, dr.risk_level,
                   dr.behavioral_deviation_score, dr.evidence_count,
                   dr.ml_score_norm, dr.reasons,
                   e.timestamp, e.entity_type, e.geo_location, e.resource_accessed, e.label
            FROM detection_results dr
            JOIN events e ON dr.event_id = e.event_id
            ORDER BY dr.risk_score DESC
            LIMIT ?
            """,
            (n_alerts,),
        ).fetchall()
    finally:
        conn.close()

    alerts = []
    for r in rows:
        try:
            reasons = json.loads(r["reasons"])
        except Exception:
            reasons = []
        alerts.append({
            "event_id":                  r["event_id"],
            "entity_id":                 r["entity_id"],
            "entity_type":               r["entity_type"],
            "timestamp":                 r["timestamp"],
            "risk_score":                r["risk_score"],
            "risk_level":                r["risk_level"],
            "ml_score_norm":             r["ml_score_norm"],
            "behavioral_deviation_score": r["behavioral_deviation_score"],
            "evidence_count":            r["evidence_count"],
            "primary_reason":            reasons[0] if reasons else "—",
            "reasons":                   reasons,
            "resource_accessed":         r["resource_accessed"],
            "geo_location":              r["geo_location"],
            "label":                     r["label"],   # included for UI display context only
        })

    return {
        "alerts":      alerts,
        "total_events": total,
        "alert_count": n_alerts,
        "budget_pct":  budget_pct,
    }


@router.get("/detection/top1-metrics")
def detection_top1_metrics():
    """
    Top-1% KPI metrics for the SOC Overview dashboard:
      - TOP-1% ALERT PRECISION: fraction of top-1% alerts that are genuine attacks
      - ATTACK COVERAGE @ TOP 1%: fraction of all true attacks captured in top-1%
      - TOP-1% ALERT COUNT

    Rankings are computed from final_risk_score only (no label input).
    Ground truth is applied AFTER ranking to compute these metrics.
    """
    conn = get_connection()
    try:
        if _detection_exists(conn) == 0:
            return {"has_results": False}

        rows = conn.execute(
            """
            SELECT dr.risk_score, e.label
            FROM detection_results dr
            JOIN events e ON dr.event_id = e.event_id
            ORDER BY dr.risk_score DESC
            """
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return {"has_results": False}

    n_total      = len(rows)
    n_alerts     = max(1, int(round(n_total * 0.01)))
    y_true_all   = np.array([0 if r["label"] == "normal" else 1 for r in rows])
    total_attacks = int(y_true_all.sum())

    # Top-1% events (already sorted by risk_score DESC from query)
    top_labels   = y_true_all[:n_alerts]
    tp           = int(top_labels.sum())
    precision    = round(tp / n_alerts, 4)
    recall       = round(tp / max(total_attacks, 1), 4)
    f1_val       = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    return {
        "has_results":         True,
        "alert_count":         n_alerts,
        "total_events":        n_total,
        "total_attacks":       total_attacks,
        "true_positives":      tp,
        "false_positives":     n_alerts - tp,
        "precision":           precision,
        "recall":              recall,
        "f1_score":            f1_val,
        "note": (
            "Events ranked by unsupervised behavioral risk score. "
            "Ground-truth labels applied after ranking for offline evaluation only."
        ),
    }


@router.get("/detection/alert-budget")
def detection_alert_budget():
    """
    SOC Alert Budget Analysis: precision/recall/F1 at 0.5%, 1%, 2%, 5% cutoffs.

    Events are ranked by final_risk_score descending (no label input).
    Ground truth is applied ONLY after ranking to evaluate each cutoff.
    """
    conn = get_connection()
    try:
        if _detection_exists(conn) == 0:
            return {"has_results": False, "budgets": []}

        rows = conn.execute(
            """
            SELECT dr.risk_score, e.label
            FROM detection_results dr
            JOIN events e ON dr.event_id = e.event_id
            ORDER BY dr.risk_score DESC
            """
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return {"has_results": False, "budgets": []}

    n_total      = len(rows)
    y_true_ranked = np.array([0 if r["label"] == "normal" else 1 for r in rows])
    total_attacks = int(y_true_ranked.sum())

    budgets = []
    for pct in [0.5, 1.0, 2.0, 5.0]:
        n_alerts  = max(1, int(round(n_total * pct / 100)))
        top       = y_true_ranked[:n_alerts]
        tp        = int(top.sum())
        fp        = n_alerts - tp
        fn        = total_attacks - tp
        prec      = round(tp / n_alerts, 4) if n_alerts > 0 else 0.0
        rec       = round(tp / max(total_attacks, 1), 4)
        f1_val    = round(2 * prec * rec / (prec + rec), 4) if (prec + rec) > 0 else 0.0
        budgets.append({
            "budget_pct":     pct,
            "alert_count":    n_alerts,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision":      prec,
            "recall":         rec,
            "f1_score":       f1_val,
        })

    return {
        "has_results":  True,
        "total_events": n_total,
        "total_attacks": total_attacks,
        "budgets":      budgets,
        "note": (
            "Events are ranked using unsupervised behavioral risk. "
            "Ground-truth labels are applied only after ranking for offline evaluation."
        ),
    }


@router.get("/detection/attack-coverage")
def detection_attack_coverage():
    """
    Detection coverage by attack type at the Top-1% alert budget.

    Shows how many true attacks of each category are captured in the
    highest-risk 1% of events. Rankings use final_risk_score only.
    Labels are used ONLY to evaluate after ranking.
    """
    conn = get_connection()
    try:
        if _detection_exists(conn) == 0:
            return {"has_results": False, "coverage": []}

        rows = conn.execute(
            """
            SELECT dr.risk_score, e.label
            FROM detection_results dr
            JOIN events e ON dr.event_id = e.event_id
            ORDER BY dr.risk_score DESC
            """
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return {"has_results": False, "coverage": []}

    n_total  = len(rows)
    n_alerts = max(1, int(round(n_total * 0.01)))

    # All events ranked; apply labels post-hoc
    all_labels   = [r["label"] for r in rows]
    top1_labels  = all_labels[:n_alerts]

    # Find all attack categories (exclude "normal")
    from collections import Counter
    all_counts  = Counter(l for l in all_labels if l != "normal")
    top1_counts = Counter(l for l in top1_labels if l != "normal")

    coverage = []
    for attack_type, total_gt in sorted(all_counts.items(), key=lambda x: -x[1]):
        captured  = top1_counts.get(attack_type, 0)
        pct       = round(captured / max(total_gt, 1) * 100, 1)
        coverage.append({
            "attack_type":   attack_type,
            "total_gt":      total_gt,
            "captured_top1": captured,
            "coverage_pct":  pct,
        })

    return {
        "has_results":   True,
        "total_events":  n_total,
        "alert_count":   n_alerts,
        "budget_pct":    1.0,
        "coverage":      coverage,
        "note": (
            "Attack categories are applied ONLY after ranking to measure coverage. "
            "They are not used during scoring or ranking."
        ),
    }
