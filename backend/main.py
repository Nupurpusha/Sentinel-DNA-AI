"""
SentinelDNA FastAPI backend.
All routes are prefixed with /sentinel-api (paths are not rewritten by the proxy).
"""

import csv
import io
import json
import sqlite3
from contextlib import asynccontextmanager
from typing import Optional

import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from database import DB_PATH, drop_all, get_connection, init_db
from generator import generate_dataset
from detector import run_detection
from detection_routes import router as detection_router
from baseline import MINIMUM_HISTORY_EVENTS, baseline_status

# ─── Lifespan: initialise DB and seed if empty ──────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    conn = get_connection()
    try:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM events").fetchone()
        event_count = row["cnt"] if row else 0
    finally:
        conn.close()

    if event_count == 0:
        print("No data found — generating synthetic dataset...")
        _do_generate()
    else:
        print(f"Database already contains {event_count} events — skipping generation.")

    # Step 2: run detection if not already done
    run_detection(force=False)
    yield


# ─── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SentinelDNA API",
    description="Synthetic cybersecurity access-log backend",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(detection_router)


# ─── Internal helper ──────────────────────────────────────────────────────────

def _do_generate():
    """Run the generator and persist results to SQLite."""
    identities, events = generate_dataset()

    conn = get_connection()
    try:
        conn.execute("BEGIN")
        conn.executemany(
            """INSERT OR REPLACE INTO identities
               (entity_id, entity_type, department, profile, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            [
                (
                    ident["entity_id"],
                    ident["entity_type"],
                    ident.get("department"),
                    json.dumps(ident["profile"]),
                    ident["created_at"],
                )
                for ident in identities
            ],
        )
        conn.executemany(
            """INSERT OR REPLACE INTO events
               (event_id, entity_id, entity_type, timestamp, source_ip,
                geo_location, latitude, longitude, resource_accessed,
                auth_method, auth_success, session_duration, command_sequence,
                device_fingerprint, department, label)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    ev["event_id"],
                    ev["entity_id"],
                    ev["entity_type"],
                    ev["timestamp"],
                    ev["source_ip"],
                    ev["geo_location"],
                    ev["latitude"],
                    ev["longitude"],
                    ev["resource_accessed"],
                    ev["auth_method"],
                    bool(ev["auth_success"]),
                    ev["session_duration"],
                    ev["command_sequence"],
                    ev["device_fingerprint"],
                    ev.get("department"),
                    ev["label"],
                )
                for ev in events
            ],
        )
        conn.commit()
        print(f"Persisted {len(identities)} identities and {len(events)} events.")
    except Exception as exc:
        conn.rollback()
        raise exc
    finally:
        conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    # Convert integer boolean back to bool
    if "auth_success" in d:
        d["auth_success"] = bool(d["auth_success"])
    # Deserialise JSON command_sequence
    if "command_sequence" in d and isinstance(d["command_sequence"], str):
        try:
            d["command_sequence"] = json.loads(d["command_sequence"])
        except Exception:
            pass
    return d


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/sentinel-api/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/sentinel-api/summary")
def get_summary():
    """Return high-level dataset statistics."""
    conn = get_connection()
    try:
        total = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        if total == 0:
            return {
                "total_events": 0,
                "total_identities": 0,
                "normal_count": 0,
                "anomaly_count": 0,
                "normal_pct": 0.0,
                "anomaly_pct": 0.0,
                "by_label": {},
                "by_entity_type": {},
                "by_department": {},
            }

        normal = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE label = 'normal'"
        ).fetchone()["n"]
        anomaly = total - normal

        by_label_rows = conn.execute(
            "SELECT label, COUNT(*) AS cnt FROM events GROUP BY label ORDER BY cnt DESC"
        ).fetchall()
        by_label = {r["label"]: r["cnt"] for r in by_label_rows}

        by_type_rows = conn.execute(
            "SELECT entity_type, COUNT(*) AS cnt FROM events GROUP BY entity_type"
        ).fetchall()
        by_entity_type = {r["entity_type"]: r["cnt"] for r in by_type_rows}

        by_dept_rows = conn.execute(
            "SELECT department, COUNT(*) AS cnt FROM events WHERE department IS NOT NULL GROUP BY department"
        ).fetchall()
        by_department = {r["department"]: r["cnt"] for r in by_dept_rows}

        id_count = conn.execute(
            "SELECT COUNT(*) AS n FROM identities"
        ).fetchone()["n"]

        return {
            "total_events": total,
            "total_identities": id_count,
            "normal_count": normal,
            "anomaly_count": anomaly,
            "normal_pct": round(100.0 * normal / total, 2),
            "anomaly_pct": round(100.0 * anomaly / total, 2),
            "by_label": by_label,
            "by_entity_type": by_entity_type,
            "by_department": by_department,
        }
    finally:
        conn.close()


@app.get("/sentinel-api/events")
def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    entity_id: Optional[str] = None,
    entity_type: Optional[str] = None,
    department: Optional[str] = None,
    label: Optional[str] = None,
    search: Optional[str] = None,
):
    """Return paginated events with optional filters."""
    conn = get_connection()
    try:
        where_clauses = []
        params: list = []

        if entity_id:
            where_clauses.append("entity_id = ?")
            params.append(entity_id)
        if entity_type:
            where_clauses.append("entity_type = ?")
            params.append(entity_type)
        if department:
            where_clauses.append("department = ?")
            params.append(department)
        if label:
            where_clauses.append("label = ?")
            params.append(label)
        if search:
            where_clauses.append("(entity_id LIKE ? OR geo_location LIKE ? OR resource_accessed LIKE ?)")
            params += [f"%{search}%", f"%{search}%", f"%{search}%"]

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        count_row = conn.execute(
            f"SELECT COUNT(*) AS n FROM events {where_sql}", params
        ).fetchone()
        total = count_row["n"]

        offset = (page - 1) * page_size
        rows = conn.execute(
            f"SELECT * FROM events {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [page_size, offset],
        ).fetchall()

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, (total + page_size - 1) // page_size),
            "events": [_row_to_dict(r) for r in rows],
        }
    finally:
        conn.close()


@app.get("/sentinel-api/identities")
def list_identities():
    """Return all identity summaries."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT entity_id, entity_type, department, created_at FROM identities ORDER BY entity_id"
        ).fetchall()
        return {"identities": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/sentinel-api/identities/{entity_id}")
def get_identity(entity_id: str):
    """Return an identity's behavioural profile and their event history."""
    conn = get_connection()
    try:
        ident_row = conn.execute(
            "SELECT * FROM identities WHERE entity_id = ?", (entity_id,)
        ).fetchone()
        if not ident_row:
            raise HTTPException(status_code=404, detail=f"Identity '{entity_id}' not found")

        ident = dict(ident_row)
        try:
            ident["profile"] = json.loads(ident["profile"])
        except Exception:
            pass

        events_rows = conn.execute(
            "SELECT * FROM events WHERE entity_id = ? ORDER BY timestamp DESC",
            (entity_id,),
        ).fetchall()
        events = [_row_to_dict(r) for r in events_rows]
        history_event_count = len(events)

        return {
            "identity": ident,
            "event_count": len(events),
            "history_event_count": history_event_count,
            "baseline_status": baseline_status(history_event_count),
            "minimum_history_events": MINIMUM_HISTORY_EVENTS,
            "events": events,
        }
    finally:
        conn.close()


@app.post("/sentinel-api/regenerate")
def regenerate():
    """Drop all data and regenerate the synthetic dataset from scratch."""
    try:
        drop_all()
        init_db()
        _do_generate()
        conn = get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        finally:
            conn.close()
        # Re-run detection on fresh data
        run_detection(force=True)
        return {"success": True, "total_events": count, "message": f"Dataset regenerated with {count} events."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/sentinel-api/export/csv")
def export_csv(
    entity_id: Optional[str] = None,
    label: Optional[str] = None,
):
    """Stream the events table as a CSV file."""
    conn = get_connection()
    try:
        where_clauses = []
        params: list = []
        if entity_id:
            where_clauses.append("entity_id = ?")
            params.append(entity_id)
        if label:
            where_clauses.append("label = ?")
            params.append(label)
        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        rows = conn.execute(
            f"SELECT * FROM events {where_sql} ORDER BY timestamp ASC", params
        ).fetchall()

        output = io.StringIO()
        if rows:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            for row in rows:
                writer.writerow(dict(row))
        output.seek(0)

        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=sentinel_events.csv"},
        )
    finally:
        conn.close()
