"""
SentinelDNA — Step 2: ML-Based Behavioral Anomaly Detection

Trains an Isolation Forest on behavioral features derived from event data
WITHOUT using the ground-truth `label` column. Labels are used ONLY for
post-hoc evaluation of model performance.
"""

import json
import math
import pickle
import os
from datetime import datetime
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score,
)

from database import get_connection

# ─── Hyperparameters ─────────────────────────────────────────────────────────
RANDOM_SEED = 42
CONTAMINATION = 0.05   # expected ~5% anomaly rate
N_ESTIMATORS = 200
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model_cache.pkl")

# ─── Behavioral feature columns (NO label) ───────────────────────────────────
FEATURE_COLS = [
    "hour_of_day",
    "is_outside_normal_hours",
    "session_duration",
    "session_zscore",
    "auth_failed",
    "auth_method_unfamiliar",
    "device_unknown",
    "resource_unfamiliar",
    "location_unfamiliar",
    "ip_unfamiliar",
    "recent_failure_rate",
    "n_anomaly_signals",
]


# ─── Data loading ─────────────────────────────────────────────────────────────

def _load_data() -> tuple:
    """Load all events and identity profiles from SQLite."""
    conn = get_connection()
    try:
        event_rows = conn.execute(
            "SELECT * FROM events ORDER BY entity_id, timestamp"
        ).fetchall()
        identity_rows = conn.execute("SELECT * FROM identities").fetchall()
    finally:
        conn.close()

    events = pd.DataFrame([dict(r) for r in event_rows])
    profiles: dict = {}
    for r in identity_rows:
        d = dict(r)
        profiles[d["entity_id"]] = json.loads(d["profile"])

    return events, profiles


# ─── Feature engineering ──────────────────────────────────────────────────────

def _engineer_features(events: pd.DataFrame, profiles: dict) -> pd.DataFrame:
    """
    Build per-event behavioral features.  The 'label' column is carried through
    the DataFrame but is NEVER passed to the model — it is used only for
    post-hoc evaluation.
    """
    # Per-identity session duration stats (mean, std)
    dur_stats = (
        events.groupby("entity_id")["session_duration"]
        .agg(["mean", "std"])
        .to_dict("index")
    )

    # Per-event rolling failure rate (previous 20 events per identity, by time)
    failure_lookup: dict = {}
    for eid, grp in events.groupby("entity_id"):
        grp_sorted = grp.sort_values("timestamp").reset_index(drop=True)
        failures = (~grp_sorted["auth_success"].astype(bool)).astype(float)
        for i, row in grp_sorted.iterrows():
            window = failures[max(0, i - 20): i]
            rate = float(window.mean()) if len(window) > 0 else 0.0
            failure_lookup[row["event_id"]] = rate

    records = []
    for _, ev in events.iterrows():
        eid = ev["entity_id"]
        profile = profiles.get(eid, {})

        # ── Time ──────────────────────────────────────────────────────────────
        try:
            hour = datetime.fromisoformat(str(ev["timestamp"])).hour
        except Exception:
            hour = 12

        normal_hours: list = profile.get("normal_hours", list(range(24)))
        is_outside_normal_hours = int(hour not in normal_hours)

        # ── Session duration ───────────────────────────────────────────────────
        stats = dur_stats.get(eid, {"mean": ev["session_duration"], "std": 1.0})
        mean_dur = float(stats["mean"])
        std_dur = float(stats["std"]) if stats["std"] and not math.isnan(float(stats["std"])) else 1.0
        session_zscore = abs((float(ev["session_duration"]) - mean_dur) / max(std_dur, 1.0))

        # ── Authentication ─────────────────────────────────────────────────────
        auth_failed = int(not bool(ev["auth_success"]))
        preferred_auth = profile.get("preferred_auth", "")
        auth_method_unfamiliar = int(str(ev["auth_method"]) != preferred_auth)

        # ── Device ────────────────────────────────────────────────────────────
        known_devices: list = profile.get("known_devices", [])
        device_unknown = int(str(ev["device_fingerprint"]) not in known_devices)

        # ── Resource ──────────────────────────────────────────────────────────
        common_resources: list = profile.get("common_resources", [])
        resource_unfamiliar = int(str(ev["resource_accessed"]) not in common_resources)

        # ── Location ──────────────────────────────────────────────────────────
        primary_location = profile.get("primary_location", "")
        location_unfamiliar = int(str(ev["geo_location"]) != primary_location)

        # ── IP / subnet ───────────────────────────────────────────────────────
        ip_prefix = profile.get("ip_prefix", "")
        ip_unfamiliar = int(not str(ev["source_ip"]).startswith(ip_prefix)) if ip_prefix else 0

        # ── Recent failure rate ───────────────────────────────────────────────
        recent_failure_rate = failure_lookup.get(ev["event_id"], 0.0)

        # ── Aggregate signal count ────────────────────────────────────────────
        n_anomaly_signals = (
            is_outside_normal_hours + auth_failed + auth_method_unfamiliar
            + device_unknown + resource_unfamiliar + location_unfamiliar + ip_unfamiliar
        )

        records.append({
            "event_id": ev["event_id"],
            "entity_id": eid,
            "label": ev["label"],  # stored for evaluation ONLY — never passed to model
            # ── ML features ──
            "hour_of_day": float(hour),
            "is_outside_normal_hours": float(is_outside_normal_hours),
            "session_duration": float(ev["session_duration"]),
            "session_zscore": float(session_zscore),
            "auth_failed": float(auth_failed),
            "auth_method_unfamiliar": float(auth_method_unfamiliar),
            "device_unknown": float(device_unknown),
            "resource_unfamiliar": float(resource_unfamiliar),
            "location_unfamiliar": float(location_unfamiliar),
            "ip_unfamiliar": float(ip_unfamiliar),
            "recent_failure_rate": float(recent_failure_rate),
            "n_anomaly_signals": float(n_anomaly_signals),
        })

    return pd.DataFrame(records)


# ─── Model training & scoring ──────────────────────────────────────────────────

def _train_and_score(feat_df: pd.DataFrame) -> pd.DataFrame:
    """
    Trains Isolation Forest on FEATURE_COLS only (label excluded).
    Returns the DataFrame with anomaly_score, risk_score, predicted_anomaly,
    and risk_level columns appended.
    """
    X = feat_df[FEATURE_COLS].values  # label column intentionally excluded

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    model.fit(X_scaled)  # trained without label

    # Persist for later use
    try:
        with open(MODEL_PATH, "wb") as f:
            pickle.dump({"model": model, "scaler": scaler}, f)
    except Exception:
        pass

    # decision_function: higher = more normal, lower (negative) = more anomalous
    decision_scores = model.decision_function(X_scaled)
    preds = model.predict(X_scaled)  # -1 = anomaly, 1 = normal

    # Convert to risk score 0–100 (invert: higher raw_risk = more anomalous)
    raw_risk = -decision_scores
    r_min, r_max = raw_risk.min(), raw_risk.max()
    if r_max > r_min:
        risk_scores = ((raw_risk - r_min) / (r_max - r_min) * 100).clip(0, 100).astype(int)
    else:
        risk_scores = np.zeros(len(raw_risk), dtype=int)

    def _risk_level(score: int) -> str:
        if score >= 76:
            return "Critical"
        if score >= 51:
            return "High"
        if score >= 26:
            return "Medium"
        return "Low"

    out = feat_df.copy()
    out["predicted_anomaly"] = (preds == -1).astype(int)
    out["anomaly_score"] = decision_scores.round(6)
    out["risk_score"] = risk_scores
    out["risk_level"] = [_risk_level(int(s)) for s in risk_scores]

    return out


# ─── Explanation generation ───────────────────────────────────────────────────

def _generate_explanation(row: dict) -> list:
    """
    Generate human-readable behavioral deviation reasons for a single event.
    Derived entirely from feature values — never from the ground-truth label.
    """
    reasons = []
    if row.get("is_outside_normal_hours", 0):
        reasons.append("Access outside normal hours")
    if row.get("device_unknown", 0):
        reasons.append("Unknown device")
    if row.get("location_unfamiliar", 0):
        reasons.append("Unusual location")
    if row.get("resource_unfamiliar", 0):
        reasons.append("Unfamiliar resource")
    if float(row.get("session_zscore", 0)) > 2.0:
        reasons.append("Abnormally long session")
    if row.get("auth_failed", 0):
        reasons.append("Authentication failed")
    if row.get("auth_method_unfamiliar", 0):
        reasons.append("Unusual authentication method")
    if row.get("ip_unfamiliar", 0):
        reasons.append("New IP/subnet")
    if float(row.get("recent_failure_rate", 0)) > 0.3:
        reasons.append("High recent authentication failure rate")
    if not reasons:
        reasons.append("Subtle multi-feature behavioral deviation")
    return reasons


# ─── Persistence ──────────────────────────────────────────────────────────────

def _persist_results(scored_df: pd.DataFrame):
    """Write all detection results to the detection_results table."""
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_results (
                event_id          TEXT PRIMARY KEY,
                entity_id         TEXT NOT NULL,
                anomaly_score     REAL NOT NULL,
                risk_score        INTEGER NOT NULL,
                predicted_anomaly INTEGER NOT NULL,
                risk_level        TEXT NOT NULL,
                reasons           TEXT NOT NULL
            )
        """)
        conn.execute("DELETE FROM detection_results")

        rows = []
        for _, row in scored_df.iterrows():
            reasons = _generate_explanation(row.to_dict())
            rows.append((
                row["event_id"],
                row["entity_id"],
                float(row["anomaly_score"]),
                int(row["risk_score"]),
                int(row["predicted_anomaly"]),
                row["risk_level"],
                json.dumps(reasons),
            ))

        conn.executemany(
            """INSERT OR REPLACE INTO detection_results
               (event_id, entity_id, anomaly_score, risk_score, predicted_anomaly, risk_level, reasons)
               VALUES (?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()
        print(f"Persisted {len(rows)} detection results to SQLite.")
    except Exception as exc:
        conn.rollback()
        raise exc
    finally:
        conn.close()


# ─── Evaluation (label used ONLY here) ────────────────────────────────────────

def _compute_metrics(scored_df: pd.DataFrame) -> dict:
    """
    Evaluate model using ground-truth labels.
    Labels are used ONLY in this function — never during training or scoring.
    """
    y_true = (scored_df["label"] != "normal").astype(int).values
    y_pred = scored_df["predicted_anomaly"].values

    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    try:
        roc_auc: Optional[float] = float(
            roc_auc_score(y_true, scored_df["risk_score"].values)
        )
    except Exception:
        roc_auc = None

    return {
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
    }


# ─── Public API ───────────────────────────────────────────────────────────────

def run_detection(force: bool = False) -> dict:
    """
    Main entry point for Step 2 ML pipeline.

    1. Load events + identity profiles from SQLite.
    2. Engineer behavioral features (no label).
    3. Train Isolation Forest (no label).
    4. Score every event and generate explanations.
    5. Persist results.
    6. Evaluate using labels (post-hoc only).

    If results already exist and force=False, skips training.
    """
    # Check for existing results
    conn = get_connection()
    try:
        try:
            count_row = conn.execute(
                "SELECT COUNT(*) AS n FROM detection_results"
            ).fetchone()
            existing = count_row["n"] if count_row else 0
        except Exception:
            existing = 0
    finally:
        conn.close()

    if existing > 0 and not force:
        print(f"Detection results already exist ({existing} rows) — skipping training.")
        return {"status": "cached", "scored_events": existing}

    print("Step 2: Loading data...")
    events, profiles = _load_data()

    if events.empty:
        return {"status": "error", "message": "No events found in database."}

    print(f"Step 2: Engineering features for {len(events)} events...")
    feat_df = _engineer_features(events, profiles)

    print("Step 2: Training Isolation Forest (no labels used)...")
    scored_df = _train_and_score(feat_df)

    print("Step 2: Persisting detection results...")
    _persist_results(scored_df)

    metrics = _compute_metrics(scored_df)
    print(
        f"Step 2: Evaluation — Precision={metrics['precision']}, "
        f"Recall={metrics['recall']}, F1={metrics['f1_score']}"
    )

    return {
        "status": "trained",
        "scored_events": len(scored_df),
        "detected_anomalies": int(scored_df["predicted_anomaly"].sum()),
        "metrics": metrics,
    }
