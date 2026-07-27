"""
SentinelDNA — Step 2 + Step 3: Behavioral Anomaly Detection with Precision Calibration

Step 2 (preserved):
- Isolation Forest on behavioral features (no label leakage)
- Anomaly scoring, explanation generation

Step 3 (added):
- Behavioral evidence score: weighted multi-signal deviation engine (0-100)
- Final risk score: weighted combination of ML + behavioral evidence
  Formula: final = 0.55 * ml_score_norm + 0.45 * behavioral_deviation_score
           + agreement bonus (×1.15) when both signals are ≥ threshold
- Recalibrated risk levels: Critical ≥ 80, High ≥ 65, Medium ≥ 45, Low < 45
- SOC alert budget: top-N% ranking (0.5/1/2/5%) evaluated post-hoc with ground truth
- Label leakage validation test (deterministic, genuinely tested)

ABSOLUTE RULE: `label` is never used in training, scoring, or ranking.
Labels are consulted ONLY in post-hoc evaluation functions.
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
from classifier import classify_all, run_classifier_leakage_test, evaluate_classifier

# ─── Hyperparameters ─────────────────────────────────────────────────────────
RANDOM_SEED = 42
# Isolation Forest contamination: controls internal tree partitioning.
# This is NOT the operational SOC alert rate — alerts are determined separately
# via the SOC alert budget (top-N% of final_risk_score ranking).
CONTAMINATION = 0.05
N_ESTIMATORS  = 300        # was 200 — more trees reduce variance
MODEL_PATH    = os.path.join(os.path.dirname(__file__), "model_cache.pkl")

# ─── Final risk score weights ─────────────────────────────────────────────────
# When a GRU sequence score is available (event has >= SEQUENCE_LENGTH prior events
# for its entity), the GRU provides a third independent signal.
ML_WEIGHT         = 0.55   # without GRU: normalized Isolation Forest anomaly strength
BEHAVIORAL_WEIGHT = 0.45   # without GRU: behavioral deviation / evidence strength

# With GRU fusion (three signals):
ML_WEIGHT_GRU         = 0.45   # Isolation Forest signal
BEHAVIORAL_WEIGHT_GRU = 0.35   # behavioral deviation signal
GRU_WEIGHT            = 0.20   # GRU next-event prediction error signal

# Agreement bonus: applied when BOTH the ML signal AND behavioral evidence are high.
# This rewards cases where the unsupervised ML model AND multiple behavioral
# deviations agree that an event is suspicious.
AGREEMENT_THRESHOLD_ML  = 65   # was 70 — captures more concordant high-risk events
AGREEMENT_THRESHOLD_BEH = 55   # was 60
AGREEMENT_MULTIPLIER    = 1.20  # was 1.15 — stronger reward for dual-signal agreement

# ─── Risk level thresholds (applied to final_risk_score 0–100) ───────────────
# Recalibrated so that Critical is genuinely rare.
# Step 2 used uniform 76/51/26 ranges; Step 3 weights the upper tail.
THRESHOLD_CRITICAL = 80   # top ~2-3% of scored events
THRESHOLD_HIGH     = 65   # top ~8-12%
THRESHOLD_MEDIUM   = 45   # top ~25-35%
# Low: < 45 (majority of normal events)

# ─── Behavioral signal weights ────────────────────────────────────────────────
# Each signal represents an independent behavioral deviation from the identity's
# established Behavioral DNA profile.  Weights reflect operational severity.
# The sum can exceed 100; the final behavioral_deviation_score is clipped to 0-100.
#
# Binary signals (0 or 1 from feature engineering):
WEIGHT_AUTH_FAILED             = 18   # was 15 — authentication failure is a strong signal
WEIGHT_DEVICE_UNKNOWN          = 12   # device not in known_devices
WEIGHT_LOCATION_UNFAMILIAR     = 12   # geo_location differs from primary_location
WEIGHT_OUTSIDE_HOURS           = 10   # access outside normal_hours window
WEIGHT_IP_UNFAMILIAR           = 10   # source_ip prefix mismatch
WEIGHT_RESOURCE_UNFAMILIAR     =  8   # resource not in common_resources
WEIGHT_AUTH_METHOD_UNFAMILIAR  =  8   # auth method differs from preferred_auth
# Graded signals (continuous, mapped to two tiers):
WEIGHT_SESSION_MILD            =  8   # session_zscore 2.0–3.0  (moderately unusual)
WEIGHT_SESSION_STRONG          = 12   # session_zscore > 3.0    (very unusual)
WEIGHT_FAILURE_RATE_MODERATE   =  8   # recent_failure_rate 0.2–0.6 (threshold lowered from 0.3)
WEIGHT_FAILURE_RATE_HIGH       = 15   # recent_failure_rate > 0.6  (sustained failures)
# Graded: consecutive failure streak ending at this event
WEIGHT_CONSEC_FAILURES_MILD    =  8   # 3–7 consecutive failures (brute-force warmup)
WEIGHT_CONSEC_FAILURES_HIGH    = 15   # ≥ 8 consecutive failures  (active brute-force)

# ─── Feature columns (label intentionally excluded) ───────────────────────────
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
    "n_consecutive_failures",   # count of consecutive auth failures ending just before this event
]


# ─── Schema check ─────────────────────────────────────────────────────────────

def _has_step3_columns(conn) -> bool:
    """Return True if detection_results already has the Step 3 columns."""
    try:
        info = conn.execute("PRAGMA table_info(detection_results)").fetchall()
        cols = {row["name"] for row in info}
        return "behavioral_deviation_score" in cols and "evidence_count" in cols and "ml_score_norm" in cols
    except Exception:
        return False


def _has_step6_columns(conn) -> bool:
    """Return True if detection_results already has the Step 6 classification columns."""
    try:
        info = conn.execute("PRAGMA table_info(detection_results)").fetchall()
        cols = {row["name"] for row in info}
        return "predicted_anomaly_type" in cols
    except Exception:
        return False


# ─── Data loading ─────────────────────────────────────────────────────────────

def _load_data() -> tuple:
    """Load all events and identity profiles from SQLite."""
    conn = get_connection()
    try:
        event_rows    = conn.execute("SELECT * FROM events ORDER BY entity_id, timestamp").fetchall()
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
    Build per-event behavioral features.
    The `label` column is carried through for post-hoc evaluation ONLY —
    it is never passed to the model or used in scoring.
    """
    # Per-identity session duration stats (mean, std)
    dur_stats = (
        events.groupby("entity_id")["session_duration"]
        .agg(["mean", "std"])
        .to_dict("index")
    )

    # Rolling recent authentication failure rate (previous 10 events per identity).
    # Window shrunk from 20→10 so recent bursts (brute-force) register faster.
    # Also tracks consecutive failure streak ending just before each event.
    failure_lookup: dict = {}
    consec_lookup: dict = {}
    for eid, grp in events.groupby("entity_id"):
        grp_sorted = grp.sort_values("timestamp").reset_index(drop=True)
        failures = (~grp_sorted["auth_success"].astype(bool)).astype(float)
        streak = 0
        for i, row in grp_sorted.iterrows():
            # Rolling rate over previous 10 events
            window = failures[max(0, i - 10): i]
            rate = float(window.mean()) if len(window) > 0 else 0.0
            failure_lookup[row["event_id"]] = rate
            # Consecutive streak recorded BEFORE updating (streak of prior events)
            consec_lookup[row["event_id"]] = streak
            if not bool(row["auth_success"]):
                streak += 1
            else:
                streak = 0

    records = []
    for _, ev in events.iterrows():
        eid     = ev["entity_id"]
        profile = profiles.get(eid, {})

        # ── Time ──────────────────────────────────────────────────────────────
        try:
            hour = datetime.fromisoformat(str(ev["timestamp"])).hour
        except Exception:
            hour = 12

        normal_hours: list = profile.get("normal_hours", list(range(24)))
        is_outside_normal_hours = int(hour not in normal_hours)

        # ── Session duration ───────────────────────────────────────────────────
        stats    = dur_stats.get(eid, {"mean": ev["session_duration"], "std": 1.0})
        mean_dur = float(stats["mean"])
        std_dur  = float(stats["std"]) if stats["std"] and not math.isnan(float(stats["std"])) else 1.0
        session_zscore = abs((float(ev["session_duration"]) - mean_dur) / max(std_dur, 1.0))

        # ── Authentication ─────────────────────────────────────────────────────
        auth_failed            = int(not bool(ev["auth_success"]))
        preferred_auth         = profile.get("preferred_auth", "")
        auth_method_unfamiliar = int(str(ev["auth_method"]) != preferred_auth)

        # ── Device ────────────────────────────────────────────────────────────
        known_devices  = profile.get("known_devices", [])
        device_unknown = int(str(ev["device_fingerprint"]) not in known_devices)

        # ── Resource ──────────────────────────────────────────────────────────
        common_resources    = profile.get("common_resources", [])
        resource_unfamiliar = int(str(ev["resource_accessed"]) not in common_resources)

        # ── Location ──────────────────────────────────────────────────────────
        primary_location    = profile.get("primary_location", "")
        location_unfamiliar = int(str(ev["geo_location"]) != primary_location)

        # ── IP / subnet ───────────────────────────────────────────────────────
        ip_prefix      = profile.get("ip_prefix", "")
        ip_unfamiliar  = int(not str(ev["source_ip"]).startswith(ip_prefix)) if ip_prefix else 0

        # ── Recent failure rate ───────────────────────────────────────────────
        recent_failure_rate = failure_lookup.get(ev["event_id"], 0.0)

        # ── Consecutive failure streak (prior events) ─────────────────────────
        n_consecutive_failures = float(consec_lookup.get(ev["event_id"], 0))

        # ── Aggregate binary signal count ─────────────────────────────────────
        n_anomaly_signals = (
            is_outside_normal_hours + auth_failed + auth_method_unfamiliar
            + device_unknown + resource_unfamiliar + location_unfamiliar + ip_unfamiliar
        )

        records.append({
            "event_id":     ev["event_id"],
            "entity_id":    eid,
            "label":        ev["label"],  # stored for evaluation ONLY — never passed to model
            # ── ML features ──────────────────────────────────────────────────
            "hour_of_day":              float(hour),
            "is_outside_normal_hours":  float(is_outside_normal_hours),
            "session_duration":         float(ev["session_duration"]),
            "session_zscore":           float(session_zscore),
            "auth_failed":              float(auth_failed),
            "auth_method_unfamiliar":   float(auth_method_unfamiliar),
            "device_unknown":           float(device_unknown),
            "resource_unfamiliar":      float(resource_unfamiliar),
            "location_unfamiliar":      float(location_unfamiliar),
            "ip_unfamiliar":            float(ip_unfamiliar),
            "recent_failure_rate":      float(recent_failure_rate),
            "n_anomaly_signals":        float(n_anomaly_signals),
            "n_consecutive_failures":   n_consecutive_failures,
        })

    return pd.DataFrame(records)


# ─── Behavioral deviation scoring (Step 3) ────────────────────────────────────

def _behavioral_evidence(row: dict) -> tuple:
    """
    Compute behavioral_deviation_score (0-100) and evidence_count for one event.

    Each signal is an independent behavioral deviation from the identity's
    established Behavioral DNA profile. Derived entirely from feature values —
    NEVER from the ground-truth label.

    Returns: (behavioral_deviation_score: int, evidence_count: int)
    """
    score  = 0
    count  = 0

    # Binary signals
    if row.get("auth_failed", 0):
        score += WEIGHT_AUTH_FAILED; count += 1
    if row.get("device_unknown", 0):
        score += WEIGHT_DEVICE_UNKNOWN; count += 1
    if row.get("location_unfamiliar", 0):
        score += WEIGHT_LOCATION_UNFAMILIAR; count += 1
    if row.get("is_outside_normal_hours", 0):
        score += WEIGHT_OUTSIDE_HOURS; count += 1
    if row.get("ip_unfamiliar", 0):
        score += WEIGHT_IP_UNFAMILIAR; count += 1
    if row.get("resource_unfamiliar", 0):
        score += WEIGHT_RESOURCE_UNFAMILIAR; count += 1
    if row.get("auth_method_unfamiliar", 0):
        score += WEIGHT_AUTH_METHOD_UNFAMILIAR; count += 1

    # Graded: session duration anomaly (two tiers)
    zscore = float(row.get("session_zscore", 0.0))
    if zscore > 3.0:
        score += WEIGHT_SESSION_STRONG; count += 1
    elif zscore > 2.0:
        score += WEIGHT_SESSION_MILD; count += 1

    # Graded: recent authentication failure rate (two tiers; lower first tier 0.3→0.2)
    fail_rate = float(row.get("recent_failure_rate", 0.0))
    if fail_rate > 0.6:
        score += WEIGHT_FAILURE_RATE_HIGH; count += 1
    elif fail_rate > 0.2:
        score += WEIGHT_FAILURE_RATE_MODERATE; count += 1

    # Graded: consecutive failure streak (two tiers) — sensitive to brute-force bursts
    n_consec = int(row.get("n_consecutive_failures", 0))
    if n_consec >= 8:
        score += WEIGHT_CONSEC_FAILURES_HIGH; count += 1
    elif n_consec >= 3:
        score += WEIGHT_CONSEC_FAILURES_MILD; count += 1

    return min(100, score), count


def _compute_final_risk_score(
    ml_score_norm: int,
    beh_score: int,
    gru_score: Optional[float] = None,
) -> int:
    """
    Combine normalized ML anomaly strength, behavioral evidence strength, and
    (when available) GRU sequence prediction error into a final risk score.

    Two-signal formula (no GRU — cold-start events or entities with < SEQUENCE_LENGTH events):
        combined = 0.55 * ml_score_norm + 0.45 * behavioral_deviation_score

    Three-signal formula (GRU available):
        combined = 0.45 * ml_score_norm + 0.35 * behavioral_deviation_score + 0.20 * gru_score

    Agreement bonus (×AGREEMENT_MULTIPLIER, capped at 100):
        Applied when BOTH the ML model AND behavioral evidence are elevated.
        Rewards high-confidence events where independent signals agree.

    Never uses ground-truth labels.
    """
    if gru_score is not None:
        combined = (
            ML_WEIGHT_GRU * ml_score_norm
            + BEHAVIORAL_WEIGHT_GRU * beh_score
            + GRU_WEIGHT * gru_score
        )
    else:
        combined = ML_WEIGHT * ml_score_norm + BEHAVIORAL_WEIGHT * beh_score

    if ml_score_norm >= AGREEMENT_THRESHOLD_ML and beh_score >= AGREEMENT_THRESHOLD_BEH:
        combined = combined * AGREEMENT_MULTIPLIER
    return int(min(100, round(combined)))


def _risk_level(final_risk_score: int) -> str:
    """
    Recalibrated risk levels.

    Thresholds (applied to final_risk_score 0-100):
        Critical: >= 80   (genuinely rare; top ~2-3% of events)
        High:     >= 65   (top ~8-12%)
        Medium:   >= 45   (top ~25-35%)
        Low:      <  45   (baseline-normal majority)

    Step 2 used uniform 76/51/26 ranges which caused too many Critical/High alerts.
    These thresholds are calibrated to the combined score distribution.
    """
    if final_risk_score >= THRESHOLD_CRITICAL: return "Critical"
    if final_risk_score >= THRESHOLD_HIGH:     return "High"
    if final_risk_score >= THRESHOLD_MEDIUM:   return "Medium"
    return "Low"


# ─── Model training & scoring ──────────────────────────────────────────────────

def _train_and_score(feat_df: pd.DataFrame) -> pd.DataFrame:
    """
    1. Trains Isolation Forest on FEATURE_COLS only (label excluded).
    2. Normalizes IF decision score to ml_score_norm (0–100).
    3. Computes GRU sequence score per event (label-free; lazy-imported to avoid
       circular import at module load time).
    4. Computes behavioral_deviation_score and evidence_count per event.
    5. Combines into final_risk_score:
         - Three-signal: 0.45*ml + 0.35*behavioral + 0.20*gru  (when GRU available)
         - Two-signal:   0.55*ml + 0.45*behavioral             (cold-start events)
         + agreement bonus when both ML and behavioral exceed their thresholds.
    6. Assigns recalibrated risk_level from final_risk_score.
    """
    X = feat_df[FEATURE_COLS].values   # label column intentionally excluded

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    model.fit(X_scaled)    # trained without label

    # Persist model for reuse (label leakage test, future scoring)
    try:
        with open(MODEL_PATH, "wb") as f:
            pickle.dump({"model": model, "scaler": scaler}, f)
    except Exception:
        pass

    # IF decision_function: higher = more normal; lower (negative) = more anomalous
    decision_scores = model.decision_function(X_scaled)
    preds           = model.predict(X_scaled)   # -1 = anomaly, 1 = normal

    # Normalize to ml_score_norm: 0 = most normal, 100 = most anomalous
    raw_anomaly = -decision_scores
    r_min, r_max = raw_anomaly.min(), raw_anomaly.max()
    if r_max > r_min:
        ml_norms = ((raw_anomaly - r_min) / (r_max - r_min) * 100).clip(0, 100).astype(int)
    else:
        ml_norms = np.zeros(len(raw_anomaly), dtype=int)

    # ── GRU sequence score (lazy import avoids circular dependency at load time) ──
    # sequence_detector imports FEATURE_COLS and helpers from this module at the top
    # level, so we must not import it at the top of detector.py.  Importing inside
    # this function is safe because by call-time both modules are fully initialised.
    gru_score_map: dict = {}
    try:
        from sequence_detector import batch_score_all_events  # noqa: PLC0415
        # Pass only the label-free feature frame (labels are stripped inside)
        feat_no_label = feat_df.drop(columns=["label"], errors="ignore")
        gru_score_map = batch_score_all_events(feat_no_label)
        n_scored = sum(1 for v in gru_score_map.values() if v is not None)
        print(f"GRU batch scoring: {n_scored}/{len(feat_df)} events scored.")
    except Exception as exc:
        print(f"GRU batch scoring skipped (will use two-signal formula): {exc}")

    # Compute behavioral evidence and final risk score per event
    out = feat_df.copy()
    out["predicted_anomaly"] = (preds == -1).astype(int)
    out["anomaly_score"]     = decision_scores.round(6)
    out["ml_score_norm"]     = ml_norms

    beh_scores  = []
    ev_counts   = []
    final_risks = []
    risk_levels = []
    gru_scores_out = []

    for i, row in out.iterrows():
        row_d = row.to_dict()
        beh_score, ev_count = _behavioral_evidence(row_d)
        ml_norm  = int(row["ml_score_norm"])
        gru_val  = gru_score_map.get(str(row["event_id"]))   # None for cold-start events
        final    = _compute_final_risk_score(ml_norm, beh_score, gru_val)
        level    = _risk_level(final)
        beh_scores.append(beh_score)
        ev_counts.append(ev_count)
        final_risks.append(final)
        risk_levels.append(level)
        gru_scores_out.append(gru_val)

    out["behavioral_deviation_score"] = beh_scores
    out["evidence_count"]             = ev_counts
    out["gru_score"]                  = gru_scores_out
    out["risk_score"]                 = final_risks    # final_risk_score stored in risk_score for API compatibility
    out["risk_level"]                 = risk_levels

    return out


# ─── Explanation generation ───────────────────────────────────────────────────

def _generate_explanation(row: dict) -> list:
    """
    Generate human-readable behavioral deviation reasons for a single event.
    Derived entirely from feature values — NEVER from the ground-truth label.
    """
    reasons = []
    if row.get("auth_failed", 0):
        reasons.append("Authentication failed")
    if row.get("device_unknown", 0):
        reasons.append("Unknown device")
    if row.get("location_unfamiliar", 0):
        reasons.append("Unusual location")
    if row.get("is_outside_normal_hours", 0):
        reasons.append("Access outside normal hours")
    if row.get("ip_unfamiliar", 0):
        reasons.append("New IP/subnet")
    if row.get("resource_unfamiliar", 0):
        reasons.append("Unfamiliar resource")
    if row.get("auth_method_unfamiliar", 0):
        reasons.append("Unusual authentication method")
    zscore = float(row.get("session_zscore", 0))
    if zscore > 3.0:
        reasons.append("Severely abnormal session duration")
    elif zscore > 2.0:
        reasons.append("Abnormally long session")
    fail_rate = float(row.get("recent_failure_rate", 0))
    if fail_rate > 0.6:
        reasons.append("Very high recent authentication failure rate")
    elif fail_rate > 0.2:
        reasons.append("High recent authentication failure rate")
    n_consec = int(row.get("n_consecutive_failures", 0))
    if n_consec >= 8:
        reasons.append(f"Active brute-force streak ({n_consec} consecutive failures)")
    elif n_consec >= 3:
        reasons.append(f"Consecutive authentication failure streak ({n_consec} events)")
    gru_val = row.get("gru_score")
    if gru_val is not None and float(gru_val) >= 75:
        reasons.append("Anomalous behavioral sequence (GRU prediction error elevated)")
    if not reasons:
        reasons.append("Subtle multi-feature behavioral deviation")
    return reasons


# ─── Persistence ──────────────────────────────────────────────────────────────

def _persist_results(classified_df: pd.DataFrame):
    """Write all detection results to the detection_results table (Step 7 schema)."""
    conn = get_connection()
    try:
        # Drop and recreate to ensure the full Step 7 schema is present.
        conn.execute("DROP TABLE IF EXISTS detection_results")
        conn.execute("""
            CREATE TABLE detection_results (
                event_id                   TEXT PRIMARY KEY,
                entity_id                  TEXT NOT NULL,
                anomaly_score              REAL NOT NULL,
                ml_score_norm              INTEGER NOT NULL DEFAULT 0,
                behavioral_deviation_score INTEGER NOT NULL DEFAULT 0,
                evidence_count             INTEGER NOT NULL DEFAULT 0,
                gru_score                  REAL,
                risk_score                 INTEGER NOT NULL,
                predicted_anomaly          INTEGER NOT NULL,
                risk_level                 TEXT NOT NULL,
                reasons                    TEXT NOT NULL,
                predicted_anomaly_type     TEXT,
                classification_confidence  REAL,
                classification_reasons     TEXT
            )
        """)

        rows = []
        for _, row in classified_df.iterrows():
            reasons = _generate_explanation(row.to_dict())
            gru_val = row.get("gru_score")
            rows.append((
                row["event_id"],
                row["entity_id"],
                float(row["anomaly_score"]),
                int(row["ml_score_norm"]),
                int(row["behavioral_deviation_score"]),
                int(row["evidence_count"]),
                float(gru_val) if gru_val is not None else None,
                int(row["risk_score"]),
                int(row["predicted_anomaly"]),
                row["risk_level"],
                json.dumps(reasons),
                row.get("predicted_anomaly_type"),
                row.get("classification_confidence"),
                row.get("classification_reasons", json.dumps([])),
            ))

        conn.executemany(
            """INSERT OR REPLACE INTO detection_results
               (event_id, entity_id, anomaly_score, ml_score_norm,
                behavioral_deviation_score, evidence_count, gru_score,
                risk_score, predicted_anomaly, risk_level, reasons,
                predicted_anomaly_type, classification_confidence, classification_reasons)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()
        print(f"Persisted {len(rows)} detection results to SQLite (Step 7 schema with GRU fusion).")
    except Exception as exc:
        conn.rollback()
        raise exc
    finally:
        conn.close()


# ─── Label leakage validation test ────────────────────────────────────────────

def _run_label_leakage_test(feat_df: pd.DataFrame) -> bool:
    """
    Prove that ground-truth labels do not influence any scoring output.

    Test procedure (deterministic):
    1. Load the persisted model (trained without labels).
    2. Take a reproducible sample of events.
    3. Score original feature data → record ml_anomaly_score, behavioral_deviation_score,
       evidence_count, final_risk_score, and ranking position.
    4. Shuffle/replace ALL ground-truth labels in the sample.
    5. Score the SAME feature data again.
    6. Compare: all scores must be bit-for-bit identical.

    Returns True only if the test genuinely passes (no label leakage detected).
    """
    try:
        if not os.path.exists(MODEL_PATH):
            return False

        with open(MODEL_PATH, "rb") as f:
            cache = pickle.load(f)
        model  = cache["model"]
        scaler = cache["scaler"]

        # Reproducible sample
        sample = feat_df.sample(min(300, len(feat_df)), random_state=RANDOM_SEED)

        def _score_sample(df: pd.DataFrame):
            X        = df[FEATURE_COLS].values
            X_scaled = scaler.transform(X)
            decision = model.decision_function(X_scaled)
            raw      = -decision
            r_min, r_max = raw.min(), raw.max()
            if r_max > r_min:
                ml_norms = ((raw - r_min) / (r_max - r_min) * 100).clip(0, 100).astype(int)
            else:
                ml_norms = np.zeros(len(raw), dtype=int)

            beh_scores, ev_counts, finals = [], [], []
            for i, row in df.iterrows():
                b, c = _behavioral_evidence(row.to_dict())
                f    = _compute_final_risk_score(int(ml_norms[list(df.index).index(i)]), b)
                beh_scores.append(b); ev_counts.append(c); finals.append(f)

            return {
                "decision":  decision.tolist(),
                "ml_norms":  ml_norms.tolist(),
                "beh":       beh_scores,
                "ev_counts": ev_counts,
                "finals":    finals,
                "ranking":   sorted(range(len(finals)), key=lambda x: finals[x], reverse=True),
            }

        original = _score_sample(sample)

        # Shuffle labels — must have zero effect on any score
        shuffled = sample.copy()
        rng = np.random.default_rng(seed=RANDOM_SEED + 1)
        shuffled["label"] = rng.permutation(shuffled["label"].values)
        after = _score_sample(shuffled)

        # All score arrays must be identical
        passed = (
            original["decision"]  == after["decision"]
            and original["ml_norms"]  == after["ml_norms"]
            and original["beh"]       == after["beh"]
            and original["ev_counts"] == after["ev_counts"]
            and original["finals"]    == after["finals"]
            and original["ranking"]   == after["ranking"]
        )
        return passed

    except Exception as exc:
        print(f"Label leakage test error: {exc}")
        return False


# ─── Evaluation (label used ONLY here) ────────────────────────────────────────

def _compute_metrics(scored_df: pd.DataFrame) -> dict:
    """
    Evaluate model using ground-truth labels.
    Labels are used ONLY in this function — never during training or scoring.
    """
    y_true  = (scored_df["label"] != "normal").astype(int).values
    y_pred  = scored_df["predicted_anomaly"].values
    y_score = scored_df["risk_score"].values

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
        "precision":               round(precision, 4),
        "recall":                  round(recall, 4),
        "f1_score":                round(f1, 4),
        "true_positives":          int(tp),
        "false_positives":         int(fp),
        "false_negatives":         int(fn),
        "true_negatives":          int(tn),
        "roc_auc":                 round(roc_auc, 4) if roc_auc is not None else None,
        "total_true_anomalies":    int(y_true.sum()),
        "total_predicted_anomalies": int(y_pred.sum()),
    }


def compute_alert_budget(scored_df: pd.DataFrame) -> list:
    """
    Compute SOC alert budget metrics for cutoffs: 0.5%, 1%, 2%, 5%.

    Events are ranked by final_risk_score (= risk_score column) DESCENDING.
    Ground-truth labels are applied ONLY AFTER ranking to measure coverage.

    Returns a list of dicts, one per budget cutoff.
    """
    n_total = len(scored_df)
    y_true  = (scored_df["label"] != "normal").astype(int).values
    # Rank by final risk score descending (no label used)
    ranked  = scored_df.sort_values("risk_score", ascending=False).reset_index(drop=True)
    y_true_ranked = (ranked["label"] != "normal").astype(int).values
    total_attacks = int(y_true.sum())

    results = []
    for pct in [0.5, 1.0, 2.0, 5.0]:
        n_alerts = max(1, int(round(n_total * pct / 100)))
        # Select top-N events by risk score
        top_labels = y_true_ranked[:n_alerts]
        tp = int(top_labels.sum())
        fp = n_alerts - tp
        fn = total_attacks - tp
        prec  = round(tp / n_alerts, 4) if n_alerts > 0 else 0.0
        rec   = round(tp / max(total_attacks, 1), 4)
        f1_val = round(2 * prec * rec / (prec + rec), 4) if (prec + rec) > 0 else 0.0
        results.append({
            "budget_pct":  pct,
            "alert_count": n_alerts,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision":   prec,
            "recall":      rec,
            "f1_score":    f1_val,
        })
    return results


# ─── Public API ───────────────────────────────────────────────────────────────

def run_detection(force: bool = False) -> dict:
    """
    Main entry point for the ML pipeline.

    1. Load events + identity profiles from SQLite.
    2. Engineer behavioral features (no label).
    3. Train Isolation Forest (no label).
    4. Compute behavioral_deviation_score and evidence_count per event.
    5. Compute final_risk_score = 0.55*ml + 0.45*behavioral + agreement bonus.
    6. Assign recalibrated risk levels (Critical ≥ 80, High ≥ 65, Medium ≥ 45).
    7. Persist results.
    8. Run label leakage test.
    9. Evaluate using labels (post-hoc only).

    If Step 3 columns already exist and force=False, skips training.
    """
    conn = get_connection()
    try:
        try:
            count_row = conn.execute("SELECT COUNT(*) AS n FROM detection_results").fetchone()
            existing  = count_row["n"] if count_row else 0
        except Exception:
            existing  = 0

        # Force retrain if Step 3 or Step 6 columns are missing (schema migration)
        if existing > 0 and not force:
            if not _has_step3_columns(conn) or not _has_step6_columns(conn):
                print("Schema columns missing — forcing retrain for schema migration...")
                force = True
    finally:
        conn.close()

    if existing > 0 and not force:
        print(f"Detection results already exist ({existing} rows) — skipping training.")
        return {"status": "cached", "scored_events": existing}

    print("Step 2+3: Loading data...")
    events, profiles = _load_data()

    if events.empty:
        return {"status": "error", "message": "No events found in database."}

    print(f"Step 2+3: Engineering features for {len(events)} events...")
    feat_df = _engineer_features(events, profiles)

    print("Step 2+3: Training Isolation Forest (no labels used)...")
    scored_df = _train_and_score(feat_df)

    print("Step 2+3: Running label leakage validation test...")
    leakage_passed = _run_label_leakage_test(feat_df)
    print(f"Label leakage test: {'PASSED' if leakage_passed else 'FAILED'}")

    print("Step 6: Classifying anomaly types (no labels used)...")
    classified_df = classify_all(scored_df)

    print("Step 6: Running classifier label-independence test...")
    classifier_leakage_passed = run_classifier_leakage_test(scored_df)
    print(f"Classifier label-independence test: {'PASSED' if classifier_leakage_passed else 'FAILED'}")

    print("Step 2+3+6: Persisting detection results...")
    _persist_results(classified_df)

    # Evaluate classifier post-hoc (labels used ONLY here)
    print("Step 6: Evaluating classifier accuracy (post-hoc, labels used here only)...")
    classifier_metrics = evaluate_classifier(classified_df)
    print(
        f"Step 6: Overall accuracy={classifier_metrics.get('overall_accuracy')}, "
        f"Unknown rate={classifier_metrics.get('unknown_rate')}, "
        f"Top-1% accuracy={classifier_metrics.get('top1_pct_classification_accuracy')}"
    )

    # Persist meta values for API exposure
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        import json as _json
        conn.execute(
            "INSERT OR REPLACE INTO detection_meta (key, value) VALUES (?, ?)",
            ("label_leakage_test_passed", "true" if leakage_passed else "false"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO detection_meta (key, value) VALUES (?, ?)",
            ("classifier_leakage_test_passed", "true" if classifier_leakage_passed else "false"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO detection_meta (key, value) VALUES (?, ?)",
            ("classifier_metrics", _json.dumps(classifier_metrics)),
        )
        conn.commit()
    finally:
        conn.close()

    metrics = _compute_metrics(classified_df)
    budget  = compute_alert_budget(classified_df)

    print(
        f"Step 2+3: Evaluation — Precision={metrics['precision']}, "
        f"Recall={metrics['recall']}, F1={metrics['f1_score']}"
    )
    top1 = next((b for b in budget if b["budget_pct"] == 1.0), {})
    print(
        f"Step 3: Top-1% — Precision={top1.get('precision')}, "
        f"Recall={top1.get('recall')}, F1={top1.get('f1_score')}"
    )

    return {
        "status":             "trained",
        "scored_events":      len(classified_df),
        "detected_anomalies": int(classified_df["predicted_anomaly"].sum()),
        "metrics":            metrics,
        "alert_budget":       budget,
        "label_leakage_test_passed":       leakage_passed,
        "classifier_leakage_test_passed":  classifier_leakage_passed,
        "classifier_metrics":              classifier_metrics,
    }
